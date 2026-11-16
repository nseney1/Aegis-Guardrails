"""aegis_core.team leases: ``refs/aegis/lanes/<lane>`` -> one JSON blob (v4.1 spec §1).

Leases are cooperative conflict input, not locks: a claim refuses when a live lease of
another lane may overlap its paths, writes create-only, takes over an expired lease by
compare-and-swap with ``gen`` + 1 and a new ``claim_id``, and treats "the ref now holds
the oid I computed before writing" as success when git's acknowledgement is lost.
renew/transfer/release are CAS against ``--expect``; renewing an expired lease goes
through the claim path. Every test runs real git in temp repositories.
"""
from __future__ import annotations

import ast
from datetime import datetime, timezone
import json
import multiprocessing
import os
from pathlib import Path
import queue
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
from typing import Dict, List, Optional

import pytest

from aegis_core import events, gitsafe, lane_gate, match, storage_confined, team, team_paths, team_queue, team_status
from aegis_core import team_lease_custody
from tests import helpers_teamrace

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

NOW = 1_760_000_000
BLOB_KEYS = ["v", "lane", "role", "owner", "claim_id", "gen", "branch", "paths", "ts", "ttl_s"]
VIEW_KEYS = ["lane", "role", "owner", "claim_id", "gen", "oid", "branch", "paths", "expires_at",
             "clock_basis", "expired", "clock_skew", "overlaps"]


def _git(repo: Path, *args: str, stdin: Optional[bytes] = None) -> str:
    return subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=T", *args],
        cwd=str(repo), check=True, capture_output=True, input=stdin,
    ).stdout.decode()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    (root / "a.txt").write_text("a\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    return root


def _ref(repo: Path, lane: str) -> Optional[str]:
    proc = subprocess.run(["git", "show-ref", "--verify", "--hash", f"refs/aegis/lanes/{lane}"],
                          cwd=str(repo), capture_output=True, text=True)
    return proc.stdout.strip() if proc.returncode == 0 else None


def _refs(repo: Path) -> Dict[str, str]:
    out = _git(repo, "for-each-ref", "--format=%(refname) %(objectname)", "refs/aegis")
    return dict(line.split() for line in out.splitlines())


def _blob(repo: Path, oid: str) -> dict:
    return json.loads(_git(repo, "cat-file", "blob", oid))


def _plant(repo: Path, lane_ref: str, data: bytes) -> str:
    oid = _git(repo, "hash-object", "-w", "--stdin", stdin=data).strip()
    _git(repo, "update-ref", lane_ref, oid)
    return oid


def _events(repo: Path, kind: str) -> List[dict]:
    return events.read(repo, kind).rows


def _valid_blob(**changes) -> dict:
    blob = {"v": 1, "lane": "docs", "role": "implementer", "owner": "o@h", "claim_id": "0123456789abcdef",
            "gen": 1, "branch": None, "paths": ["docs/**"], "ts": NOW, "ttl_s": 3600}
    blob.update(changes)
    return blob


# ── claim: create-only ───────────────────────────────────────────────────────

def test_a_claim_creates_the_lane_ref_holding_exactly_the_lease_blob(repo: Path):
    change = team.claim(repo, "docs", ["docs/**", "README.md"], owner="nick@host", ttl_s=3600,
                        branch="lane/docs", now=NOW)
    assert (change.action, change.lane, change.previous) == ("claimed", "docs", None)
    assert _ref(repo, "docs") == change.oid
    blob = _blob(repo, change.oid)
    assert list(blob) == BLOB_KEYS
    assert re.fullmatch(r"[0-9a-f]{16}", blob["claim_id"])
    assert blob == _valid_blob(owner="nick@host", claim_id=blob["claim_id"], branch="lane/docs",
                               paths=["docs/**", "README.md"])
    assert change.lease == team.Lease(lane="docs", role="implementer", owner="nick@host",
                                      claim_id=blob["claim_id"], gen=1, branch="lane/docs",
                                      paths=("docs/**", "README.md"), ts=NOW, ttl_s=3600, oid=change.oid)


def test_the_blob_is_compact_utf8_json_with_a_final_newline(repo: Path):
    change = team.claim(repo, "docs", ["docs/**"], owner="Zoë@hôst", now=NOW)
    raw = subprocess.run(["git", "cat-file", "blob", change.oid], cwd=str(repo), capture_output=True).stdout
    expected = _valid_blob(owner="Zoë@hôst", claim_id=change.lease.claim_id)
    assert raw == (json.dumps(expected, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def test_a_lease_over_64_kib_is_refused_before_anything_is_written(repo: Path):
    paths = [f"docs/{n:04d}/" + "x" * 60 + "/**" for n in range(1000)]
    with pytest.raises(team.TeamUsageError, match=r"\Apaths: the lease would be larger than 64 KiB\Z"):
        team.claim(repo, "docs", paths, owner="o@h", now=NOW)
    assert _refs(repo) == {}


def test_the_returned_oid_names_the_blob_in_the_repository_hash_format(repo: Path):
    change = team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW)
    data = subprocess.run(["git", "cat-file", "blob", change.oid], cwd=str(repo), capture_output=True).stdout
    assert gitsafe.blob_oid(repo, data) == change.oid


def test_defaults_are_the_implementer_role_an_hour_no_branch_and_user_at_host(repo: Path, monkeypatch):
    monkeypatch.setenv("LOGNAME", "tester")
    change = team.claim(repo, "docs", ["docs/**"], now=NOW)
    assert team.default_owner() == f"tester@{socket.gethostname()}"
    assert (change.lease.owner, change.lease.role, change.lease.ttl_s, change.lease.branch) == (
        f"tester@{socket.gethostname()}", "implementer", 3600, None)
    assert team.DEFAULT_TTL_S == 3600 and team.MAX_TTL_S == 86400


def test_paths_are_stored_workspace_relative_posix_once_each(repo: Path):
    change = team.claim(repo, "docs", ["./docs/**", "docs\\**", "/README.md"], owner="o@h", now=NOW)
    assert change.lease.paths == ("docs/**", "/README.md")


@pytest.mark.parametrize("operation", ["claim", "read", "renew", "transfer", "construct"])
def test_every_lease_path_keeps_its_runtime_type_and_wire_bytes(repo: Path, operation):
    change = team.claim(repo, "docs", ["/README.md", "docs/**"], owner="o@h", now=NOW)
    if operation == "read":
        lease = team.read_leases(repo).get("docs")
    elif operation == "renew":
        lease = team.renew(repo, "docs", change.oid, now=NOW + 1).lease
    elif operation == "transfer":
        lease = team.transfer(repo, "docs", change.oid, "new@h", now=NOW + 1).lease
    elif operation == "construct":
        lease = team.Lease(
            "docs", "implementer", "o@h", change.lease.claim_id, 1, None,
            ("/README.md", "docs/**"), NOW, 3600, change.oid)
    else:
        lease = change.lease
    values = (*lease.paths, *lease.path_set.raw, *lease.path_set.matching)
    assert all(isinstance(path, team_paths.LeaseGlob) for path in values)
    assert json.dumps(list(lease.paths)).encode() == b'["/README.md", "docs/**"]'
    expected = _valid_blob(paths=["/README.md", "docs/**"], owner=lease.owner,
                           claim_id=lease.claim_id, gen=lease.gen, ts=lease.ts)
    assert gitsafe.read_object(repo, lease.oid, team.MAX_LEASE_BYTES) == (
        json.dumps(expected, ensure_ascii=False, separators=(",", ":")) + "\n").encode()


def test_anchored_lease_fixture_is_wider_for_the_old_reader(repo: Path):
    # v4.5 normalization, frozen here so this test needs no repository history.
    def old_normalize(path):
        text = path.replace("\\", "/")
        while text.startswith("./"):
            text = text[2:]
        return text.lstrip("/")

    raw = json.dumps(_valid_blob(paths=["/pyproject.toml"])).encode()
    _plant(repo, "refs/aegis/lanes/docs", raw)
    held = team.read_leases(repo).get("docs")
    assert held.paths == ("/pyproject.toml",)
    assert not team_paths.overlap(held.path_set, team_paths.claim_paths(["tools/a.py"]))
    from aegis_core import match
    old_paths = [old_normalize(path) for path in held.paths]
    assert old_paths == ["pyproject.toml"]
    assert match.sets_overlap(old_paths, ["tools/a.py"])
    assert match.matches(old_paths[0], "nested/pyproject.toml")


@pytest.mark.parametrize("peer_path,refused", [("/pyproject.toml", True), ("tools/a.py", False)])
def test_anchor_claim_retry_rechecks_a_concurrent_peer(repo: Path, monkeypatch, peer_path, refused):
    old = team.claim(repo, "root", ["/pyproject.toml"], owner="old@h", ttl_s=1, now=NOW)
    real = gitsafe.update_ref

    def changed(cwd, ref, new, old_value):
        monkeypatch.setattr(gitsafe, "update_ref", real)
        real(cwd, ref, None, old.oid)
        team.claim(repo, "peer", [peer_path], owner="peer@h", now=NOW + 1)
        return real(cwd, ref, new, old_value)

    monkeypatch.setattr(gitsafe, "update_ref", changed)
    if refused:
        for _ in range(2):
            with pytest.raises(team.LeaseRefused) as caught:
                team.claim(repo, "root", ["/pyproject.toml"], owner="new@h", now=NOW + 1)
            assert (caught.value.code, caught.value.reason, caught.value.lanes) == (
                "LEASE_REFUSED", "overlap", ("peer",))
        assert _ref(repo, "root") is None
    else:
        result = team.claim(repo, "root", ["/pyproject.toml"], owner="new@h", now=NOW + 1)
        assert result.action == "claimed"
        assert result.lease.paths == ("/pyproject.toml",)
        assert all(view["overlaps"] == [] for view in team.describe(repo, now=NOW + 1)["leases"])


def _anchor_cli(repo, *args):
    source = Path(__file__).resolve().parents[3]
    environment = dict(os.environ, PYTHONPATH=str(source))
    environment.pop("AEGIS_WORKSPACE", None)
    result = subprocess.run([sys.executable, "-m", "aegis_cli", "--workspace", str(repo),
                             "team", *args, "--json"], cwd=repo, env=environment,
                            capture_output=True, text=True, timeout=30)
    assert result.stderr == ""
    return result.returncode, json.loads(result.stdout)


def test_anchor_cli_claim_list_status_release_round_trip(repo: Path):
    (repo / ".aegis" / "rules").mkdir(parents=True)
    code, peer = _anchor_cli(repo, "claim", "tools", "--paths", "tools/a.py", "--owner", "peer@h")
    assert code == 0
    code, claimed = _anchor_cli(repo, "claim", "root", "--paths", "//pyproject.toml", "--owner", "root@h")
    assert code == 0
    assert claimed["lease"]["paths"] == ["/pyproject.toml"]
    for command in ("list", "status"):
        code, listed = _anchor_cli(repo, command)
        assert code == 0
        views = {view["lane"]: view for view in listed["leases" if command == "list" else "lanes"]}
        assert views["root"]["paths"] == ["/pyproject.toml"]
        assert views["root"]["overlaps"] == views["tools"]["overlaps"] == []
    for _ in range(2):
        code, denied = _anchor_cli(repo, "claim", "other", "--paths", "/pyproject.toml")
        assert (code, denied["status"], denied["reason"], denied["lanes"]) == (1, "refused", "overlap", ["root"])
    code, released = _anchor_cli(repo, "release", "root", "--expect", claimed["oid"])
    assert (code, released["status"]) == (0, "released")
    assert _ref(repo, "root") is None
    assert _ref(repo, "tools") == peer["oid"]


def test_root_file_overlap_refusal_suggests_an_anchor_and_preserves_it_when_pickled(repo: Path):
    from tests.unit.core.test_storage_confined import make_store
    import pickle

    make_store(repo)
    (repo / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    peer = team.claim(repo, "tools", ["tools/a.py"], owner="peer@h", now=NOW)
    for _ in range(2):
        with pytest.raises(team.LeaseRefused) as caught:
            team.claim(repo, "root", ["pyproject.toml"], owner="root@h", now=NOW)
        assert (caught.value.code, caught.value.reason) == ("LEASE_REFUSED", "overlap")
        assert "/pyproject.toml" in caught.value.next_action
        copied = pickle.loads(pickle.dumps(caught.value))
        assert copied.next_action == caught.value.next_action
    assert _refs(repo) == {"refs/aegis/lanes/tools": peer.oid}
    assert team.claim(repo, "root", ["/pyproject.toml"], owner="root@h", now=NOW).action == "claimed"


@pytest.mark.parametrize("root_exists", [False, True])
@pytest.mark.parametrize("local_exists", [False, True])
def test_anchor_hint_uses_repository_top_level_from_a_subdirectory(repo: Path, root_exists, local_exists):
    from tests.unit.core.test_storage_confined import make_store

    make_store(repo)
    tools = repo / "tools"
    tools.mkdir()
    if local_exists:
        (tools / "pyproject.toml").write_text("subdirectory\n", encoding="utf-8")
    if root_exists:
        (repo / "pyproject.toml").write_text("root\n", encoding="utf-8")
    held = team.claim(repo, "peer", ["other/file.py"], owner="peer@h", now=NOW)
    for _ in range(2):
        with pytest.raises(team.LeaseRefused) as caught:
            team.claim(tools, "root", ["pyproject.toml"], owner="root@h", now=NOW)
        assert (caught.value.code, caught.value.reason, caught.value.lanes) == ("LEASE_REFUSED", "overlap", ("peer",))
        assert bool(caught.value.next_action) is root_exists
        if root_exists:
            assert "/pyproject.toml" in caught.value.next_action
    assert _refs(repo) == {"refs/aegis/lanes/peer": held.oid}


@pytest.mark.parametrize("failure", ["missing", "os", "git"])
def test_anchor_hint_preserves_refusal_when_top_level_is_unavailable(repo: Path, monkeypatch, failure):
    (repo / "pyproject.toml").write_text("root\n", encoding="utf-8")
    team.claim(repo, "peer", ["tools/a.py"], owner="peer@h", now=NOW)
    found = team.read_leases(repo)
    paths = team_paths.claim_paths(["pyproject.toml"])
    calls = []

    def unavailable(root):
        calls.append(root)
        if failure == "os":
            raise OSError("token=private-value")
        if failure == "git":
            raise gitsafe.GitError("token=private-value")
        return None

    monkeypatch.setattr(gitsafe, "toplevel", unavailable)
    for _ in range(2):
        assert team_paths.anchor_next_action(repo, paths, found, "root", NOW) == ""
    assert calls == [repo, repo]


@pytest.mark.parametrize("stored", ["pyproject.toml", ".//pyproject.toml"])
def test_expired_renew_overlap_does_not_probe_for_claim_advice(repo: Path, monkeypatch, stored):
    oid = _plant(repo, "refs/aegis/lanes/root",
                 json.dumps(_valid_blob(lane="root", paths=[stored], ttl_s=1)).encode())
    peer = team.claim(repo, "peer", ["tools/a.py"], owner="peer@h", now=NOW + 1)
    before = _refs(repo)

    def forbidden(root, name):
        raise AssertionError("renew must not probe root files for claim-only advice")

    # This test-owned seam is the OS file probe, not a process-global operation.
    monkeypatch.setattr(team_paths, "_root_file", forbidden)
    for _ in range(2):
        with pytest.raises(team.LeaseRefused) as caught:
            team.renew(repo, "root", oid, now=NOW + 1)
        assert (caught.value.code, caught.value.reason, caught.value.lanes, caught.value.next_action) == (
            "LEASE_REFUSED", "overlap", ("peer",), "")
    assert _refs(repo) == before == {"refs/aegis/lanes/root": oid, "refs/aegis/lanes/peer": peer.oid}


@pytest.mark.parametrize("obstacle", ["missing", "directory", "real_overlap", "unreadable", "taken", "partial"])
def test_root_anchor_hint_is_absent_unless_anchoring_resolves_the_entire_refusal(repo: Path, obstacle):
    from tests.unit.core.test_storage_confined import make_store

    make_store(repo)
    if obstacle == "directory":
        (repo / "pyproject.toml").mkdir()
    elif obstacle != "missing":
        (repo / "pyproject.toml").write_text("", encoding="utf-8")
    peer_path = "/pyproject.toml" if obstacle == "real_overlap" else "tools/a.py"
    team.claim(repo, "tools", [peer_path], owner="peer@h", now=NOW)
    if obstacle == "unreadable":
        _plant(repo, "refs/aegis/lanes/bad", b"not-json")
    if obstacle == "taken":
        team.claim(repo, "root", ["src/**"], owner="other@h", now=NOW)
    wanted = ["pyproject.toml", "tools/**"] if obstacle == "partial" else ["pyproject.toml"]
    with pytest.raises(team.LeaseRefused) as caught:
        team.claim(repo, "root", wanted, owner="root@h", now=NOW)
    assert caught.value.next_action == ""


def test_unsupported_descriptor_probe_keeps_the_original_overlap_refusal(repo: Path, monkeypatch):
    (repo / "pyproject.toml").write_text("", encoding="utf-8")
    team.claim(repo, "tools", ["tools/a.py"], owner="peer@h", now=NOW)
    monkeypatch.setattr(storage_confined, "descriptor_supported", lambda: False)
    for _ in range(2):
        with pytest.raises(team.LeaseRefused) as caught:
            team.claim(repo, "root", ["pyproject.toml"], owner="root@h", now=NOW)
        assert (caught.value.code, caught.value.reason, caught.value.next_action) == (
            "LEASE_REFUSED", "overlap", "")


def test_anchor_hint_redacts_before_truncating_untrusted_names(repo: Path):
    from tests.unit.core.test_storage_confined import make_store

    make_store(repo)
    names = ["a" * 240, "b" * 200, "token=" + "private" * 15]
    for name in names:
        (repo / name).write_bytes(b"")
    team.claim(repo, "tools", ["tools/a.py"], owner="peer@h", now=NOW)
    with pytest.raises(team.LeaseRefused) as caught:
        team.claim(repo, "root", names, owner="root@h", now=NOW)
    hint = caught.value.next_action
    assert "token=REDACTED" in hint
    assert "private" not in hint
    assert len(hint) <= 512 and hint.endswith("...")


@pytest.mark.parametrize("failure", ["symlink", "io"])
def test_root_hint_file_swap_or_io_failure_keeps_refusal_and_closes_descriptors(repo: Path, monkeypatch, failure):
    from conftest import symlink_or_skip
    from tests.unit.core.test_storage_confined import make_store, ModuleOS

    make_store(repo)
    target = repo / "pyproject.toml"
    target.write_bytes(b"")
    outside = repo.parent / "outside"
    outside.write_bytes(b"secret")
    if failure == "symlink":
        probe = repo / "probe"
        symlink_or_skip(outside, probe)
        probe.unlink()
    team.claim(repo, "tools", ["tools/a.py"], owner="peer@h", now=NOW)
    live = set()

    def opened(name, *args, **kwargs):
        if name == "pyproject.toml":
            if failure == "io":
                raise OSError("token=private-value")
            target.unlink()
            symlink_or_skip(outside, target)
        fd = os.open(name, *args, **kwargs)
        live.add(fd)
        return fd

    def closed(fd):
        live.remove(fd)
        os.close(fd)

    monkeypatch.setattr(storage_confined, "os", ModuleOS(open=opened, close=closed))
    with pytest.raises(team.LeaseRefused) as caught:
        team.claim(repo, "root", ["pyproject.toml"], owner="root@h", now=NOW)
    assert (caught.value.code, caught.value.reason, caught.value.next_action) == ("LEASE_REFUSED", "overlap", "")
    assert "private-value" not in str(caught.value)
    assert not live
    assert outside.read_bytes() == b"secret"


def _containment_commits(repo: Path, files, policy=None):
    if policy is not None:
        (repo / ".aegis").mkdir(exist_ok=True)
        (repo / ".aegis" / "team.json").write_text(json.dumps(policy), encoding="utf-8")
        _git(repo, "add", ".aegis/team.json")
        _git(repo, "commit", "-q", "-m", "base policy")
    base = _git(repo, "rev-parse", "HEAD").strip()
    _git(repo, "branch", "base")
    for path in files:
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("change\n", encoding="utf-8")
    _git(repo, "add", "--", *files)
    _git(repo, "commit", "-q", "-m", "lane changes")
    return base, _git(repo, "rev-parse", "HEAD").strip()


def _mutated_gate(kind):
    source = Path(__file__).resolve().parents[3] / "aegis_core" / "lane_gate.py"
    text = source.read_text(encoding="utf-8")
    target = "team_paths.first_match(leased, path)"
    replacement = "next((g for g in leased.matching if _rule_path_matches(g, path)), None)"
    helper = ""
    if kind == "wrapper":
        replacement = "_unsafe_lease_wrapper(leased, path)"
        helper = ("\ndef _unsafe_lease_wrapper(leased, path):\n"
                  "    return next((g for g in leased.matching if _rule_path_matches(g, path)), None)\n")
    elif kind in ("allowed", "allowed-cli", "allowed-policy"):
        target = "allowed = [] if leased is not None else [(glob, paths_source) for glob in lane_paths]"
        values = {"allowed": "lane_paths", "allowed-cli": "_cli_globs(lane_paths)",
                  "allowed-policy": 'team._policy_globs(list(lane_paths), "paths")'}[kind]
        replacement = "allowed = [(glob, paths_source) for glob in " + values + "]"
    elif kind == "filter":
        target = "entries = gitsafe.diff_entries(top, merge_base, head)"
        indent = next(line[:line.index(target)] for line in text.splitlines() if target in line)
        replacement = (target + "\n" + indent + "entries = [e for e in entries if not any(\n" + indent
                       + "    _rule_path_matches(g, e[3]) for g in leased.matching)]")
    elif kind == "rebind":
        target = "for glob, source in allowed:"
        replacement = "allowed = [(g, lease_source) for g in leased.matching]\n    " + target
    elif kind == "argon-append":
        target = ("if leased is not None and not protected:\n"
                  "        glob = team_paths.first_match(leased, path)\n"
                  "        if glob is not None:\n"
                  "            return PathCheck(path, status, old_mode, new_mode, True, glob, lease_source, protected)")
        replacement = "allowed = list(allowed) + [(g, lease_source) for g in leased.matching]"
    elif kind == "argon-changes":
        target = "_contain(entry, allowed, leased, paths_source) for entry in entries"
        replacement = ("PathCheck(e[3], e[0], e[1], e[2], "
                       "any(_rule_path_matches(g, e[3]) for g in leased.matching), "
                       "None, None, False) for e in entries")
    assert text.count(target) == 1
    if kind != "baseline":
        text = text.replace(target, replacement) + helper
    # Execute real function bodies in a test-owned namespace, without mutating
    # process globals or replacing production filesystem/Git boundaries.
    tree = ast.parse(text)
    tree.body = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    namespace = dict(vars(lane_gate))
    exec(compile(tree, str(source), "exec"), namespace)
    return namespace["check_lane"]


@pytest.mark.parametrize("captured", [False, True], ids=["live", "captured"])
@pytest.mark.parametrize("kind", ["baseline", "argon", "wrapper", "allowed", "filter", "rebind",
                                  "allowed-cli", "allowed-policy", "argon-append", "argon-changes"])
def test_lease_rule_mutants_fail_closed_at_runtime(repo: Path, captured, kind):
    _, tip = _containment_commits(repo, ["nested/README.md"])
    held = team.claim(repo, "root", ["/README.md"], owner="o@h", now=NOW)
    before = _refs(repo), _events(repo, "lane_check")
    check = _mutated_gate(kind)
    options = {"paths": held.lease.paths, "tip": tip} if captured else {}
    for _ in range(2):
        if kind == "baseline":
            result = check(repo, "root", base="base", now=NOW, record=False, **options)
            assert not result.containment_passed
            assert [(row.path, row.allowed) for row in result.changes] == [("nested/README.md", False)]
        else:
            with pytest.raises(lane_gate.LaneGateUsage) as caught:
                check(repo, "root", base="base", now=NOW, **options)
            assert (caught.value.code, caught.value.status, caught.value.reason, caught.value.next_action) == (
                "VALIDATION_ERROR", "refused", "lease_rule_mix",
                "Repair lease/rule separation, then retry aegis check --lane.")
            assert str(caught.value) == (
                "refused: lease globs cannot use rule matching; "
                "Repair lease/rule separation, then retry aegis check --lane.")
    assert (_refs(repo), _events(repo, "lane_check")) == before


@pytest.mark.parametrize("captured", [False, True], ids=["live", "captured"])
@pytest.mark.parametrize("paths,files,admitted,legacy", [
    (["/README.md"], ["README.md"], {"README.md"}, False),
    (["/README.md"], ["nested/README.md"], set(), False),
    (["/README.md"], ["README.md", "nested/README.md"], {"README.md"}, False),
    (["/docs/"], ["docs/x.txt", "a/docs/x.txt"], {"docs/x.txt"}, False),
    (["/docs/"], ["docs/x.txt"], {"docs/x.txt"}, False),
    (["README.md"], ["README.md", "nested/README.md"], {"README.md", "nested/README.md"}, False),
    (["/docs/**/*.txt"], ["docs/x.txt", "docs/a/x.txt", "a/docs/x.txt"],
     {"docs/x.txt", "docs/a/x.txt"}, False),
    (["/README.md docs/**"], ["README.md", "nested/README.md", "docs/x.txt"],
     {"README.md", "nested/README.md", "docs/x.txt"}, True),
    (["/README.md", "docs/a.txt src/a.txt"], ["nested/README.md", "src/a.txt"],
     {"nested/README.md", "src/a.txt"}, True),
    ([".//README.md"], ["README.md", "nested/README.md"], {"README.md", "nested/README.md"}, True),
    (["./README.md"], ["nested/README.md"], {"nested/README.md"}, True),
    ([".//pyproject.toml"], ["nested/pyproject.toml"], {"nested/pyproject.toml"}, True),
])
def test_lease_containment_uses_the_conflict_parser(repo: Path, paths, files, admitted, legacy, captured):
    _, tip = _containment_commits(repo, files)
    if legacy:
        _plant(repo, "refs/aegis/lanes/root", json.dumps(_valid_blob(lane="root", paths=paths)).encode())
    else:
        team.claim(repo, "root", paths, owner="o@h", now=NOW)
    before = _refs(repo), _events(repo, "lane_check")
    options = {"paths": paths, "tip": tip} if captured else {}
    source = "cli" if captured else "lease"
    for _ in range(2):
        result = lane_gate.check_lane(repo, "root", base="base", now=NOW, record=False, **options)
        assert result.containment_passed is (set(files) == admitted)
        assert result.paths_source == source
        assert result.paths == tuple(paths)
        assert {change.path: (change.allowed, change.source) for change in result.changes} == {
            path: (path in admitted, source if path in admitted else None) for path in files}
    assert (_refs(repo), _events(repo, "lane_check")) == before


@pytest.mark.parametrize("policy_source", ["cli", "base", "shared"])
def test_rule_sourced_containment_keeps_root_slash_normalization(repo: Path, policy_source):
    policy = {"v": 1, "shared": ["/README.md"] if policy_source == "shared" else [],
              "lanes": {"root": ["/README.md"]}}
    base, _ = _containment_commits(repo, ["nested/README.md"], policy)
    if policy_source == "shared":
        team.claim(repo, "root", ["/other.txt"], owner="o@h", now=NOW)
    options = {"paths": ["/README.md"]} if policy_source == "cli" else {"base_policy": True}
    if policy_source == "shared":
        options = {}
    result = lane_gate.check_lane(repo, "root", base="base", now=NOW, record=False, **options)
    expected = {"cli": "cli", "base": "base@" + base, "shared": "worktree"}[policy_source]
    assert result.containment_passed
    assert [(change.path, change.allowed, change.source) for change in result.changes] == [
        ("nested/README.md", True, expected)]


def test_status_checks_captured_lease_anchors_with_exact_provenance(repo: Path):
    _containment_commits(repo, ["README.md", "nested/README.md"])
    claimed = team.claim(repo, "root", ["/README.md"], owner="o@h", branch="main", now=NOW)
    for _ in range(2):
        report = team_status.status(repo, NOW, base="base", check=True)
        assert report["checks_passed"] is False
        row, = report["lanes"]
        assert row["check"]["containment"]["passed"] is False
        assert row["check"]["provenance"]["paths"] == "lease@" + claimed.oid
        assert {change["path"]: (change["allowed"], change["source"])
                for change in row["check"]["containment"]["paths"]} == {
            "README.md": (True, "lease@" + claimed.oid), "nested/README.md": (False, None)}


def test_captured_containment_is_independent_of_a_concurrently_replaced_lease(repo: Path):
    _, tip = _containment_commits(repo, ["README.md", "nested/README.md"])
    old = team.claim(repo, "root", ["/README.md"], owner="old@h", now=NOW)
    team.release(repo, "root", old.oid)
    current = team.claim(repo, "root", ["/unrelated.txt"], owner="new@h", now=NOW)
    for _ in range(2):
        result = lane_gate.check_lane(repo, "root", base="base", paths=old.lease.paths,
                                      tip=tip, now=NOW, record=False)
        assert result.containment_passed is False
        assert result.paths == ("/README.md",)
        assert result.paths_source == "cli"  # team_status owns the lease@OID rewrite.
        assert {change.path: (change.allowed, change.source) for change in result.changes} == {
            "README.md": (True, "cli"), "nested/README.md": (False, None)}
    assert _ref(repo, "root") == current.oid


@pytest.mark.parametrize("paths", [[], ["/"], ["../token=private-value"], ["\ud800"],
                                   ["x" * (team.MAX_LEASE_BYTES + 1)]],
                         ids=["empty", "root-only", "climbs", "non-utf8", "oversized"])
def test_invalid_captured_paths_refuse_before_git_with_a_fixed_usage_error(tmp_path, paths):
    for _ in range(2):
        with pytest.raises(lane_gate.LaneGateUsage) as caught:
            lane_gate.check_lane(tmp_path, "root", paths=paths, tip="a" * 40, record=False)
        assert caught.value.code == "VALIDATION_ERROR"
        assert str(caught.value) == "paths: invalid captured lease globs"


@pytest.mark.parametrize("raw", [".//README.md", "./README.md", ".//pyproject.toml"])
@pytest.mark.parametrize("operation", ["read", "renew", "transfer"])
def test_old_writer_blobs_keep_width_across_reads_renewals_and_transfers(repo: Path, raw, operation):
    # Construct the exact bytes an old claim writer normalized and stored.
    written = match.normalize_path("/" + raw)
    assert written == raw
    basename = match.normalize_path(written)
    nested = "nested/" + basename
    _containment_commits(repo, [nested])
    original = _plant(repo, "refs/aegis/lanes/root", json.dumps(_valid_blob(lane="root", paths=[written])).encode())
    oid = original
    if operation == "renew":
        oid = team.renew(repo, "root", oid, now=NOW + 1).oid
    elif operation == "transfer":
        oid = team.transfer(repo, "root", oid, "new@h", now=NOW + 1).oid
    assert _blob(repo, oid)["paths"] == [written]
    for _ in range(2):
        held = team.read_leases(repo).get("root")
        assert held.paths == (written,)
        assert held.path_set.matching == (basename,)
        result = lane_gate.check_lane(repo, "root", base="base", now=NOW + 1, record=False)
        assert result.containment_passed
        assert [(change.path, change.source) for change in result.changes] == [(nested, "lease")]
        with pytest.raises(team.LeaseRefused) as caught:
            team.claim(repo, "peer", [nested], owner="peer@h", now=NOW + 1)
        assert (caught.value.code, caught.value.reason, caught.value.lanes) == ("LEASE_REFUSED", "overlap", ("root",))
    assert _ref(repo, "root") == oid


@pytest.mark.parametrize("stored", [".//README.md", "a.py /", "a.py .."])
def test_claim_retry_rechecks_a_concurrently_installed_old_spelling(repo: Path, monkeypatch, stored):
    old = team.claim(repo, "root", ["/unused.txt"], owner="old@h", ttl_s=1, now=NOW)
    real = gitsafe.update_ref

    def replaced(cwd, ref, new, expected):
        monkeypatch.setattr(gitsafe, "update_ref", real)
        real(cwd, ref, None, old.oid)
        _plant(repo, "refs/aegis/lanes/peer",
               json.dumps(_valid_blob(lane="peer", paths=[stored])).encode())
        return real(cwd, ref, new, expected)

    monkeypatch.setattr(gitsafe, "update_ref", replaced)
    with pytest.raises(team.LeaseRefused) as caught:
        team.claim(repo, "root", ["nested/README.md"], owner="new@h", now=NOW + 1)
    assert (caught.value.code, caught.value.reason, caught.value.lanes) == ("LEASE_REFUSED", "overlap", ("peer",))
    assert _ref(repo, "root") is None


@pytest.mark.parametrize("raw", ["a.py /", "/ a.py", "a.py //", "a.py ./", "a.py /./",
                                 "a.py .//", "a.py ..", ".. a.py", "a.py ../x", "a.py /../x",
                                 "a.py\t/", "a.py\u2003/", "a.py\n.."])
def test_invalid_legacy_components_refuse_and_make_stored_leases_fail_closed(repo: Path, raw):
    _, tip = _containment_commits(repo, ["unrelated.txt"])
    oid = _plant(repo, "refs/aegis/lanes/root", json.dumps(_valid_blob(lane="root", paths=[raw])).encode())
    for _ in range(2):
        with pytest.raises(team_paths.LeasePathError, match=r"\Apaths is not a non-empty list of globs\Z"):
            team_paths.stored_paths([raw])
        found = team.read_leases(repo)
        assert found.get("root") is None
        assert found.unreadable_lane("root").oid == oid
        with pytest.raises(team.LeaseRefused) as refused:
            team.claim(repo, "peer", ["unrelated.txt"], owner="peer@h", now=NOW)
        assert (refused.value.code, refused.value.reason, refused.value.lanes) == (
            "LEASE_REFUSED", "overlap", ("root",))
        for options, message in (({}, _unreadable_paths_message("root", oid)),
                                 ({"paths": [raw], "tip": tip}, "paths: invalid captured lease globs")):
            with pytest.raises(lane_gate.LaneGateUsage) as usage:
                lane_gate.check_lane(repo, "root", base="base", now=NOW, record=False, **options)
            assert (usage.value.code, str(usage.value)) == ("VALIDATION_ERROR", message)
    assert _ref(repo, "root") == oid


def _unreadable_paths_message(lane, oid):
    return (f"lane {lane} has no live lease (its lease is unreadable): "
            f"claim it with aegis team claim (release {lane} --expect {oid}, then claim), "
            "give its globs with --paths, or read them from base with --base-policy")


@pytest.mark.parametrize("paths", [["a.py /"], [], "token=private-value"],
                         ids=["invalid-component", "empty", "non-list"])
@pytest.mark.parametrize("windows_stderr", [False, True], ids=["native-stderr", "windows-stderr"])
def test_unreadable_stored_paths_keep_exact_cli_recovery_bytes(repo: Path, paths, windows_stderr):
    (repo / ".aegis" / "rules").mkdir(parents=True)
    _containment_commits(repo, ["unrelated.txt"])
    oid = _plant(repo, "refs/aegis/lanes/root", json.dumps(_valid_blob(lane="root", paths=paths)).encode())
    expected = _unreadable_paths_message("root", oid)
    source = Path(__file__).resolve().parents[3]
    environment = dict(os.environ, PYTHONPATH=str(source))
    environment.pop("AEGIS_WORKSPACE", None)
    entry = [sys.executable, "-m", "aegis_cli"]
    if windows_stderr:
        # Run the real CLI with Windows text newline translation on every host.
        entry = [sys.executable, "-c", (
            "import io,sys; from aegis_cli.cli import main; "
            "sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', newline='\\r\\n'); "
            "sys.exit(main(sys.argv[1:]))")]
    for _ in range(2):
        result = subprocess.run([*entry, "--workspace", str(repo),
                                 "check", "--lane", "root", "--base", "base"],
                                cwd=repo, env=environment, capture_output=True, timeout=30)
        stderr = result.stderr.replace(b"\r\n", b"\n")  # Windows text stderr
        assert (result.returncode, result.stdout, stderr) == (2, b"", ("Error: " + expected + "\n").encode())
    assert _ref(repo, "root") == oid


@pytest.mark.parametrize("raw", ["a.py /", "a.py ..", "a.py ../x", "a.py /./"])
def test_invalid_legacy_components_in_a_snapshot_refuse_before_git(tmp_path, raw):
    for _ in range(2):
        with pytest.raises(lane_gate.LaneGateUsage) as caught:
            lane_gate.check_lane(tmp_path, "root", paths=[raw], tip="a" * 40, record=False)
        assert (caught.value.code, str(caught.value)) == (
            "VALIDATION_ERROR", "paths: invalid captured lease globs")


@pytest.mark.parametrize("raw", [" ", "\t", " \n\t", "\u2003", "\xa0\u2028"],
                         ids=["space", "tab", "mixed", "em-space", "unicode"])
def test_empty_legacy_split_stays_unreadable_conservative_and_not_collected(repo: Path, raw):
    # Argon's exact expired lease: an invalid reading has no trusted expiry.
    oid = _plant(repo, "refs/aegis/lanes/root",
                 json.dumps(_valid_blob(lane="root", paths=[raw], ts=100, ttl_s=1)).encode())
    for _ in range(2):
        with pytest.raises(team_paths.LeasePathError, match=r"\Apaths is not a non-empty list of globs\Z"):
            team_paths.stored_paths([raw])
        found = team.read_leases(repo)
        assert found.get("root") is None
        assert found.unreadable_lane("root").oid == oid
        with pytest.raises(team.LeaseRefused) as caught:
            team.claim(repo, "peer", ["other.txt"], owner="peer@h", now=101)
        assert (caught.value.code, caught.value.reason, caught.value.lanes) == ("LEASE_REFUSED", "overlap", ("root",))
        result = team.gc(repo, now=101)
        assert (result.collected, result.kept) == ((), (("root", "unreadable"),))
        assert _refs(repo) == {"refs/aegis/lanes/root": oid}


@pytest.mark.parametrize("raw", [" ", "\t", " \n\t", "\u2003", "\xa0\u2028"],
                         ids=["space", "tab", "mixed", "em-space", "unicode"])
def test_empty_legacy_split_in_capture_refuses_before_git(tmp_path, raw, monkeypatch):
    def unexpected_git(*args, **kwargs):
        raise AssertionError("invalid captured paths must refuse before Git")

    monkeypatch.setattr(gitsafe, "toplevel", unexpected_git)
    for _ in range(2):
        with pytest.raises(lane_gate.LaneGateUsage) as caught:
            lane_gate.check_lane(tmp_path, "root", paths=[raw], tip="a" * 40, record=False)
        assert (caught.value.code, str(caught.value)) == ("VALIDATION_ERROR", "paths: invalid captured lease globs")


@pytest.mark.parametrize("raw", ["a.py /", "a.py .."])
@pytest.mark.parametrize("operation", ["renew", "transfer"])
def test_invalid_legacy_components_cannot_be_rewritten(repo: Path, raw, operation):
    oid = _plant(repo, "refs/aegis/lanes/root", json.dumps(_valid_blob(lane="root", paths=[raw])).encode())
    for _ in range(2):
        with pytest.raises(team.LeaseRefused) as caught:
            if operation == "renew":
                team.renew(repo, "root", oid, now=NOW)
            else:
                team.transfer(repo, "root", oid, "new@h", now=NOW)
        assert (caught.value.code, caught.value.reason, caught.value.current) == (
            "LEASE_REFUSED", "unreadable", oid)
    assert _ref(repo, "root") == oid


def test_whitespace_lease_paths_are_refused_without_echo_or_effects(repo: Path):
    recovery = "give each path as its own entry (use ? for a space inside a name)"
    for space in (" ", "\t", "\n", "\r", "\v", "\f", "\x85", "\xa0", "\u1680",
                  "\u2003", "\u2028", "\u2029", "\u202f", "\u205f", "\u3000"):
        for raw in (space + "docs/**", "docs/" + space + "token=secret", "docs/**" + space):
            reason = "has a control character" if ord(space) < 32 or ord(space) == 133 else "has whitespace"
            for _ in range(2):
                with pytest.raises(team.TeamUsageError) as caught:
                    team.claim(repo, "docs", [raw], owner="o@h", now=NOW)
                assert str(caught.value) == "paths: glob 1 " + reason + "; " + recovery
                assert caught.value.code == "VALIDATION_ERROR"
    assert _refs(repo) == {}
    assert _events(repo, "lease_claimed") == _events(repo, "lease_denied") == []


@pytest.mark.parametrize("paths", [["docs/reference.md src/**"], ["docs/**", "src/\xa0**"],
                                   ["docs/reference.md\tREADME.md"]])
def test_legacy_whitespace_lease_paths_are_read_without_changing_their_spelling(paths):
    raw = json.dumps(_valid_blob(paths=paths)).encode()
    lease = team.parse_lease(raw, "docs", "a" * 40)
    assert lease.paths == tuple(paths)
    assert lease.path_set.legacy
    assert lease.path_set.matching == tuple(dict.fromkeys(g for raw in paths for g in (raw, *raw.split())))


def test_live_legacy_whitespace_leases_block_parts_and_raw_but_not_disjoint_paths(repo: Path):
    raw = json.dumps(_valid_blob(paths=["docs/reference.md src/file.py"])).encode()
    oid = _plant(repo, "refs/aegis/lanes/docs", raw)
    found = team.read_leases(repo)
    assert found.unreadable == ()
    assert found.get("docs").paths == ("docs/reference.md src/file.py",)
    assert team.live_lease(repo, "docs", now=NOW).oid == oid
    recovery = f"release docs --expect {oid}, then claim each path as its own entry"
    for wanted in ("docs/reference.md", "src/file.py", "docs/reference.md?src/file.py"):
        for _ in range(2):
            with pytest.raises(team.LeaseRefused) as caught:
                team.claim(repo, "new", [wanted], owner="o@h", now=NOW)
            assert (caught.value.reason, caught.value.lanes) == ("overlap", ("docs",))
            assert str(caught.value).endswith(recovery)
            assert "docs/reference.md src/file.py" not in str(caught.value)
    with pytest.raises(team.LeaseRefused) as caught:
        team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW)
    assert (caught.value.reason, caught.value.current) == ("taken", oid)
    assert str(caught.value).endswith(recovery)
    assert team.claim(repo, "new", ["unrelated/**"], owner="o@h", now=NOW).action == "claimed"
    _plant(repo, "refs/aegis/lanes/peer", json.dumps(_valid_blob(lane="peer", paths=["src/file.py"])).encode())
    views = {view["lane"]: view for view in team.describe(repo, now=NOW)["leases"]}
    assert views["docs"]["overlaps"] == ["peer"]
    assert views["peer"]["overlaps"] == ["docs"]
    assert gitsafe.read_object(repo, oid, team.MAX_LEASE_BYTES) == raw


def test_expired_legacy_whitespace_leases_do_not_block_and_gc_collects_them(repo: Path):
    raw = json.dumps(_valid_blob(paths=["docs/reference.md src/**"])).encode()
    oid = _plant(repo, "refs/aegis/lanes/docs", raw)
    assert team.live_lease(repo, "docs", now=NOW + 3600) is None
    assert team.claim(repo, "new", ["src/file.py"], owner="o@h", now=NOW + 3600).action == "claimed"
    views = {view["lane"]: view for view in team.describe(repo, now=NOW + 3600)["leases"]}
    assert views["new"]["overlaps"] == []
    result = team.gc(repo, now=NOW + 3600)
    assert [(change.lane, change.previous) for change in result.collected] == [("docs", oid)]
    assert _ref(repo, "docs") is None
    assert gitsafe.read_object(repo, oid, team.MAX_LEASE_BYTES) == raw


def test_overlap_refusal_carries_recovery_for_the_requested_legacy_lane(repo: Path):
    raw = json.dumps(_valid_blob(paths=["docs/a.py docs/b.py"])).encode()
    oid = _plant(repo, "refs/aegis/lanes/docs", raw)
    _plant(repo, "refs/aegis/lanes/api", json.dumps(_valid_blob(lane="api", paths=["src/**"])).encode())
    with pytest.raises(team.LeaseRefused) as caught:
        team.claim(repo, "docs", ["src/file.py"], owner="o@h", now=NOW)
    assert (caught.value.reason, caught.value.lanes) == ("overlap", ("api",))
    assert str(caught.value).endswith(f"release docs --expect {oid}, then claim each path as its own entry")
    assert _ref(repo, "docs") == oid


@pytest.mark.parametrize("age", [0, 3600])
def test_legacy_whitespace_renew_and_transfer_refuse_with_recovery(repo: Path, age):
    raw = json.dumps(_valid_blob(paths=["docs/reference.md src/**"])).encode()
    oid = _plant(repo, "refs/aegis/lanes/docs", raw)
    recovery = f"release docs --expect {oid}, then claim each path as its own entry"
    for operation in (lambda: team.renew(repo, "docs", oid, now=NOW + age),
                      lambda: team.transfer(repo, "docs", oid, "new@h", now=NOW + age)):
        for _ in range(2):
            with pytest.raises(team.LeaseRefused) as caught:
                operation()
            assert (caught.value.reason, caught.value.current) == ("legacy_paths", oid)
            assert caught.value.code == "LEASE_REFUSED"
            assert str(caught.value).endswith(recovery)
    with pytest.raises(team.LeaseRefused) as caught:
        team.renew(repo, "docs", "f" * 40, now=NOW + age)
    assert caught.value.reason == "stale"
    assert str(caught.value).endswith(recovery)
    import pickle
    copied = pickle.loads(pickle.dumps(caught.value))
    assert str(copied) == str(caught.value)
    assert copied.lease.path_set == caught.value.lease.path_set
    assert _refs(repo) == {"refs/aegis/lanes/docs": oid}
    assert gitsafe.read_object(repo, oid, team.MAX_LEASE_BYTES) == raw
    assert _events(repo, "lease_claimed") == []
    assert team.release(repo, "docs", oid).action == "released"
    assert team.claim(repo, "new", ["docs/reference.md"], owner="o@h", now=NOW + age).action == "claimed"


@pytest.mark.parametrize("legacy_lane,reason", [("api", "overlap"), ("docs", "taken")])
def test_claim_retry_rechecks_concurrently_installed_legacy_paths(repo: Path, monkeypatch,
                                                                legacy_lane, reason):
    old = team.claim(repo, "docs", ["docs/**"], owner="old@h", ttl_s=1, now=NOW)
    real = gitsafe.update_ref
    installed = []

    def replaced_meanwhile(cwd, ref, new, old_value):
        monkeypatch.setattr(gitsafe, "update_ref", real)
        real(cwd, ref, None, old.oid)
        raw = json.dumps(_valid_blob(lane=legacy_lane, paths=["docs/reference.md src/**"])).encode()
        installed.append(_plant(repo, "refs/aegis/lanes/" + legacy_lane, raw))
        return real(cwd, ref, new, old_value)

    monkeypatch.setattr(gitsafe, "update_ref", replaced_meanwhile)
    with pytest.raises(team.LeaseRefused) as caught:
        team.claim(repo, "docs", ["src/file.py"], owner="new@h", now=NOW + 1)
    assert caught.value.reason == reason
    assert str(caught.value).endswith(
        f"release {legacy_lane} --expect {installed[0]}, then claim each path as its own entry")
    assert _refs(repo) == {"refs/aegis/lanes/" + legacy_lane: installed[0]}
    assert len(_events(repo, "lease_claimed")) == 1


def test_concurrent_claims_from_worktrees_refuse_legacy_paths(repo: Path, worktree: Path):
    raw = json.dumps(_valid_blob(lane="api", paths=["docs/reference.md src/**"], ts=int(time.time()))).encode()
    oid = _plant(repo, "refs/aegis/lanes/api", raw)
    outcomes = _race(repo, worktree, "docs", racers=3)
    assert sorted(result[1] for result in outcomes) == ["refused:overlap"] * 3
    assert _refs(repo) == {"refs/aegis/lanes/api": oid}
    assert gitsafe.read_object(repo, oid, team.MAX_LEASE_BYTES) == raw
    assert _events(repo, "lease_claimed") == []


def test_whitespace_lease_cli_exit_codes_and_safe_messages(repo: Path, capsys):
    from aegis_cli.cli import main

    argv = ["--workspace", str(repo), "team", "claim", "docs", "--paths"]
    for space in (" ", "\t", "\n", "\xa0"):
        assert main(argv + ["docs/token=secret" + space + "src/**", "--json"]) == 2
        captured = capsys.readouterr()
        reason = "has a control character" if space in ("\t", "\n") else "has whitespace"
        assert json.loads(captured.out)["error"] == (
            "paths: glob 1 " + reason + "; give each path as its own entry (use ? for a space inside a name)")
        assert "secret" not in captured.out + captured.err
    raw = json.dumps(_valid_blob(lane="api", paths=["docs/reference.md src/**"], ts=int(time.time()))).encode()
    oid = _plant(repo, "refs/aegis/lanes/api", raw)
    assert main(argv + ["docs/reference.md", "--json"]) == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out)["reason"] == "overlap"
    assert json.loads(captured.out)["message"].endswith(
        f"release api --expect {oid}, then claim each path as its own entry")
    for action in ("renew", "transfer"):
        args = ["--workspace", str(repo), "team", action, "api", "--expect", oid, "--json"]
        if action == "transfer":
            args += ["--owner", "new@h"]
        assert main(args) == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["reason"] == "legacy_paths"
        assert payload["message"].endswith(f"release api --expect {oid}, then claim each path as its own entry")
    assert _refs(repo) == {"refs/aegis/lanes/api": oid}


def test_overlap_uses_boundary_parsed_values_without_revalidating_them():
    class OnceParsed(str):
        parsed = False

        def __iter__(self):
            assert not self.parsed, "overlap revalidated a parsed path"
            return super().__iter__()

    raw = OnceParsed("docs/a.py src/b.py")
    held = team_paths.stored_paths([raw])
    wanted = team_paths.claim_paths(["src/b.py"])
    disjoint = team_paths.claim_paths(["other/**"])
    raw.parsed = True
    for _ in range(3):
        assert team_paths.overlap(held, wanted)
        assert not team_paths.overlap(held, disjoint)


@pytest.mark.parametrize("paths", [["docs/a.py\x1bb.py"], ["docs/a.py\ud800"], [7], "docs/a.py src/b.py"])
def test_malformed_legacy_paths_remain_unreadable(paths):
    with pytest.raises(team.LeaseFormatError) as caught:
        team.parse_lease(json.dumps(_valid_blob(paths=paths)).encode(), "docs", "a" * 40)
    assert str(caught.value) == "paths is not a non-empty list of globs"


def test_gc_retains_a_legacy_lease_replaced_after_reading(repo: Path, monkeypatch):
    raw = json.dumps(_valid_blob(paths=["docs/a.py src/b.py"])).encode()
    _plant(repo, "refs/aegis/lanes/docs", raw)
    real = gitsafe.update_ref
    replacement = []

    def replaced_meanwhile(cwd, ref, new, old):
        monkeypatch.setattr(gitsafe, "update_ref", real)
        replacement.append(_plant(repo, ref, json.dumps(_valid_blob(
            paths=["docs/a.py src/b.py"], ts=NOW + 3600)).encode()))
        return real(cwd, ref, new, old)

    monkeypatch.setattr(gitsafe, "update_ref", replaced_meanwhile)
    result = team.gc(repo, now=NOW + 3600)
    assert result.collected == ()
    assert result.kept == (("docs", "changed after it was read"),)
    assert _ref(repo, "docs") == replacement[0]
    assert team.live_lease(repo, "docs", now=NOW + 3600).oid == replacement[0]


def test_lease_path_bounds_and_invalid_utf8_refuse_before_git(repo: Path):
    for paths, message in ((["x" * (team.MAX_LEASE_BYTES + 1)],
                            "paths: the lease would be larger than 64 KiB"),
                           (["docs/\ud800"], "paths: glob 1 is not UTF-8 text")):
        with pytest.raises(team.TeamUsageError) as caught:
            team.claim(repo, "docs", paths, owner="o@h", now=NOW)
        assert str(caught.value) == message
    assert _refs(repo) == {}


def test_nonlease_glob_validation_keeps_whitespace_compatibility():
    assert team.glob_problem("docs/my file.md") is None


def test_a_reclaim_after_release_never_reproduces_the_blob(repo: Path):
    first = team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW)
    team.release(repo, "docs", first.oid)
    second = team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW)
    assert second.oid != first.oid
    assert second.lease.claim_id != first.lease.claim_id


def test_a_claim_records_a_lease_claimed_event(repo: Path):
    change = team.claim(repo, "docs", ["docs/**"], owner="o@h", role="writer", now=NOW)
    rows = _events(repo, "lease_claimed")
    assert [(r["result"], r["detail"]) for r in rows] == [("claimed", {
        "lane": "docs", "oid": change.oid, "previous": None, "gen": 1,
        "claim_id": change.lease.claim_id, "owner": "o@h", "role": "writer",
    })]
    assert _events(repo, "lease_denied") == []
    assert change.warnings == ()


def test_a_live_lease_of_the_same_lane_is_taken(repo: Path):
    first = team.claim(repo, "docs", ["docs/**"], owner="first@h", now=NOW)
    with pytest.raises(team.LeaseRefused) as info:
        team.claim(repo, "docs", ["docs/**"], owner="second@h", now=NOW + 3599)
    assert (info.value.reason, info.value.lane, info.value.current) == ("taken", "docs", first.oid)
    assert info.value.lease == first.lease
    assert _ref(repo, "docs") == first.oid
    assert [(r["result"], r["detail"]) for r in _events(repo, "lease_denied")] == [
        ("refused", {"reason": "taken", "lane": "docs", "current": first.oid})]


# ── claim: overlap ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("held, wanted", [
    (["Makefile"], ["tools/**"]),
    (["*.py"], ["src/**"]),
    (["src/*.py"], ["src/a/**"]),
    (["Docs/**"], ["docs/x.md"]),
])
def test_a_live_overlapping_lease_of_another_lane_refuses_the_claim(repo: Path, held, wanted):
    other = team.claim(repo, "api", held, owner="o@h", now=NOW)
    with pytest.raises(team.LeaseRefused) as info:
        team.claim(repo, "docs", wanted, owner="o@h", now=NOW + 10)
    assert (info.value.reason, info.value.lanes, info.value.current) == ("overlap", ("api",), None)
    assert _ref(repo, "docs") is None
    assert _ref(repo, "api") == other.oid
    assert [(r["result"], r["detail"]) for r in _events(repo, "lease_denied")] == [
        ("refused", {"reason": "overlap", "lane": "docs", "lanes": ["api"]})]


def test_every_overlapping_lane_is_named(repo: Path):
    team.claim(repo, "b", ["src/b/**"], owner="o@h", now=NOW)
    team.claim(repo, "a", ["src/a/**"], owner="o@h", now=NOW)
    team.claim(repo, "c", ["docs/**"], owner="o@h", now=NOW)
    with pytest.raises(team.LeaseRefused) as info:
        team.claim(repo, "all", ["src/**"], owner="o@h", now=NOW)
    assert info.value.lanes == ("a", "b")


def test_disjoint_paths_do_not_overlap(repo: Path):
    team.claim(repo, "ab", ["a/b*"], owner="o@h", now=NOW)
    assert team.claim(repo, "ac", ["a/c/**"], owner="o@h", now=NOW).action == "claimed"


def test_an_expired_lease_of_another_lane_never_blocks(repo: Path):
    team.claim(repo, "api", ["src/**"], owner="o@h", ttl_s=60, now=NOW)
    assert team.claim(repo, "docs", ["src/docs/**"], owner="o@h", now=NOW + 60).action == "claimed"


def test_a_lease_whose_writer_clock_runs_ahead_still_blocks(repo: Path):
    team.claim(repo, "api", ["src/**"], owner="o@h", ttl_s=60, now=NOW + 10_000)
    with pytest.raises(team.LeaseRefused) as info:
        team.claim(repo, "docs", ["src/x/**"], owner="o@h", now=NOW)
    assert info.value.reason == "overlap"


def test_an_unreadable_lease_of_another_lane_counts_as_overlapping_everything(repo: Path):
    _plant(repo, "refs/aegis/lanes/mystery", b"not json")
    with pytest.raises(team.LeaseRefused) as info:
        team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW)
    assert (info.value.reason, info.value.lanes) == ("overlap", ("mystery",))
    assert _ref(repo, "docs") is None


def test_a_ref_that_names_no_lane_never_blocks_a_claim(repo: Path):
    # No aegis writer makes refs/aegis/lanes/x/y, and release cannot name it.
    _plant(repo, "refs/aegis/lanes/x/y", b"garbage")
    assert team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW).action == "claimed"


# ── claim: takeover of an expired lease ──────────────────────────────────────

def test_an_expired_lease_is_taken_over_by_cas_with_gen_plus_one_and_a_new_claim_id(repo: Path):
    old = team.claim(repo, "docs", ["docs/**"], owner="old@h", ttl_s=60, now=NOW)
    new = team.claim(repo, "docs", ["docs/**", "README.md"], owner="new@h", now=NOW + 60)
    assert (new.action, new.previous) == ("taken_over", old.oid)
    assert _ref(repo, "docs") == new.oid
    assert (new.lease.gen, new.lease.owner, new.lease.ts, new.lease.paths) == (
        2, "new@h", NOW + 60, ("docs/**", "README.md"))
    assert new.lease.claim_id != old.lease.claim_id
    assert [r["result"] for r in _events(repo, "lease_claimed")] == ["claimed", "taken_over"]
    assert _events(repo, "lease_claimed")[1]["detail"]["previous"] == old.oid


def test_one_second_before_expiry_the_lease_is_still_taken(repo: Path):
    old = team.claim(repo, "docs", ["docs/**"], owner="old@h", ttl_s=60, now=NOW)
    with pytest.raises(team.LeaseRefused) as info:
        team.claim(repo, "docs", ["docs/**"], owner="new@h", now=NOW + 59)
    assert (info.value.reason, info.value.current) == ("taken", old.oid)


def test_a_takeover_runs_the_overlap_check_first(repo: Path):
    old = team.claim(repo, "docs", ["docs/**"], owner="old@h", ttl_s=60, now=NOW)
    team.claim(repo, "api", ["docs/api/**"], owner="o@h", now=NOW + 100)
    with pytest.raises(team.LeaseRefused) as info:
        team.claim(repo, "docs", ["docs/**"], owner="new@h", now=NOW + 120)
    assert (info.value.reason, info.value.lanes) == ("overlap", ("api",))
    assert _ref(repo, "docs") == old.oid


def test_an_unreadable_lease_of_the_same_lane_is_taken_never_overwritten(repo: Path):
    oid = _plant(repo, "refs/aegis/lanes/docs", b'{"v":9}')
    with pytest.raises(team.LeaseRefused) as info:
        team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW)
    assert (info.value.reason, info.value.current, info.value.lease) == ("taken", oid, None)
    assert _ref(repo, "docs") == oid


# ── claim: validation ────────────────────────────────────────────────────────

@pytest.mark.parametrize("kwargs, message", [
    ({"lane": "Docs"}, r"\Ainvalid lane name: 'Docs'"),
    ({"paths": []}, r"\Apaths: give at least one glob\Z"),
    ({"paths": "docs/**"}, r"\Apaths: give a list of globs\Z"),
    ({"paths": {"docs/**"}}, r"\Apaths: give a list of globs\Z"),
    ({"paths": None}, r"\Apaths: give a list of globs\Z"),
    ({"paths": [""]}, r"\Apaths: glob 1 is empty\Z"),
    ({"paths": ["/"]}, r"\Apaths: glob 1 is empty\Z"),
    ({"paths": ["docs/**", "a/../b"]}, r"\Apaths: glob 2 climbs out of the workspace with '\.\.'\Z"),
    ({"paths": ["a\x1bb"]}, r"\Apaths: glob 1 has a control character\Z"),
    ({"paths": [7]}, r"\Apaths: glob 1 is not text\Z"),
    ({"ttl_s": 0}, r"\Attl must be a whole number of seconds from 1 to 86400\Z"),
    ({"ttl_s": 86401}, r"\Attl must be a whole number of seconds from 1 to 86400\Z"),
    ({"ttl_s": True}, r"\Attl must be a whole number of seconds from 1 to 86400\Z"),
    ({"ttl_s": 1.5}, r"\Attl must be a whole number of seconds from 1 to 86400\Z"),
    ({"owner": ""}, r"\Aowner must be 1 to 200 characters with no control characters\Z"),
    ({"owner": "a\nb"}, r"\Aowner must be 1 to 200 characters with no control characters\Z"),
    ({"owner": "x" * 201}, r"\Aowner must be 1 to 200 characters with no control characters\Z"),
    ({"role": "\x85"}, r"\Arole must be 1 to 200 characters with no control characters\Z"),
    ({"branch": "lane docs"}, r"\Abranch must be 1 to 200 characters with no spaces or control characters\Z"),
])
def test_invalid_claims_are_refused_before_anything_is_written(repo: Path, kwargs, message):
    args = {"lane": "docs", "paths": ["docs/**"], "owner": "o@h", "now": NOW}
    args.update(kwargs)
    lane, paths = args.pop("lane"), args.pop("paths")
    with pytest.raises(team.TeamUsageError, match=message):
        team.claim(repo, lane, paths, **args)
    assert _refs(repo) == {}
    assert not events.events_path(repo).exists()


def test_labels_of_one_character_and_with_spaces_are_accepted_but_a_branch_has_no_spaces(repo: Path):
    change = team.claim(repo, "docs", ["docs/**"], owner="Nick Seney@desk", role="r", branch="b", now=NOW)
    assert (change.lease.owner, change.lease.role, change.lease.branch) == ("Nick Seney@desk", "r", "b")
    moved = team.transfer(repo, "docs", change.oid, owner="o", role="lead reviewer", now=NOW)
    assert (moved.lease.owner, moved.lease.role) == ("o", "lead reviewer")
    with pytest.raises(team.TeamUsageError, match=r"\Abranch must be"):
        team.claim(repo, "web", ["web/**"], owner="o@h", branch="lane web", now=NOW)


def test_the_longest_ttl_and_label_are_accepted(repo: Path):
    change = team.claim(repo, "docs", ["docs/**"], owner="x" * 200, ttl_s=86400, now=NOW)
    assert (change.lease.ttl_s, len(change.lease.owner)) == (86400, 200)


def test_the_shortest_ttl_is_one_second(repo: Path):
    change = team.claim(repo, "docs", ["docs/**"], owner="o@h", ttl_s=1, now=NOW)
    assert change.lease.ttl_s == 1
    assert team.renew(repo, "docs", change.oid, ttl_s=1, now=NOW).lease.ttl_s == 1


def test_a_claim_outside_a_git_repository_is_a_usage_error(tmp_path: Path):
    with pytest.raises(team.TeamUsageError, match=r"\Anot in a git repository: aegis team keeps leases in git refs\Z"):
        team.claim(tmp_path, "docs", ["docs/**"], owner="o@h", now=NOW)


# ── claim: lost acknowledgements and lost races ─────────────────────────────

def test_a_claim_whose_acknowledgement_was_lost_succeeds(repo: Path, monkeypatch):
    real = gitsafe.update_ref

    def landed_then_timed_out(cwd, ref, new, old):
        real(cwd, ref, new, old)
        raise gitsafe.GitError("git update-ref timed out after 10s")

    monkeypatch.setattr(gitsafe, "update_ref", landed_then_timed_out)
    change = team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW)
    assert change.action == "claimed"
    assert _ref(repo, "docs") == change.oid
    assert len(_events(repo, "lease_claimed")) == 1


def test_a_conflict_naming_my_own_oid_is_success(repo: Path, monkeypatch):
    real = gitsafe.update_ref

    def landed_then_conflict(cwd, ref, new, old):
        real(cwd, ref, new, old)
        raise gitsafe.RefConflict("lost ack", ref=ref, expected=old, current=new)

    monkeypatch.setattr(gitsafe, "update_ref", landed_then_conflict)
    assert team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW).oid == _ref(repo, "docs")


def test_a_write_that_never_landed_is_an_error_not_a_claim(repo: Path, monkeypatch):
    def failed(cwd, ref, new, old):
        raise gitsafe.GitError("git update-ref failed 5 times")

    monkeypatch.setattr(gitsafe, "update_ref", failed)
    with pytest.raises(gitsafe.GitError, match="failed 5 times"):
        team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW)
    assert _ref(repo, "docs") is None
    assert _events(repo, "lease_claimed") == []


def test_losing_the_create_race_is_taken_with_the_winner_lease(repo: Path, monkeypatch):
    real = gitsafe.update_ref
    winner = []

    def another_claimer_first(cwd, ref, new, old):
        monkeypatch.setattr(gitsafe, "update_ref", real)
        winner.append(team.claim(repo, "docs", ["docs/**"], owner="winner@h", now=NOW))
        return real(cwd, ref, new, old)

    monkeypatch.setattr(gitsafe, "update_ref", another_claimer_first)
    with pytest.raises(team.LeaseRefused) as info:
        team.claim(repo, "docs", ["docs/**"], owner="loser@h", now=NOW)
    assert (info.value.reason, info.value.current) == ("taken", winner[0].oid)
    assert info.value.lease.owner == "winner@h"
    assert _ref(repo, "docs") == winner[0].oid


def test_a_lease_that_vanished_before_the_takeover_is_claimed_afresh(repo: Path, monkeypatch):
    old = team.claim(repo, "docs", ["docs/**"], owner="old@h", ttl_s=60, now=NOW)
    real = gitsafe.update_ref

    def collected_meanwhile(cwd, ref, new, old_value):
        monkeypatch.setattr(gitsafe, "update_ref", real)
        real(cwd, ref, None, old.oid)  # another process's gc
        return real(cwd, ref, new, old_value)

    monkeypatch.setattr(gitsafe, "update_ref", collected_meanwhile)
    change = team.claim(repo, "docs", ["docs/**"], owner="new@h", now=NOW + 100)
    assert (change.action, change.previous, change.lease.gen) == ("claimed", None, 1)
    assert _ref(repo, "docs") == change.oid


# ── renew ────────────────────────────────────────────────────────────────────

def test_renewing_a_live_lease_is_a_plain_cas_keeping_the_claim(repo: Path):
    old = team.claim(repo, "docs", ["docs/**"], owner="o@h", role="writer", ttl_s=600, now=NOW)
    new = team.renew(repo, "docs", old.oid, now=NOW + 100)
    assert (new.action, new.previous) == ("renewed", old.oid)
    assert _ref(repo, "docs") == new.oid
    assert new.lease == team.Lease(lane="docs", role="writer", owner="o@h", claim_id=old.lease.claim_id, gen=2,
                                   branch=None, paths=("docs/**",), ts=NOW + 100, ttl_s=600, oid=new.oid)
    assert team.renew(repo, "docs", new.oid, ttl_s=1200, now=NOW + 200).lease.ttl_s == 1200
    assert _events(repo, "lease_claimed")[1]["result"] == "renewed"


def test_renew_with_a_stale_expectation_is_refused(repo: Path):
    old = team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW)
    new = team.renew(repo, "docs", old.oid, now=NOW + 1)
    with pytest.raises(team.LeaseRefused) as info:
        team.renew(repo, "docs", old.oid, now=NOW + 2)
    assert (info.value.reason, info.value.current) == ("stale", new.oid)
    assert _ref(repo, "docs") == new.oid


def test_renew_without_a_lease_is_refused_as_absent(repo: Path):
    with pytest.raises(team.LeaseRefused) as info:
        team.renew(repo, "docs", "a" * 40, now=NOW)
    assert (info.value.reason, info.value.current) == ("absent", None)


def test_renewing_an_expired_lease_goes_through_the_claim_path(repo: Path):
    old = team.claim(repo, "docs", ["docs/**"], owner="o@h", role="writer", ttl_s=60, now=NOW)
    new = team.renew(repo, "docs", old.oid, now=NOW + 120)
    assert (new.action, new.previous) == ("renewed", old.oid)
    assert new.lease.claim_id != old.lease.claim_id
    assert (new.lease.gen, new.lease.ts, new.lease.ttl_s, new.lease.owner, new.lease.role) == (
        2, NOW + 120, 60, "o@h", "writer")
    assert re.fullmatch(r"[0-9a-f]{16}", new.lease.claim_id)
    assert team.read_leases(repo).get("docs") == new.lease
    assert _events(repo, "lease_claimed")[1]["detail"]["was_expired"] is True


def test_renewing_an_expired_lease_rechecks_overlap(repo: Path):
    old = team.claim(repo, "docs", ["docs/**"], owner="o@h", ttl_s=60, now=NOW)
    team.claim(repo, "api", ["docs/api/**"], owner="o@h", now=NOW + 100)
    with pytest.raises(team.LeaseRefused) as info:
        team.renew(repo, "docs", old.oid, now=NOW + 120)
    assert (info.value.reason, info.value.lanes) == ("overlap", ("api",))
    assert _ref(repo, "docs") == old.oid
    assert _events(repo, "lease_denied")[0]["detail"] == {"reason": "overlap", "lane": "docs", "lanes": ["api"]}


def test_renewing_a_live_lease_needs_no_overlap_check(repo: Path):
    # Overlap is judged when a lease is (re)claimed; a live lease keeps its claim.
    old = team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW)
    _plant(repo, "refs/aegis/lanes/api", json.dumps(_valid_blob(lane="api", paths=["docs/**"])).encode())
    assert team.renew(repo, "docs", old.oid, now=NOW + 1).action == "renewed"


def test_renewing_an_unreadable_lease_is_refused(repo: Path):
    oid = _plant(repo, "refs/aegis/lanes/docs", b"garbage")
    with pytest.raises(team.LeaseRefused) as info:
        team.renew(repo, "docs", oid, now=NOW)
    assert (info.value.reason, info.value.current) == ("unreadable", oid)


def test_every_operation_refuses_an_invalid_lane_name_before_reading(repo: Path):
    for call in (lambda: team.renew(repo, "a/b", "a" * 40, now=NOW),
                 lambda: team.transfer(repo, "a/b", "a" * 40, owner="o@h", now=NOW),
                 lambda: team.release(repo, "a/b", "a" * 40),
                 lambda: team.live_lease(repo, "a/b", now=NOW)):
        with pytest.raises(team.TeamUsageError, match=r"\Ainvalid lane name: 'a/b'"):
            call()


@pytest.mark.parametrize("expect", ["abc", "A" * 40, "", None])
def test_an_expectation_must_be_a_full_object_id(repo: Path, expect):
    for call in (lambda: team.renew(repo, "docs", expect, now=NOW),
                 lambda: team.transfer(repo, "docs", expect, owner="o@h", now=NOW),
                 lambda: team.release(repo, "docs", expect)):
        with pytest.raises(team.TeamUsageError, match=r"\A--expect must be a full object id"):
            call()


def test_renew_refuses_a_ttl_over_the_cap(repo: Path):
    old = team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW)
    with pytest.raises(team.TeamUsageError, match="ttl"):
        team.renew(repo, "docs", old.oid, ttl_s=86401, now=NOW)
    assert _ref(repo, "docs") == old.oid


def test_a_renew_whose_acknowledgement_was_lost_succeeds(repo: Path, monkeypatch):
    old = team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW)
    real = gitsafe.update_ref

    def landed_then_timed_out(cwd, ref, new, expected):
        real(cwd, ref, new, expected)
        raise gitsafe.GitError("timed out")

    monkeypatch.setattr(gitsafe, "update_ref", landed_then_timed_out)
    new = team.renew(repo, "docs", old.oid, now=NOW + 5)
    assert _ref(repo, "docs") == new.oid != old.oid


# ── transfer ─────────────────────────────────────────────────────────────────

def test_transfer_changes_the_owner_and_role_by_cas(repo: Path):
    old = team.claim(repo, "docs", ["docs/**"], owner="a@h", role="implementer", ttl_s=600, now=NOW)
    new = team.transfer(repo, "docs", old.oid, owner="b@h", role="reviewer", now=NOW + 10)
    assert (new.action, new.previous) == ("transferred", old.oid)
    assert new.lease == team.Lease(lane="docs", role="reviewer", owner="b@h", claim_id=old.lease.claim_id, gen=2,
                                   branch=None, paths=("docs/**",), ts=NOW, ttl_s=600, oid=new.oid)
    assert _ref(repo, "docs") == new.oid
    kept = team.transfer(repo, "docs", new.oid, owner="c@h", now=NOW + 20)
    assert (kept.lease.role, kept.lease.gen) == ("reviewer", 3)
    detail = _events(repo, "lease_claimed")[1]["detail"]
    assert (detail["from_owner"], detail["owner"]) == ("a@h", "b@h")


def test_transfer_of_an_expired_lease_is_refused(repo: Path):
    old = team.claim(repo, "docs", ["docs/**"], owner="a@h", ttl_s=60, now=NOW)
    with pytest.raises(team.LeaseRefused) as info:
        team.transfer(repo, "docs", old.oid, owner="b@h", now=NOW + 60)
    assert (info.value.reason, info.value.current) == ("expired", old.oid)
    assert _ref(repo, "docs") == old.oid


def test_transfer_with_a_stale_expectation_or_no_lease_is_refused(repo: Path):
    with pytest.raises(team.LeaseRefused) as info:
        team.transfer(repo, "docs", "b" * 40, owner="b@h", now=NOW)
    assert info.value.reason == "absent"
    old = team.claim(repo, "docs", ["docs/**"], owner="a@h", now=NOW)
    with pytest.raises(team.LeaseRefused) as info:
        team.transfer(repo, "docs", "b" * 40, owner="b@h", now=NOW)
    assert (info.value.reason, info.value.current) == ("stale", old.oid)


def test_transfer_validates_the_new_labels(repo: Path):
    old = team.claim(repo, "docs", ["docs/**"], owner="a@h", now=NOW)
    with pytest.raises(team.TeamUsageError, match=r"\Aowner must be"):
        team.transfer(repo, "docs", old.oid, owner="", now=NOW)
    with pytest.raises(team.TeamUsageError, match=r"\Arole must be"):
        team.transfer(repo, "docs", old.oid, owner="b@h", role="\t", now=NOW)
    assert _ref(repo, "docs") == old.oid


# ── release ──────────────────────────────────────────────────────────────────

def test_anyone_may_release_and_the_event_names_the_caller(repo: Path):
    old = team.claim(repo, "docs", ["docs/**"], owner="agent@box", now=NOW)
    change = team.release(repo, "docs", old.oid, caller="human@desk")
    assert (change.action, change.oid, change.previous, change.caller) == ("released", None, old.oid, "human@desk")
    assert _ref(repo, "docs") is None
    assert _events(repo, "lease_claimed")[-1]["result"] == "released"
    assert _events(repo, "lease_claimed")[-1]["detail"] == {
        "lane": "docs", "oid": None, "previous": old.oid, "caller": "human@desk", "owner": "agent@box"}


def test_release_defaults_the_caller_to_user_at_host(repo: Path, monkeypatch):
    monkeypatch.setenv("LOGNAME", "releaser")
    old = team.claim(repo, "docs", ["docs/**"], owner="agent@box", now=NOW)
    assert team.release(repo, "docs", old.oid).caller == f"releaser@{socket.gethostname()}"


def test_release_with_a_stale_expectation_keeps_the_lease(repo: Path):
    old = team.claim(repo, "docs", ["docs/**"], owner="a@h", now=NOW)
    new = team.renew(repo, "docs", old.oid, now=NOW + 1)
    with pytest.raises(team.LeaseRefused) as info:
        team.release(repo, "docs", old.oid)
    assert (info.value.reason, info.value.current) == ("stale", new.oid)
    assert _ref(repo, "docs") == new.oid


def test_release_without_a_lease_is_absent(repo: Path):
    with pytest.raises(team.LeaseRefused) as info:
        team.release(repo, "docs", "c" * 40)
    assert info.value.reason == "absent"


def test_an_unreadable_lease_can_be_released_by_its_oid(repo: Path):
    oid = _plant(repo, "refs/aegis/lanes/docs", b"garbage")
    change = team.release(repo, "docs", oid, caller="h@d")
    assert _ref(repo, "docs") is None
    assert _events(repo, "lease_claimed")[-1]["detail"]["owner"] is None
    assert change.previous == oid


def test_a_release_whose_acknowledgement_was_lost_succeeds(repo: Path, monkeypatch):
    old = team.claim(repo, "docs", ["docs/**"], owner="a@h", now=NOW)
    real = gitsafe.update_ref

    def landed_then_timed_out(cwd, ref, new, expected):
        real(cwd, ref, new, expected)
        raise gitsafe.RefConflict("lost", ref=ref, expected=expected, current=None)

    monkeypatch.setattr(gitsafe, "update_ref", landed_then_timed_out)
    assert team.release(repo, "docs", old.oid).action == "released"
    assert _ref(repo, "docs") is None


# ── gc ───────────────────────────────────────────────────────────────────────

def test_gc_deletes_only_expired_leases(repo: Path):
    expired = team.claim(repo, "docs", ["docs/**"], owner="a@h", ttl_s=60, now=NOW)
    live = team.claim(repo, "api", ["src/**"], owner="b@h", ttl_s=600, now=NOW + 100)
    junk = _plant(repo, "refs/aegis/lanes/junk", b"garbage")
    result = team.gc(repo, now=NOW + 100, caller="janitor@h")
    assert [(c.action, c.lane, c.previous, c.caller) for c in result.collected] == [
        ("collected", "docs", expired.oid, "janitor@h")]
    assert _refs(repo) == {"refs/aegis/lanes/api": live.oid, "refs/aegis/lanes/junk": junk}
    assert result.kept == (("junk", "unreadable"),)
    assert _events(repo, "lease_claimed")[-1]["detail"] == {
        "lane": "docs", "oid": None, "previous": expired.oid, "caller": "janitor@h", "owner": "a@h"}


def test_gc_leaves_a_lease_that_changed_after_it_was_read(repo: Path, monkeypatch):
    expired = team.claim(repo, "docs", ["docs/**"], owner="a@h", ttl_s=60, now=NOW)
    real = gitsafe.update_ref

    def renewed_meanwhile(cwd, ref, new, old):
        monkeypatch.setattr(gitsafe, "update_ref", real)
        team.renew(repo, "docs", expired.oid, now=NOW + 100)
        return real(cwd, ref, new, old)

    monkeypatch.setattr(gitsafe, "update_ref", renewed_meanwhile)
    result = team.gc(repo, now=NOW + 100, caller="j@h")
    assert result.collected == ()
    assert result.kept == (("docs", "changed after it was read"),)
    assert _ref(repo, "docs") not in (None, expired.oid)


def test_gc_with_nothing_expired_changes_nothing(repo: Path):
    live = team.claim(repo, "docs", ["docs/**"], owner="a@h", now=NOW)
    result = team.gc(repo, now=NOW + 1)
    assert (result.collected, result.kept) == ((), ())
    assert _ref(repo, "docs") == live.oid


# ── reading and describing ───────────────────────────────────────────────────

@pytest.mark.parametrize("changes", [
    {"extra": 1}, {"v": 2}, {"lane": "api"}, {"role": ""}, {"owner": 1}, {"claim_id": "0123456789ABCDEF"},
    {"claim_id": "0123456789abcde"}, {"gen": 0}, {"gen": True}, {"branch": 5}, {"branch": ""},
    {"paths": []}, {"paths": [""]}, {"paths": "docs/**"}, {"ts": -1}, {"ts": 1.5}, {"ttl_s": 0},
    {"ttl_s": 86401}, {"ttl_s": True},
])
def test_parse_lease_is_strict(changes):
    good = json.dumps(_valid_blob()).encode()
    assert team.parse_lease(good, "docs", "a" * 40).gen == 1
    with pytest.raises(team.LeaseFormatError):
        team.parse_lease(json.dumps(_valid_blob(**changes)).encode(), "docs", "a" * 40)


@pytest.mark.parametrize("changes", [
    {"ts": 0}, {"ts": 253402300799 - 86400}, {"ttl_s": 1}, {"ttl_s": 86400}, {"gen": 1}, {"gen": 2 ** 53},
    {"branch": "lane/docs"}, {"role": "r" * 200}, {"paths": ["docs/**", "README.md"]},
])
def test_parse_lease_accepts_its_boundaries(changes):
    lease = team.parse_lease(json.dumps(_valid_blob(**changes)).encode(), "docs", "b" * 64)
    for key, value in changes.items():
        assert getattr(lease, key) == (tuple(value) if key == "paths" else value)
    assert lease.oid == "b" * 64


@pytest.mark.parametrize("changes", [{"ts": 253402300799 - 86400 + 1}, {"gen": 2 ** 53 + 1}, {"role": "r" * 201}])
def test_parse_lease_refuses_past_its_boundaries(changes):
    with pytest.raises(team.LeaseFormatError):
        team.parse_lease(json.dumps(_valid_blob(**changes)).encode(), "docs", "b" * 64)


@pytest.mark.parametrize("data", [b"\xff", b"{", b"[]", b'"x"'])
def test_parse_lease_refuses_what_is_not_a_json_object(data: bytes):
    with pytest.raises(team.LeaseFormatError):
        team.parse_lease(data, "docs", "a" * 40)


def test_parse_lease_refuses_a_missing_key():
    blob = _valid_blob()
    del blob["branch"]
    with pytest.raises(team.LeaseFormatError, match="keys"):
        team.parse_lease(json.dumps(blob).encode(), "docs", "a" * 40)


def test_read_leases_separates_readable_from_unreadable_by_lane(repo: Path):
    good = team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW)
    wrong_lane = _plant(repo, "refs/aegis/lanes/api", json.dumps(_valid_blob()).encode())
    nested = _plant(repo, "refs/aegis/lanes/x/y", json.dumps(_valid_blob(lane="x/y")).encode())
    found = team.read_leases(repo)
    assert found.leases == (good.lease,)
    assert [(u.lane, u.oid) for u in found.unreadable] == [("api", wrong_lane), ("x/y", nested)]
    assert found.unreadable[0].error == "the blob names a different lane"
    assert found.unreadable[1].error == "not a lane name"
    assert found.get("docs") == good.lease and found.get("api") is None


def test_an_oversized_lease_blob_is_unreadable_without_being_read(repo: Path):
    big = json.dumps(_valid_blob(owner="o" * 10, paths=["d/" + "x" * 70_000])).encode()
    oid = _plant(repo, "refs/aegis/lanes/docs", big)
    found = team.read_leases(repo)
    assert [(u.lane, u.oid) for u in found.unreadable] == [("docs", oid)]
    assert "cap" in found.unreadable[0].error


def test_live_lease_answers_only_a_readable_unexpired_lease(repo: Path):
    team.claim(repo, "docs", ["docs/**"], owner="o@h", ttl_s=60, now=NOW)
    assert team.live_lease(repo, "docs", now=NOW + 59).owner == "o@h"
    assert team.live_lease(repo, "docs", now=NOW + 60) is None
    assert team.live_lease(repo, "api", now=NOW) is None
    with pytest.raises(team.TeamUsageError, match=r"\Ainvalid lane name: 'Docs'"):
        team.live_lease(repo, "Docs", now=NOW)


def test_describe_lists_every_plan_field_and_overlaps_with_live_lanes(repo: Path):
    team.claim(repo, "old", ["docs/old/**"], owner="b@h", ttl_s=60, now=NOW - 1000)  # expired by NOW
    docs = team.claim(repo, "docs", ["docs/**"], owner="a@h", role="writer", ttl_s=600, branch="lane/docs", now=NOW)
    team.claim(repo, "web", ["web/**"], owner="c@h", now=NOW)
    _plant(repo, "refs/aegis/lanes/zzz", b"garbage")
    view = team.describe(repo, now=NOW + 5)
    leases = {entry["lane"]: entry for entry in view["leases"]}
    assert [entry["lane"] for entry in view["leases"]] == ["docs", "old", "web"]
    assert all(list(entry) == VIEW_KEYS for entry in view["leases"])
    assert leases["docs"] == {
        "lane": "docs", "role": "writer", "owner": "a@h", "claim_id": docs.lease.claim_id, "gen": 1,
        "oid": docs.oid, "branch": "lane/docs", "paths": ["docs/**"],
        "expires_at": datetime.fromtimestamp(NOW + 600, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "clock_basis": {"clock": "writer_utc", "ts": NOW, "ttl_s": 600},
        "expired": False, "clock_skew": False, "overlaps": [],
    }
    # The expired lane overlaps live docs; nobody overlaps the expired one.
    assert (leases["old"]["expired"], leases["old"]["overlaps"]) == (True, ["docs"])
    assert leases["web"]["overlaps"] == []
    assert view["unreadable"] == [{"lane": "zzz", "ref": "refs/aegis/lanes/zzz", "oid": _ref(repo, "zzz"),
                                   "error": view["unreadable"][0]["error"]}]


def test_two_live_overlapping_leases_name_each_other(repo: Path):
    _plant(repo, "refs/aegis/lanes/api", json.dumps(_valid_blob(lane="api", paths=["src/**"])).encode())
    _plant(repo, "refs/aegis/lanes/core", json.dumps(_valid_blob(lane="core", paths=["src/core/**"])).encode())
    view = {e["lane"]: e["overlaps"] for e in team.describe(repo, now=NOW)["leases"]}
    assert view == {"api": ["core"], "core": ["api"]}


@pytest.mark.parametrize("ahead, skewed", [(300, False), (301, True)])
def test_clock_skew_flags_a_writer_more_than_300_seconds_ahead_and_the_lease_stays_live(repo: Path, ahead, skewed):
    team.claim(repo, "docs", ["docs/**"], owner="o@h", ttl_s=60, now=NOW + ahead)
    entry = team.describe(repo, now=NOW)["leases"][0]
    assert (entry["clock_skew"], entry["expired"]) == (skewed, False)


@pytest.mark.parametrize("elapsed, expired", [(59, False), (60, True)])
def test_a_lease_expires_at_ts_plus_ttl(repo: Path, elapsed, expired):
    team.claim(repo, "docs", ["docs/**"], owner="o@h", ttl_s=60, now=NOW)
    assert team.describe(repo, now=NOW + elapsed)["leases"][0]["expired"] is expired


def test_describing_is_side_effect_free(repo: Path):
    claimed = team.claim(repo, "docs", ["docs/**"], owner="o@h", ttl_s=60, now=NOW)
    shared = Path(os.path.realpath(repo / ".git")) / "aegis"
    shutil.rmtree(str(shared))
    before = _refs(repo)
    team.describe(repo, now=NOW + 1000)
    team.read_leases(repo)
    assert _refs(repo) == before == {"refs/aegis/lanes/docs": claimed.oid}
    assert not shared.exists()


# ── events never fail an operation ───────────────────────────────────────────

def test_an_event_that_cannot_be_recorded_is_a_warning_not_a_failure(repo: Path, tmp_path: Path):
    shared = Path(os.path.realpath(repo / ".git")) / "aegis"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    try:
        os.symlink(str(elsewhere), str(shared), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    change = team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW)
    assert _ref(repo, "docs") == change.oid
    assert len(change.warnings) == 1 and change.warnings[0].startswith("event not recorded: ")
    assert list(elsewhere.iterdir()) == []


# ── racing claims from two worktrees ─────────────────────────────────────────

def _race(repo: Path, other: Path, lane: str, racers: int = 6) -> List[tuple]:
    ctx = multiprocessing.get_context("spawn")
    barrier = ctx.Barrier(racers)
    results = ctx.Queue()
    procs = [
        ctx.Process(target=helpers_teamrace.claim,
                    args=(str(repo if i % 2 else other), lane, ["docs/**"], f"racer{i}@h", barrier, results))
        for i in range(racers)
    ]
    for proc in procs:
        proc.start()
    try:
        return [results.get(timeout=120) for _ in procs]
    except queue.Empty:
        pytest.fail("a racer never reported")
    finally:
        for proc in procs:
            proc.join(timeout=60)
            if proc.is_alive():
                proc.terminate()


@pytest.fixture
def worktree(repo: Path, tmp_path: Path) -> Path:
    other = tmp_path / "other"
    _git(repo, "worktree", "add", "-q", "-b", "lane/other", str(other))
    return other


def test_racing_claims_from_two_worktrees_have_exactly_one_winner(repo: Path, worktree: Path):
    outcomes = _race(repo, worktree, "docs")
    assert [o for o in outcomes if o[1] == "error"] == []
    winners = [o for o in outcomes if o[1] == "claimed"]
    assert len(winners) == 1, outcomes
    assert sorted(o[1] for o in outcomes if o is not winners[0]) == ["refused:taken"] * 5
    assert all(o[2] == winners[0][2] for o in outcomes)
    assert _ref(repo, "docs") == winners[0][2] == team.read_leases(worktree).get("docs").oid
    assert team.read_leases(repo).get("docs").owner == winners[0][0]
    assert len(_events(worktree, "lease_claimed")) == 1
    assert [r["detail"]["reason"] for r in _events(repo, "lease_denied")] == ["taken"] * 5


def test_racing_takeovers_of_an_expired_lease_have_exactly_one_winner(repo: Path, worktree: Path):
    old = team.claim(repo, "docs", ["docs/**"], owner="old@h", ttl_s=60, now=int(time.time()) - 7200)
    outcomes = _race(repo, worktree, "docs")
    assert [o for o in outcomes if o[1] == "error"] == []
    winners = [o for o in outcomes if o[1] == "taken_over"]
    assert len(winners) == 1, outcomes
    assert sorted(o[1] for o in outcomes if o is not winners[0]) == ["refused:taken"] * 5
    lease = team.read_leases(repo).get("docs")
    assert (lease.oid, lease.gen, lease.owner) == (winners[0][2], 2, winners[0][0])
    assert lease.claim_id != old.lease.claim_id


def test_refusals_and_file_errors_survive_pickling(repo: Path):
    import pickle

    first = team.claim(repo, "docs", ["docs/**"], owner="o@h", now=NOW)
    with pytest.raises(team.LeaseRefused) as info:
        team.claim(repo, "docs", ["docs/**"], owner="p@h", now=NOW)
    copy = pickle.loads(pickle.dumps(info.value))
    assert (str(copy), copy.reason, copy.lane, copy.current, copy.lease, copy.lanes) == (
        str(info.value), "taken", "docs", first.oid, first.lease, ())
    error = pickle.loads(pickle.dumps(team.TeamFileError("v must be 1")))
    assert (type(error), str(error)) == (team.TeamFileError, "team.json: v must be 1")


# ── branch bytes: one predicate for lease and queue claims ──────────────────

BRANCH_REASON = "branch must be 1 to 200 characters with no spaces or control characters"
_SURROGATE_BYTES = b"feature/\xffmarker".decode("utf-8", "surrogateescape")
_BRANCH_MATRIX = [
    ("feature/bytes", True),
    ("feature/\u00fc", True),
    ("feature/\ud800marker", False),
    (_SURROGATE_BYTES, False),
    ("", False),
    ("x" * 201, False),
    ("feature/a\nb", False),
]
_BRANCH_IDS = ["ascii", "utf8", "lone-surrogate", "surrogateescape", "empty", "over-length", "embedded-newline"]


def _forbid_git_write(monkeypatch):
    """Block lease writes. Restore only these two module attributes afterwards.

    ``monkeypatch.undo()`` would also drop autouse patches this test does not own.
    """
    def forbid(*_args, **_kwargs):
        raise AssertionError("branch validation reached a git write")

    originals = (gitsafe.write_blob, gitsafe.update_ref)
    monkeypatch.setattr(gitsafe, "write_blob", forbid)
    monkeypatch.setattr(gitsafe, "update_ref", forbid)
    return originals


def _restore_git_write(monkeypatch, originals) -> None:
    write_blob, update_ref = originals
    monkeypatch.setattr(gitsafe, "write_blob", write_blob)
    monkeypatch.setattr(gitsafe, "update_ref", update_ref)


def _queue_workspace(repo: Path, tmp_path: Path) -> Path:
    if not team_queue.descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    (repo / ".aegis").mkdir(exist_ok=True)
    (repo / ".aegis" / "team.json").write_text(
        json.dumps({"v": 1, "lanes": {"docs": ["docs/**"]}}), encoding="utf-8")
    home = tmp_path / "queue-home"
    home.mkdir(exist_ok=True)
    # Restored by the repository's autouse environment-isolation fixture.
    os.environ.update({"HOME": str(home), "USERPROFILE": str(home)})
    return repo


def _queue_item() -> dict:
    return {"id": "ONE", "title": "Queue work", "paths": ["docs/**"], "capabilities": ["core"]}


def _add_queue_item(root: Path):
    added = team_queue.add(root, _queue_item(), now=NOW, caller="owner")
    assert added["refused"] is False, added
    return added["item"]["revision"]


@pytest.mark.parametrize("branch,accepted", _BRANCH_MATRIX, ids=_BRANCH_IDS)
def test_claim_branch_matrix_refuses_undecodable_names_before_write(repo: Path, monkeypatch, branch, accepted):
    """Lease claims accept only a bounded UTF-8 branch; retry after a refusal still claims."""
    if accepted:
        change = team.claim(repo, "docs", ["docs/**"], owner="o@h", branch=branch, now=NOW)
        assert change.lease.branch == branch
        raw = subprocess.run(["git", "cat-file", "blob", change.oid], cwd=str(repo),
                             capture_output=True, check=True).stdout
        assert branch.encode("utf-8") in raw
        assert team.read_leases(repo).get("docs").branch == branch
        return
    originals = _forbid_git_write(monkeypatch)
    with pytest.raises(team.TeamUsageError) as caught:
        team.claim(repo, "docs", ["docs/**"], owner="o@h", branch=branch, now=NOW)
    assert str(caught.value) == BRANCH_REASON
    assert _refs(repo) == {}
    assert not events.events_path(repo).exists()
    _restore_git_write(monkeypatch, originals)
    retried = team.claim(repo, "docs", ["docs/**"], owner="o@h", branch="feature/retry", now=NOW)
    assert retried.lease.branch == "feature/retry"
    assert _ref(repo, "docs") == retried.oid


def test_undecodable_branch_refusal_does_not_disturb_a_concurrent_claim(repo: Path):
    """A refused branch never enters the claim loop, so a concurrent valid claim is unchanged."""
    import threading

    start = threading.Barrier(2)
    done = []
    errors = []

    def valid():
        start.wait(timeout=10)
        try:
            done.append(team.claim(repo, "docs", ["docs/**"], owner="o@h", branch="feature/ok", now=NOW))
        except Exception as exc:
            errors.append(exc)

    def invalid():
        start.wait(timeout=10)
        try:
            team.claim(repo, "web", ["web/**"], owner="o@h", branch="feature/\ud800marker", now=NOW)
        except team.TeamUsageError as exc:
            done.append(exc)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=valid), threading.Thread(target=invalid)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive()
    assert errors == []
    refused = [item for item in done if isinstance(item, team.TeamUsageError)]
    claimed = [item for item in done if isinstance(item, team.LeaseChange)]
    assert [str(item) for item in refused] == [BRANCH_REASON]
    assert [item.lease.branch for item in claimed] == ["feature/ok"]
    assert team.read_leases(repo).get("web") is None
    assert team.read_leases(repo).get("docs").branch == "feature/ok"


@pytest.mark.parametrize("branch,accepted", _BRANCH_MATRIX, ids=_BRANCH_IDS)
def test_queue_claim_branch_matrix_uses_the_shared_predicate(repo: Path, tmp_path: Path, branch, accepted):
    """Queue claims call the same predicate and refuse before the queue file changes."""
    if not team_queue.descriptor_supported():
        if accepted:
            pytest.skip("requires descriptor-relative nofollow operations")
        result = team_queue.claim(tmp_path, "ONE", expect="0" * 64, lane="docs", capabilities=[],
                                  branch=branch, now=NOW, caller="owner")
        assert result["reason"] == "invalid_arguments" and result["exit_code"] == 2
        assert result["next_action"] == "Use the documented queue arguments and the revision returned by list."
        assert "marker" not in json.dumps(result)
        assert list(tmp_path.iterdir()) == []
        return
    root = _queue_workspace(repo, tmp_path)
    revision = _add_queue_item(root)
    path = root / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    if accepted:
        team.claim(root, "docs", ["docs/**"], owner="owner", branch=branch, now=NOW)
        result = team_queue.claim(root, "ONE", expect=revision, lane="docs", capabilities=["core"],
                                  ttl_s=60, branch=branch, now=NOW + 1, caller="owner")
        assert result["refused"] is False, result
        assert result["item"]["branch"] == branch
        audited = team_queue.audit(root, now=NOW + 2)
        assert audited["refused"] is False, audited
        assert audited["findings"] == []
        assert audited["items"][0]["branch"] == branch
        return
    result = team_queue.claim(root, "ONE", expect=revision, lane="docs", capabilities=["core"],
                              ttl_s=60, branch=branch, now=NOW + 1, caller="owner")
    assert result["refused"] is True and result["reason"] == "invalid_arguments" and result["exit_code"] == 2
    assert result["next_action"] == "Use the documented queue arguments and the revision returned by list."
    assert "marker" not in json.dumps(result)
    assert path.read_bytes() == before
    retried = team_queue.claim(root, "ONE", expect=revision, lane="docs", capabilities=["core"],
                               ttl_s=60, branch="feature/retry", now=NOW + 1, caller="owner")
    assert retried["refused"] is False, retried
    assert retried["item"]["branch"] == "feature/retry"


def test_undecodable_queue_branch_refuses_before_the_platform_probe(tmp_path: Path, monkeypatch):
    """The shared predicate refuses before descriptor checks, including when the probe is off."""
    monkeypatch.setattr(team_queue, "descriptor_supported", lambda: False)

    def forbid(*_args, **_kwargs):
        raise AssertionError("platform probe was not the first refusal")

    monkeypatch.setattr(storage_confined, "confined_file", forbid)
    result = team_queue.claim(tmp_path, "ONE", expect="0" * 64, lane="docs", capabilities=[],
                              branch="feature/\ud800marker", now=NOW, caller="owner")
    assert result["reason"] == "invalid_arguments" and result["exit_code"] == 2
    assert "marker" not in json.dumps(result)
    assert list(tmp_path.iterdir()) == []


def test_queue_undecodable_branch_does_not_disturb_a_concurrent_claim(repo: Path, tmp_path: Path):
    import threading

    root = _queue_workspace(repo, tmp_path)
    revision = _add_queue_item(root)
    start = threading.Barrier(2)
    done = []
    errors = []

    def valid():
        start.wait(timeout=10)
        try:
            done.append(team_queue.claim(root, "ONE", expect=revision, lane="docs", capabilities=["core"],
                                        ttl_s=60, branch="feature/ok", now=NOW + 1, caller="owner"))
        except Exception as exc:
            errors.append(exc)

    def invalid():
        start.wait(timeout=10)
        try:
            done.append(team_queue.claim(root, "ONE", expect=revision, lane="docs", capabilities=["core"],
                                        ttl_s=60, branch=_SURROGATE_BYTES, now=NOW + 1, caller="owner"))
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=valid), threading.Thread(target=invalid)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
        assert not thread.is_alive()
    assert errors == []
    good = [item for item in done if item["refused"] is False]
    bad = [item for item in done if item["refused"] is True]
    assert len(good) == 1 and good[0]["item"]["branch"] == "feature/ok"
    assert [item["reason"] for item in bad] == ["invalid_arguments"]
    assert [item["exit_code"] for item in bad] == [2]
    assert "marker" not in json.dumps(bad)
    listed = team_queue.list(root, now=NOW + 2)
    assert listed["items"][0]["branch"] == "feature/ok"


@pytest.mark.parametrize("branch", ["feature/\ud800marker", _SURROGATE_BYTES], ids=["lone-surrogate", "surrogateescape"])
def test_stored_queue_branch_stays_unsupported_and_audit_does_not_crash(repo: Path, tmp_path: Path, branch):
    """A legacy stored value is an item finding, not a crash and not a rewritten branch."""
    root = _queue_workspace(repo, tmp_path)
    revision = _add_queue_item(root)
    claimed = team_queue.claim(root, "ONE", expect=revision, lane="docs", capabilities=["core"],
                               ttl_s=60, branch="feature/ok", now=NOW + 1, caller="owner")
    assert claimed["refused"] is False, claimed
    team.claim(root, "docs", ["docs/**"], owner="owner", branch="lane/docs", now=NOW)
    path = root / ".aegis" / "state" / "team-queue.json"
    state = json.loads(path.read_text(encoding="utf-8"))
    state["items"]["ONE"]["branch"] = branch
    planted = json.dumps(state, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    path.write_bytes(planted)
    listed = team_queue.list(root, now=NOW + 2)
    audited = team_queue.audit(root, now=NOW + 2)
    assert listed["refused"] is False and audited["refused"] is False
    row = listed["items"][0]
    assert row["branch"] == branch and row["branch_supported"] is False
    assert [item["code"] for item in audited["findings"]] == ["CLAIM-BRANCH-UNSUPPORTED"]
    assert "marker" not in json.dumps(audited["findings"])
    assert path.read_bytes() == planted
    again = team_queue.audit(root, now=NOW + 3)
    assert again["findings"][0]["code"] == "CLAIM-BRANCH-UNSUPPORTED"
    assert path.read_bytes() == planted
    released = team_queue.release(root, "ONE", expect=claimed["item"]["revision"], lane="docs",
                                  now=NOW + 4, caller="owner")
    assert released["refused"] is False, released
    assert team_queue.audit(root, now=NOW + 5)["findings"] == []


def test_surrogateescape_branch_is_the_posix_fsencode_argv_bytes():
    """The invalid-byte fixture is the string POSIX argv would deliver for those bytes."""
    if os.name != "posix":
        pytest.skip("Windows argv cannot carry surrogate-escaped non-UTF-8 bytes")
    raw = b"feature/\xffmarker"
    assert os.fsdecode(raw) == _SURROGATE_BYTES
    assert os.fsencode(_SURROGATE_BYTES) == raw


@pytest.mark.parametrize("branch", ["feature/\ud800marker", _SURROGATE_BYTES], ids=["lone-surrogate", "surrogateescape"])
def test_stored_lease_surrogate_branch_is_unreadable_and_renew_does_not_crash(repo: Path, branch):
    """A legacy lease blob with an undecodable branch is unreadable; list and renew do not encode it."""
    blob = _valid_blob(branch=branch)
    raw = (json.dumps(blob, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
    oid = _plant(repo, "refs/aegis/lanes/docs", raw)
    view = team.describe(repo, now=NOW)
    assert view["leases"] == []
    assert view["unreadable"][0]["lane"] == "docs"
    assert view["unreadable"][0]["oid"] == oid
    assert "marker" not in view["unreadable"][0]["error"]
    report = team_status.status(repo, NOW)
    assert "marker" not in json.dumps(report)
    with pytest.raises(team.LeaseRefused) as caught:
        team.renew(repo, "docs", oid, now=NOW)
    assert caught.value.reason == "unreadable"
    assert _ref(repo, "docs") == oid


@pytest.fixture
def lease_now():
    return int(time.time())


@pytest.fixture
def lease_cli(repo, capsys):
    from aegis_cli.cli import main

    (repo / ".aegis" / "rules").mkdir(parents=True)

    def invoke(*args, as_json=True):
        code = main(["--workspace", str(repo), "team", *args, *(["--json"] if as_json else [])])
        captured = capsys.readouterr()
        return code, json.loads(captured.out) if as_json else captured.out, captured.err

    return invoke


@pytest.mark.parametrize("branch", [None, "lane/docs", "refs/heads/lane/docs", "refs/remotes/origin/docs"])
def test_cli_liveness_renew_accepts_existing_branch_without_worktree(repo, lease_cli, lease_now, branch):
    if branch is not None:
        ref = branch if branch.startswith("refs/") else "refs/heads/" + branch
        _git(repo, "update-ref", ref, "HEAD")
    old = team.claim(repo, "docs", ["docs/**"], branch=branch, owner="o@h", now=lease_now)
    code, payload, err = lease_cli("renew", "docs", "--expect", old.oid)
    assert (code, payload["status"], err) == (0, "renewed", "")
    assert _ref(repo, "docs") == payload["oid"] != old.oid


@pytest.mark.parametrize("age", [0, 120])
@pytest.mark.parametrize("as_json", [False, True])
def test_cli_liveness_missing_branch_refuses_without_echo_and_retries(repo, lease_cli, lease_now, age, as_json):
    branch = "token=private-value"
    _git(repo, "branch", branch)
    old = team.claim(repo, "docs", ["docs/**"], branch=branch, owner="o@h", ttl_s=60, now=lease_now - 100 + age)
    _git(repo, "branch", "-D", branch)
    for _ in range(2):
        code, output, err = lease_cli("renew", "docs", "--expect", old.oid, as_json=as_json)
        assert code == 1
        if as_json:
            assert (output["status"], output["reason"], output["message"], err) == (
                "refused", "lease_branch_missing", "lease_branch_missing", "")
            assert output["next_action"] == "Restore the recorded branch, then retry."
        else:
            assert (output, err) == ("", "lease_branch_missing\nRestore the recorded branch, then retry.\n")
        assert "private-value" not in json.dumps(output) + err
        assert _ref(repo, "docs") == old.oid
    _git(repo, "branch", branch)
    code, payload, _ = lease_cli("renew", "docs", "--expect", old.oid)
    assert (code, payload["status"]) == (0, "renewed")


@pytest.mark.parametrize("action", ["renew", "gc"])
@pytest.mark.parametrize("failure", ["timeout", "nonzero", "oversize", "lease_read"])
def test_cli_liveness_unavailable_evidence_refuses_without_writes_and_retries(
        repo, lease_cli, lease_now, monkeypatch, action, failure):
    _git(repo, "branch", "lane/docs")
    old = team.claim(repo, "docs", ["docs/**"], branch="lane/docs", owner="o@h", ttl_s=60, now=lease_now - 100)
    real_run, real_read = gitsafe.run, gitsafe.read_object

    def failed_run(args, cwd, **kwargs):
        probe = args[0] == "worktree" or any(arg.startswith("refs/heads/") for arg in args)
        if probe:
            if failure == "timeout":
                raise gitsafe.GitError("token=private-value", code="git_timeout")
            return subprocess.CompletedProcess(args, 128 if failure == "nonzero" else 0,
                                               b"x" * (team.MAX_LEASE_BYTES + 1), b"token=private-value")
        return real_run(args, cwd, **kwargs)

    def failed_read(*args, **kwargs):
        raise gitsafe.GitError("token=private-value", code="git_failed")

    args = ("renew", "docs", "--expect", old.oid) if action == "renew" else ("gc",)
    before = _events(repo, "lease_claimed")
    if failure == "lease_read":
        monkeypatch.setattr(gitsafe, "read_object", failed_read)
    else:
        monkeypatch.setattr(gitsafe, "run", failed_run)
    for _ in range(2):
        code, payload, err = lease_cli(*args)
        assert (code, payload["status"], payload["reason"], payload["message"], err) == (
            1, "refused", "liveness_unknown", "liveness_unknown", "")
        assert "private-value" not in json.dumps(payload)
        assert _ref(repo, "docs") == old.oid
    monkeypatch.setattr(gitsafe, "read_object", real_read)
    monkeypatch.setattr(gitsafe, "run", real_run)
    assert _events(repo, "lease_claimed") == before
    assert lease_cli(*args)[0] == 0


@pytest.mark.parametrize("branch", ["lane/other", "refs/heads/lane/other"])
def test_cli_liveness_gc_collects_expired_with_worktree_warning_and_retry(repo, worktree, lease_cli, lease_now, branch):
    old = team.claim(repo, "docs", ["docs/**"], branch=branch, owner="o@h", ttl_s=60, now=lease_now - 100)
    live = team.claim(repo, "api", ["src/**"], branch="main", owner="o@h", ttl_s=600, now=lease_now)
    code, payload, err = lease_cli("gc")
    assert (code, payload["status"], err) == (0, "collected", "")
    assert [(row["lane"], row["previous"]) for row in payload["collected"]] == [("docs", old.oid)]
    assert payload["warnings"] == []
    assert payload["lane_warnings"] == [{"lane": "docs", "reason": "expired_with_worktree"}]
    assert _ref(repo, "docs") is None and _ref(repo, "api") == live.oid
    assert worktree.is_dir()
    code, payload, err = lease_cli("gc")
    assert (code, payload["collected"], payload["warnings"], err) == (0, [], [], "")
    assert payload["lane_warnings"] == []


@pytest.mark.parametrize("branch", [None, "missing", "main"])
def test_cli_liveness_gc_expiry_is_independent_of_branch_and_worktree(repo, lease_cli, lease_now, branch):
    old = team.claim(repo, "docs", ["docs/**"], branch=branch, owner="o@h", ttl_s=60, now=lease_now - 100)
    code, payload, err = lease_cli("gc")
    assert (code, payload["collected"][0]["previous"], err) == (0, old.oid, "")
    assert payload["warnings"] == []
    assert payload["lane_warnings"] == ([{"lane": "docs", "reason": "expired_with_worktree"}] if branch == "main" else [])


def test_cli_liveness_gc_text_warns_without_retaining_expired_lease(repo, worktree, lease_cli, lease_now):
    team.claim(repo, "docs", ["docs/**"], branch="lane/other", owner="o@h", ttl_s=60, now=lease_now - 100)
    code, out, err = lease_cli("gc", as_json=False)
    assert (code, out, err) == (0, "collected docs\n", "Warning: docs: expired_with_worktree\n")
    assert _ref(repo, "docs") is None


def test_cli_liveness_renew_preserves_stale_cas_during_preflight(repo, lease_cli, lease_now, monkeypatch):
    _git(repo, "branch", "lane/docs")
    old = team.claim(repo, "docs", ["docs/**"], branch="lane/docs", owner="o@h", now=lease_now)
    real = gitsafe.run
    replacement = []

    def renew_during_probe(args, cwd, **kwargs):
        if not replacement and any(arg.startswith("refs/heads/") for arg in args):
            replacement.append(team.renew(repo, "docs", old.oid, now=lease_now + 1).oid)
        return real(args, cwd, **kwargs)

    monkeypatch.setattr(gitsafe, "run", renew_during_probe)
    code, payload, _ = lease_cli("renew", "docs", "--expect", old.oid)
    assert (code, payload["reason"], payload["current"]) == (1, "stale", replacement[0])
    assert _ref(repo, "docs") == replacement[0]


def test_cli_liveness_gc_does_not_warn_about_a_concurrently_renewed_lease(repo, worktree, lease_cli, lease_now, monkeypatch):
    old = team.claim(repo, "docs", ["docs/**"], branch="lane/other", owner="o@h", ttl_s=60, now=lease_now - 100)
    real = gitsafe.run
    replacement = []

    def renew_during_probe(args, cwd, **kwargs):
        if args[0] == "worktree" and not replacement:
            replacement.append(team.renew(repo, "docs", old.oid, now=lease_now).oid)
        return real(args, cwd, **kwargs)

    monkeypatch.setattr(gitsafe, "run", renew_during_probe)
    code, payload, _ = lease_cli("gc")
    assert (code, payload["collected"], payload["warnings"]) == (0, [], [])
    assert payload["lane_warnings"] == []
    assert _ref(repo, "docs") == replacement[0]


def test_core_lease_liveness_contract_stays_ttl_and_cas(repo, worktree):
    old = team.claim(repo, "docs", ["docs/**"], branch="missing", owner="o@h", ttl_s=60, now=NOW)
    renewed = team.renew(repo, "docs", old.oid, now=NOW + 100)
    assert renewed.action == "renewed"
    attached = team.claim(repo, "api", ["src/**"], branch="lane/other", owner="o@h", ttl_s=60, now=NOW)
    result = team.gc(repo, now=NOW + 100)
    assert [(change.lane, change.previous) for change in result.collected] == [("api", attached.oid)]
    assert _ref(repo, "docs") == renewed.oid and _ref(repo, "api") is None


@pytest.mark.parametrize("report", [
    b"", b"worktree /private\0HEAD abc\0branch refs/heads/main\0",
    b"worktree /private\0\0", b"worktree /private\0garbage\0\0",
    b"worktree /private\0HEAD abc\0branch refs/heads/main\0\0",
    b"worktree /private\0HEAD " + b"a" * 40 + b"\0branch refs/heads/main\0detached\0\0",
], ids=["empty", "unterminated", "no-head", "unknown-state", "bad-oid", "ambiguous-state"])
def test_cli_liveness_malformed_worktree_report_is_unknown(repo, lease_cli, lease_now, monkeypatch, report):
    old = team.claim(repo, "docs", ["docs/**"], branch="main", owner="o@h", ttl_s=60, now=lease_now - 100)
    real = gitsafe.run

    def malformed(args, cwd, **kwargs):
        if args[0] == "worktree":
            return subprocess.CompletedProcess(args, 0, report, b"token=private-value")
        return real(args, cwd, **kwargs)

    monkeypatch.setattr(gitsafe, "run", malformed)
    for _ in range(2):
        code, payload, err = lease_cli("gc")
        assert (code, payload["reason"], err) == (1, "liveness_unknown", "")
        assert "/private" not in json.dumps(payload)
        assert "private-value" not in json.dumps(payload)
        assert _ref(repo, "docs") == old.oid
    with pytest.raises(gitsafe.GitError) as caught:
        team.lease_branch_evidence(repo, now=lease_now, worktrees=True)
    assert caught.value.code == "git_failed"
    monkeypatch.setattr(gitsafe, "run", real)
    assert lease_cli("gc")[0] == 0


def test_cli_liveness_worktree_paths_cannot_forge_branch_records(repo, lease_cli, lease_now, monkeypatch):
    old = team.claim(repo, "docs", ["docs/**"], branch="lane/docs", owner="o@h", ttl_s=60, now=lease_now - 100)
    real = gitsafe.run
    report = (b"worktree /not-a-real-path\nbranch refs/heads/lane/docs\0HEAD " + b"a" * 40 +
              b"\0detached\0\0worktree /not-a-real-bare-path\0bare\0\0")

    def forged_path(args, cwd, **kwargs):
        if args[0] == "worktree":
            return subprocess.CompletedProcess(args, 0, report, b"")
        return real(args, cwd, **kwargs)

    monkeypatch.setattr(gitsafe, "run", forged_path)
    code, payload, err = lease_cli("gc")
    assert (code, payload["warnings"], err) == (0, [], "")
    assert payload["collected"][0]["previous"] == old.oid


def test_cli_liveness_real_oversized_worktree_output_refuses_then_retries(repo, worktree, lease_cli, lease_now):
    old = team.claim(repo, "docs", ["docs/**"], branch="lane/other", owner="o@h", ttl_s=60, now=lease_now - 100)
    lock = repo / ".git" / "worktrees" / "other" / "locked"
    lock.write_bytes(b"token=private-value " + b"x" * team.MAX_LEASE_BYTES)
    code, payload, err = lease_cli("gc")
    assert (code, payload["reason"], err) == (1, "liveness_unknown", "")
    assert "private-value" not in json.dumps(payload)
    assert _ref(repo, "docs") == old.oid
    lock.unlink()
    assert lease_cli("gc")[0] == 0


def test_cli_liveness_maximum_lease_blob_keeps_transport_header_headroom(repo, lease_cli, lease_now):
    blob = _valid_blob(branch="main", paths=["a"], ts=lease_now)
    blob["paths"] = ["a" * (1 + team.MAX_LEASE_BYTES - len(json.dumps(blob).encode()))]
    raw = json.dumps(blob).encode()
    assert len(raw) == team.MAX_LEASE_BYTES
    oid = _plant(repo, "refs/aegis/lanes/docs", raw)
    code, payload, err = lease_cli("renew", "docs", "--expect", oid)
    assert (code, payload["status"], err) == (0, "renewed", "")
    assert _ref(repo, "docs") == payload["oid"] != oid


@pytest.mark.parametrize("action,terms", [
    ("renew", ("lease_branch_missing", "worktree is not required", "liveness_unknown")),
    ("gc", ("expired_with_worktree", "expired leases are still collected", "liveness_unknown")),
])
def test_cli_liveness_help_documents_preflight(repo, capsys, action, terms):
    from aegis_cli.cli import main

    with pytest.raises(SystemExit) as caught:
        main(["--workspace", str(repo), "team", action, "--help"])
    assert caught.value.code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    text = " ".join(captured.out.split())
    assert all(term in text for term in terms)


def test_cli_liveness_preserves_unreadable_lease_recovery(repo, lease_cli):
    oid = _plant(repo, "refs/aegis/lanes/docs", b"token=private-value")
    code, payload, err = lease_cli("renew", "docs", "--expect", oid)
    assert (code, payload["reason"], err) == (1, "unreadable", "")
    assert payload["message"] == (
        f"unreadable: lane docs holds {oid}, which is no readable lease; release it with --expect {oid}")
    assert "private-value" not in json.dumps(payload)
    assert _ref(repo, "docs") == oid


@pytest.mark.parametrize("ttl", ["0", "86401"])
def test_cli_liveness_invalid_ttl_precedes_branch_probe(repo, lease_cli, lease_now, monkeypatch, ttl):
    old = team.claim(repo, "docs", ["docs/**"], branch="missing", owner="o@h", now=lease_now)
    real = gitsafe.run

    def no_branch_probe(args, cwd, **kwargs):
        if any(arg.startswith("refs/heads/") for arg in args):
            raise AssertionError("invalid TTL must refuse before branch probing")
        return real(args, cwd, **kwargs)

    monkeypatch.setattr(gitsafe, "run", no_branch_probe)
    code, payload, err = lease_cli("renew", "docs", "--expect", old.oid, "--ttl", ttl)
    assert (code, payload["error"], err) == (2, "ttl must be a whole number of seconds from 1 to 86400", "")
    assert _ref(repo, "docs") == old.oid


def _assert_team_worktree_list_only(source):
    calls = []
    for node in ast.walk(ast.parse(source)):
        if (not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or
                not isinstance(node.func.value, ast.Name) or node.func.value.id != "gitsafe" or
                node.func.attr not in ("run", "run_checked", "_run", "execute", "capture", "checked", "output", "text")):
            continue
        argv = node.args[0] if node.args else next(
            (keyword.value for keyword in node.keywords if keyword.arg in ("args", "argv")), None)
        assert (isinstance(argv, (ast.List, ast.Tuple)) and argv.elts and
                isinstance(argv.elts[0], ast.Constant) and isinstance(argv.elts[0].value, str) and
                not argv.elts[0].value.startswith("-")), "team Git argv must have a literal command head"
        if argv.elts[0].value == "worktree":
            calls.append(argv)
    assert len(calls) == 1, "expected exactly one team worktree invocation"
    expected = ast.parse("['worktree', 'list', '--porcelain', '-z']", mode="eval").body
    assert ast.dump(calls[0]) == ast.dump(expected), "team worktree command must be exactly list --porcelain -z"


def test_team_worktree_invocation_is_exactly_read_only_list():
    path = Path(__file__).resolve().parents[3] / "aegis_core" / "team.py"
    _assert_team_worktree_list_only(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("command", ["add", "remove", "prune", "move", "lock", "unlock", "repair"])
def test_team_worktree_shape_guard_refuses_mutations(command):
    source = f"gitsafe.run_checked(['worktree', {command!r}, '--porcelain', '-z'], root)"
    with pytest.raises(AssertionError, match="(?m)^team worktree command must be exactly list --porcelain -z$"):
        _assert_team_worktree_list_only(source)


@pytest.mark.parametrize("argv", [
    "['worktree', 'list']", "['worktree', 'list', '--porcelain']",
    "['worktree', 'list', '--porcelain', '-z', '--verbose']", "['worktree', operation, '--porcelain', '-z']",
], ids=["missing-format", "missing-nul", "extra-option", "dynamic-subcommand"])
def test_team_worktree_shape_guard_refuses_changed_argv(argv):
    with pytest.raises(AssertionError, match="(?m)^team worktree command must be exactly list --porcelain -z$"):
        _assert_team_worktree_list_only(f"gitsafe.run_checked({argv}, root)")


@pytest.mark.parametrize("extra", [
    "gitsafe.run(['worktree', 'add', 'other'], root)", "gitsafe.run_checked(['worktree', 'list', '--porcelain', '-z'], root)",
], ids=["additional-mutation", "duplicate-list"])
def test_team_worktree_shape_guard_refuses_additional_invocations(extra):
    source = "gitsafe.run_checked(['worktree', 'list', '--porcelain', '-z'], root)\n" + extra
    with pytest.raises(AssertionError, match="(?m)^expected exactly one team worktree invocation$"):
        _assert_team_worktree_list_only(source)


@pytest.mark.parametrize("source", [
    "gitsafe.run(['-c', 'a=b', 'worktree', 'add', 'other'], root)", "gitsafe.run(command, root)",
], ids=["leading-global-option", "dynamic-argv"])
def test_team_worktree_shape_guard_refuses_indeterminate_commands(source):
    with pytest.raises(AssertionError, match="(?m)^team Git argv must have a literal command head$"):
        _assert_team_worktree_list_only(source)


def test_team_worktree_shape_guard_does_not_pass_vacuously():
    with pytest.raises(AssertionError, match="(?m)^expected exactly one team worktree invocation$"):
        _assert_team_worktree_list_only("gitsafe.run(['ls-tree', '-z', commit], root)")


@pytest.mark.parametrize("action", ["renew", "gc"])
@pytest.mark.parametrize("selector", [
    "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE",
])
def test_cli_liveness_rejects_ambient_repository_selectors_before_both_phases(
        repo, tmp_path, lease_cli, lease_now, action, selector):
    other = tmp_path / "other-repository"
    other.mkdir()
    _git(other, "init", "-q", "-b", "main")
    _git(other, "commit", "--allow-empty", "-q", "-m", "other")
    _git(repo, "branch", "only-in-a")
    first = team.claim(repo, "docs", ["docs/**"], branch="only-in-a", owner="o@h", ttl_s=60, now=lease_now - 100)
    raw = gitsafe.read_object(repo, first.oid, team.MAX_LEASE_BYTES)
    assert _plant(other, team.lane_ref("docs"), raw) == first.oid
    values = {
        "GIT_DIR": other / ".git", "GIT_WORK_TREE": other, "GIT_COMMON_DIR": other / ".git",
        "GIT_INDEX_FILE": other / ".git" / "index", "GIT_OBJECT_DIRECTORY": other / ".git" / "objects",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": other / ".git" / "objects", "GIT_NAMESPACE": "other-namespace",
        "GIT_CEILING_DIRECTORIES": tmp_path,
    }
    args = ("renew", "docs", "--expect", first.oid) if action == "renew" else ("gc",)
    source = Path(__file__).resolve().parents[3]
    environment = dict(os.environ)
    environment.pop("AEGIS_WORKSPACE", None)
    environment[selector] = str(values[selector])
    entry = [sys.executable, "-I", "-c", (
        "import sys; sys.path.insert(0, sys.argv[1]); from aegis_cli.cli import main; "
        "sys.exit(main(sys.argv[2:]))"), str(source), "--workspace", str(repo), "team", *args, "--json"]
    for _ in range(2):
        result = subprocess.run(entry, cwd=repo, env=environment, capture_output=True, text=True, timeout=30)
        payload = json.loads(result.stdout)
        assert (result.returncode, payload.get("reason"), payload.get("message"), result.stderr) == (
            1, "ambient_git_environment", "ambient_git_environment", "")
        assert payload.get("next_action") == "Unset Git repository selectors, then retry."
    assert (_ref(repo, "docs"), _ref(other, "docs")) == (first.oid, first.oid)
    code, payload, _ = lease_cli(*args)
    assert code == 0
    assert _ref(other, "docs") == first.oid
    assert _ref(repo, "docs") != first.oid


@pytest.mark.parametrize("action", ["renew", "gc"])
def test_cli_liveness_readonly_checkout_uses_external_git_metadata(
        repo, tmp_path, lease_cli, lease_now, action):
    from tests.unit.core.test_storage_confined import make_store

    make_store(repo)
    if os.geteuid() == 0:
        pytest.skip("root bypasses the read-only checkout permission check")
    common = tmp_path / "external-metadata.git"
    (repo / ".git").rename(common)
    (repo / ".git").write_text(f"gitdir: {common}\n", encoding="utf-8")
    first = team.claim(repo, "docs", ["docs/**"], branch="main", owner="o@h", ttl_s=60, now=lease_now - 100)
    before = {path.relative_to(repo) for path in repo.rglob("*")}
    old_mode = stat.S_IMODE(repo.stat().st_mode)
    repo.chmod(0o555)
    try:
        args = ("renew", "docs", "--expect", first.oid) if action == "renew" else ("gc",)
        code, payload, err = lease_cli(*args)
        assert (code, payload["status"], err) == (0, "renewed" if action == "renew" else "collected", "")
        assert {path.relative_to(repo) for path in repo.rglob("*")} == before
    finally:
        repo.chmod(old_mode)


def _require_lease_descriptors(root):
    from tests.unit.core.test_storage_confined import make_store

    if not team_lease_custody.descriptor_supported():
        pytest.skip("requires parent-addressable lease descriptors")
    return make_store(root)


def test_lease_descriptor_guard_uses_the_custody_probe(repo, monkeypatch):
    monkeypatch.setattr(team_lease_custody, "descriptor_supported", lambda: False)
    with pytest.raises(pytest.skip.Exception, match="parent-addressable lease descriptors"):
        _require_lease_descriptors(repo)


@pytest.mark.parametrize("action", ["renew", "gc"])
@pytest.mark.parametrize("bad", ["symlink", "file", "owner", "mode"])
def test_cli_liveness_private_scratch_refuses_bad_entry_and_retries(
        repo, tmp_path, lease_cli, lease_now, monkeypatch, action, bad):
    from conftest import symlink_or_skip
    from tests.unit.core.test_storage_confined import ModuleOS

    _require_lease_descriptors(repo)
    old = team.claim(repo, "docs", ["docs/**"], branch="main", owner="o@h", ttl_s=60, now=lease_now - 100)
    scratch = repo / ".git" / "aegis-lease-scratch"
    outside = tmp_path / "outside"
    outside.mkdir()
    if bad == "symlink":
        symlink_or_skip(outside, scratch, target_is_directory=True)
    elif bad == "file":
        scratch.write_bytes(b"private-marker")
    else:
        scratch.mkdir(mode=0o700)
        if bad == "mode":
            scratch.chmod(0o755)
    original = os.fstat
    identity = scratch.stat() if bad == "owner" else None

    def fstat(fd):
        info = original(fd)
        if identity is not None and (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
            from types import SimpleNamespace
            return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino,
                                   st_mode=info.st_mode, st_uid=info.st_uid + 1)
        return info

    monkeypatch.setattr(team_lease_custody, "os", ModuleOS(fstat=fstat))
    args = ("renew", "docs", "--expect", old.oid) if action == "renew" else ("gc",)
    for _ in range(2):
        code, payload, err = lease_cli(*args)
        assert (code, payload["reason"], payload["message"], err) == (
            1, "liveness_unknown", "liveness_unknown", "")
        assert _ref(repo, "docs") == old.oid
    monkeypatch.setattr(team_lease_custody, "os", os)
    assert list(outside.iterdir()) == []
    if bad in ("file", "symlink"):
        scratch.unlink()
    else:
        scratch.chmod(0o700)
    assert lease_cli(*args)[0] == 0


@pytest.mark.parametrize("action", ["renew", "gc"])
@pytest.mark.parametrize("when", ["after_preflight", "after_verify"])
def test_cli_liveness_repository_transition_never_mutates_replacement(
        repo, tmp_path, lease_cli, lease_now, monkeypatch, action, when):
    _require_lease_descriptors(repo)
    other = tmp_path / "replacement"
    other.mkdir()
    _git(other, "init", "-q", "-b", "main")
    old = team.claim(repo, "docs", ["docs/**"], branch="main", owner="o@h", ttl_s=60, now=lease_now - 100)
    assert _plant(other, team.lane_ref("docs"), gitsafe.read_object(repo, old.oid, team.MAX_LEASE_BYTES)) == old.oid
    original_metadata = tmp_path / "original.git"
    original = getattr(team, "lease_branch_evidence" if when == "after_preflight" else action)
    swapped = []

    def replace(*args, **kwargs):
        result = original(*args, **kwargs) if when == "after_preflight" else None
        (repo / ".git").rename(original_metadata)
        (other / ".git").rename(repo / ".git")
        swapped.append(True)
        return result if when == "after_preflight" else original(*args, **kwargs)

    args = ("renew", "docs", "--expect", old.oid) if action == "renew" else ("gc",)
    if when == "after_preflight":
        monkeypatch.setattr(team, "lease_branch_evidence", replace)
    elif action == "renew":
        monkeypatch.setattr(team, "renew", replace)
    else:
        monkeypatch.setattr(team, "gc", replace)
    try:
        code, payload, err = lease_cli(*args)
        assert err == ""
        assert code == (1 if when == "after_preflight" else 0)
        if code:
            assert payload["reason"] == "liveness_unknown"
    finally:
        if swapped:
            (repo / ".git").rename(other / ".git")
            original_metadata.rename(repo / ".git")
    if when == "after_preflight":
        monkeypatch.setattr(team, "lease_branch_evidence", original)
    elif action == "renew":
        monkeypatch.setattr(team, "renew", original)
    else:
        monkeypatch.setattr(team, "gc", original)
    assert _ref(other, "docs") == old.oid
    if when == "after_preflight":
        assert _ref(repo, "docs") == old.oid
        assert lease_cli(*args)[0] == 0
    else:
        assert _ref(repo, "docs") != old.oid


@pytest.mark.parametrize("failure", ["none", "scratch_open", "scratch_stat", "verify", "capture", "final_close"])
def test_cli_liveness_custody_closes_owned_descriptors(
        repo, lease_cli, lease_now, monkeypatch, failure):
    from types import SimpleNamespace
    from tests.unit.core.test_storage_confined import ModuleOS

    _require_lease_descriptors(repo)
    old = team.claim(repo, "docs", ["docs/**"], branch="main", owner="o@h", now=lease_now)
    live, opened, closed = set(), [], []
    scratch_fds = set()

    def open_fd(path, flags, *args, **kwargs):
        if failure == "scratch_open" and path == "aegis-lease-scratch":
            raise OSError("private-marker")
        fd = os.open(path, flags, *args, **kwargs)
        assert fd not in live
        live.add(fd)
        opened.append(fd)
        if path == "aegis-lease-scratch":
            scratch_fds.add(fd)
        return fd

    def close_fd(fd):
        assert fd in live
        live.remove(fd)
        closed.append(fd)
        os.close(fd)
        if failure == "final_close" and fd in scratch_fds:
            scratch_fds.remove(fd)
            raise OSError("private-marker")

    def fstat(fd):
        if failure == "scratch_stat" and fd in scratch_fds:
            raise OSError("private-marker")
        return os.fstat(fd)

    def refuse(*args, **kwargs):
        raise gitsafe.GitError("private-marker", code="git_failed")

    original_verify = team_lease_custody.verify
    facade = ModuleOS(open=open_fd, close=close_fd, fstat=fstat)
    monkeypatch.setattr(storage_confined, "os", facade)
    monkeypatch.setattr(team_lease_custody, "os", facade)
    if failure == "verify":
        monkeypatch.setattr(team_lease_custody, "verify", refuse)
    if failure == "capture":
        monkeypatch.setattr(team, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "read_object": refuse}))
    code, payload, err = lease_cli("renew", "docs", "--expect", old.oid)
    assert (code, err) == (0 if failure == "none" else 1, "")
    if code:
        assert (payload["reason"], payload["message"]) == ("liveness_unknown", "liveness_unknown")
    monkeypatch.setattr(storage_confined, "os", os)
    monkeypatch.setattr(team_lease_custody, "os", os)
    monkeypatch.setattr(team_lease_custody, "verify", original_verify)
    monkeypatch.setattr(team, "gitsafe", gitsafe)
    assert opened and len(opened) == len(closed) and not live
    if failure == "final_close":
        current = _ref(repo, "docs")
        assert current != old.oid
        assert lease_cli("renew", "docs", "--expect", current)[0] == 0
    elif failure != "none":
        assert _ref(repo, "docs") == old.oid
        assert lease_cli("renew", "docs", "--expect", old.oid)[0] == 0


@pytest.mark.parametrize("action", ["renew", "gc"])
def test_cli_liveness_scratch_rename_keeps_the_open_directory(
        repo, tmp_path, lease_cli, lease_now, monkeypatch, action):
    from types import SimpleNamespace
    from conftest import symlink_or_skip
    _require_lease_descriptors(repo)
    old = team.claim(repo, "docs", ["docs/**"], branch="main", owner="o@h", ttl_s=60, now=lease_now - 100)
    scratch, moved = repo / ".git" / "aegis-lease-scratch", repo / ".git" / "held-scratch"
    outside = tmp_path / "outside"
    outside.mkdir()
    original = gitsafe.read_object
    changed = []

    def read(*args, **kwargs):
        if not changed:
            scratch.rename(moved)
            changed.append(True)
            symlink_or_skip(outside, scratch, target_is_directory=True)
        return original(*args, **kwargs)

    args = ("renew", "docs", "--expect", old.oid) if action == "renew" else ("gc",)
    monkeypatch.setattr(team, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "read_object": read}))
    try:
        code, payload, err = lease_cli(*args)
        assert (code, err) == (0, "")
        assert list(outside.iterdir()) == [] and list(moved.iterdir()) == []
    finally:
        if changed:
            scratch.unlink()
            moved.rename(scratch)
    monkeypatch.setattr(team, "gitsafe", gitsafe)
    retry = ("renew", "docs", "--expect", payload["oid"]) if action == "renew" else ("gc",)
    assert lease_cli(*retry)[0] == 0


@pytest.mark.parametrize("action", ["renew", "gc"])
def test_cli_liveness_metadata_ancestor_swap_refuses_without_following_link(
        repo, tmp_path, lease_cli, lease_now, monkeypatch, action):
    from conftest import symlink_or_skip
    from tests.unit.core.test_storage_confined import ModuleOS

    _require_lease_descriptors(repo)
    parent, moved, outside = (tmp_path / name for name in ("metadata", "held-metadata", "outside"))
    parent.mkdir()
    outside.mkdir()
    common = parent / "common.git"
    (repo / ".git").rename(common)
    (repo / ".git").write_text(f"gitdir: {common}\n", encoding="utf-8")
    old = team.claim(repo, "docs", ["docs/**"], branch="main", owner="o@h", ttl_s=60, now=lease_now - 100)
    changed = []

    def mkdir(path, mode=0o777, **kwargs):
        os.mkdir(path, mode, **kwargs)
        if path == "aegis-lease-scratch" and not changed:
            parent.rename(moved)
            changed.append(True)
            symlink_or_skip(outside, parent, target_is_directory=True)

    args = ("renew", "docs", "--expect", old.oid) if action == "renew" else ("gc",)
    monkeypatch.setattr(team_lease_custody, "os", ModuleOS(mkdir=mkdir))
    try:
        code, payload, err = lease_cli(*args)
        assert (code, payload["reason"], payload["message"], err) == (
            1, "liveness_unknown", "liveness_unknown", "")
        assert list(outside.iterdir()) == []
    finally:
        if changed:
            parent.unlink()
            moved.rename(parent)
    monkeypatch.setattr(team_lease_custody, "os", os)
    assert _ref(repo, "docs") == old.oid
    assert lease_cli(*args)[0] == 0


@pytest.mark.parametrize("root", [None, 42, "x" * 16385, "bad\0root", "/a/../b"],
                         ids=["none", "integer", "long", "nul", "traversal"])
def test_lease_custody_bounds_roots_before_platform_or_filesystem_probe(monkeypatch, root):
    def unexpected():
        raise AssertionError("invalid root reached platform/filesystem discovery")

    monkeypatch.setattr(team_lease_custody, "descriptor_supported", unexpected)
    with pytest.raises(gitsafe.GitError, match="^liveness_unknown$") as caught:
        with team.lease_custody(root):
            pytest.fail("invalid root entered custody")
    assert caught.value.code == "git_failed"


@pytest.mark.parametrize("action", ["renew", "gc"])
@pytest.mark.parametrize("directory", ["workspace", "external_git", "common"])
def test_cli_liveness_confined_directory_close_refuses_and_closes_every_fd(
        repo, tmp_path, lease_now, capsys, monkeypatch, action, directory):
    import errno
    from aegis_cli.cli import main
    from tests.unit.core.test_storage_confined import ModuleOS

    _require_lease_descriptors(repo)
    workspace, target = repo, repo
    if directory == "external_git":
        target = tmp_path / "external.git"
        (repo / ".git").rename(target)
        (repo / ".git").write_text(f"gitdir: {target}\n", encoding="utf-8")
    elif directory == "common":
        workspace = tmp_path / "linked"
        _git(repo, "worktree", "add", "-q", "-b", "lane/cleanup", str(workspace))
        target = repo / ".git"
    (workspace / ".aegis" / "rules").mkdir(parents=True, exist_ok=True)
    old = team.claim(workspace, "docs", ["docs/**"], owner="o@h", branch="main", ttl_s=60,
                     now=lease_now if action == "renew" else lease_now - 100)
    identity = (target.stat().st_dev, target.stat().st_ino)
    live, opened, closed, fired, changed = set(), [], [], [], []
    original = team.renew if action == "renew" else team.gc

    def mutate(*args, **kwargs):
        result = original(*args, **kwargs)
        changed.append(True)
        return result

    def open_fd(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        assert fd not in live
        live.add(fd)
        opened.append(fd)
        return fd

    def close_fd(fd):
        info = os.fstat(fd)
        fail = changed and not fired and not gitsafe.custody_active() and (info.st_dev, info.st_ino) == identity
        assert fd in live
        live.remove(fd)
        closed.append(fd)
        os.close(fd)
        if fail:
            fired.append(True)
            raise OSError(errno.EIO, "private-directory-close-marker")

    facade = ModuleOS(open=open_fd, close=close_fd)
    monkeypatch.setattr(storage_confined, "os", facade)
    monkeypatch.setattr(team_lease_custody, "os", facade)
    if action == "renew":
        monkeypatch.setattr(team, "renew", mutate)
    else:
        monkeypatch.setattr(team, "gc", mutate)
    args = ("renew", "docs", "--expect", old.oid) if action == "renew" else ("gc",)
    try:
        code = main(["--workspace", str(workspace), "team", *args, "--json"])
        captured = capsys.readouterr()
        assert (code, captured.err) == (1, "")
        payload = json.loads(captured.out)
        assert (code, payload["reason"], payload["message"], captured.err) == (
            1, "liveness_unknown", "liveness_unknown", "")
        assert fired == [True]
    finally:
        monkeypatch.setattr(storage_confined, "os", os)
        monkeypatch.setattr(team_lease_custody, "os", os)
        if action == "renew":
            monkeypatch.setattr(team, "renew", original)
        else:
            monkeypatch.setattr(team, "gc", original)
        assert opened and len(opened) == len(closed) and not live
    current = _ref(repo, "docs")
    assert current != old.oid
    retry = ("renew", "docs", "--expect", current) if action == "renew" else ("gc",)
    assert main(["--workspace", str(workspace), "team", *retry, "--json"]) == 0
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("as_json", [True, False])
def test_cli_lease_refusal_keeps_custody_after_git_entry_disappears(
        repo, tmp_path, lease_cli, monkeypatch, as_json):
    from types import SimpleNamespace

    _require_lease_descriptors(repo)
    bad = _plant(repo, team.lane_ref("docs"), b"private-refusal-blob-marker")
    held = tmp_path / "held.git"
    original = gitsafe.read_object
    changed = []
    observed = []

    def read(*args, **kwargs):
        data = original(*args, **kwargs)
        observed.append(gitsafe.custody_active())
        if not changed:
            (repo / ".git").rename(held)
            changed.append(True)
        return data

    monkeypatch.setattr(team, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "read_object": read}))
    try:
        code, result, err = lease_cli("renew", "docs", "--expect", bad, as_json=as_json)
        assert code == 1
        if as_json:
            assert (result["reason"], result["current"], result["lease"], err) == ("unreadable", bad, None, "")
            assert "private-refusal-blob-marker" not in json.dumps(result)
        else:
            assert result == "" and err.startswith("unreadable: lane docs holds ")
            assert f"release it with --expect {bad}" in err
        assert len(observed) >= 2 and all(observed)
    finally:
        if changed:
            held.rename(repo / ".git")
    monkeypatch.setattr(team, "gitsafe", gitsafe)
    assert _ref(repo, "docs") == bad
    repaired = _plant(repo, team.lane_ref("docs"), json.dumps(_valid_blob(ts=int(time.time()), branch="main")).encode())
    assert lease_cli("renew", "docs", "--expect", repaired)[0] == 0


@pytest.mark.parametrize("backend", ["descriptor", "pathname"])
@pytest.mark.parametrize("failure", ["git", "os", "value"])
def test_cli_lease_refusal_view_failure_is_one_typed_document(
        repo, lease_cli, monkeypatch, backend, failure):
    from types import SimpleNamespace

    if backend == "descriptor":
        _require_lease_descriptors(repo)
    else:
        monkeypatch.setattr(team_lease_custody, "descriptor_supported", lambda: False)
    bad = _plant(repo, team.lane_ref("docs"), b"private-refusal-blob-marker")
    original_read, original_refs = gitsafe.read_object, gitsafe.list_refs
    ready, failed = [], []

    def read(*args, **kwargs):
        data = original_read(*args, **kwargs)
        ready.append(True)
        return data

    def refs(*args, **kwargs):
        if ready:
            failed.append(True)
            if failure == "git":
                raise gitsafe.GitError("private-view-marker", code="git_timeout")
            if failure == "os":
                raise OSError("private-view-marker")
            raise ValueError("private-view-marker")
        return original_refs(*args, **kwargs)

    monkeypatch.setattr(team, "gitsafe", SimpleNamespace(**{**vars(gitsafe), "read_object": read, "list_refs": refs}))
    for _ in range(2):
        code, result, err = lease_cli("renew", "docs", "--expect", bad)
        assert (code, result["reason"], result["message"], err) == (1, "liveness_unknown", "liveness_unknown", "")
        assert _ref(repo, "docs") == bad
    assert failed
    monkeypatch.setattr(team, "gitsafe", gitsafe)
    repaired = _plant(repo, team.lane_ref("docs"), json.dumps(_valid_blob(ts=int(time.time()), branch="main")).encode())
    assert lease_cli("renew", "docs", "--expect", repaired)[0] == 0


@pytest.mark.parametrize("action", ["renew", "gc"])
@pytest.mark.parametrize("kind", ["commit", "oversized", "malformed", "value-error"])
def test_cli_liveness_object_error_is_one_unreadable_lane(
        repo, lease_cli, lease_now, monkeypatch, action, kind):
    docs = team.claim(repo, "docs", ["docs/**"], branch="main", owner="o@h", ttl_s=60, now=lease_now - 100)
    if kind == "commit":
        bad = _git(repo, "rev-parse", "HEAD").strip()
        _git(repo, "update-ref", team.lane_ref("api"), bad)
    else:
        raw = b"private-lease-marker" + (b"x" * team.MAX_LEASE_BYTES if kind == "oversized" else b"")
        bad = _plant(repo, team.lane_ref("api"), raw)
    real = gitsafe.read_object

    def object_value_error(cwd, oid, limit):
        if oid == bad:
            raise ValueError("private-lease-marker")
        return real(cwd, oid, limit)

    if kind == "value-error":
        monkeypatch.setattr(gitsafe, "read_object", object_value_error)
    args = ("renew", "api", "--expect", bad) if action == "renew" else ("gc",)
    code, payload, err = lease_cli(*args)
    assert err == "" and "private-lease-marker" not in json.dumps(payload)
    if action == "gc":
        assert (code, payload["kept"]) == (0, [{"lane": "api", "reason": "unreadable"}])
        assert [(row["lane"], row["previous"]) for row in payload["collected"]] == [("docs", docs.oid)]
    else:
        assert (code, payload["reason"], payload["message"]) == (
            1, "unreadable", f"unreadable: lane api holds {bad}, which is no readable lease; release it with --expect {bad}")
    assert _ref(repo, "api") == bad
    repaired = _plant(repo, team.lane_ref("api"), json.dumps(
        _valid_blob(lane="api", paths=["src/**"], branch="main", ts=lease_now)).encode())
    retry = ("renew", "api", "--expect", repaired) if action == "renew" else ("gc",)
    assert lease_cli(*retry)[0] == 0


@pytest.mark.parametrize("branch,target", [
    ("refs/remotes/origin/HEAD", "refs/remotes/origin/main"),
    ("refs/heads/lane/docs", "refs/heads/main"),
])
def test_cli_liveness_symbolic_branch_is_present(repo, lease_cli, lease_now, branch, target):
    _git(repo, "update-ref", target, "HEAD")
    _git(repo, "symbolic-ref", branch, target)
    old = team.claim(repo, "docs", ["docs/**"], branch=branch, owner="o@h", now=lease_now)
    for _ in range(2):
        code, payload, err = lease_cli("renew", "docs", "--expect", old.oid)
        assert (code, payload["status"], err) == (0, "renewed", "")
        old = team.read_leases(repo).get("docs")


@pytest.mark.parametrize("metadata", [b"locked", b"locked private-reason", b"prunable private-reason"])
def test_cli_liveness_bare_worktree_record_accepts_administrative_metadata(
        repo, lease_cli, lease_now, monkeypatch, metadata):
    old = team.claim(repo, "docs", ["docs/**"], branch="main", owner="o@h", ttl_s=60, now=lease_now - 100)
    real = gitsafe.run

    def bare_record(args, cwd, **kwargs):
        if args[0] == "worktree":
            return subprocess.CompletedProcess(args, 0, b"worktree /private-path\0bare\0" + metadata + b"\0\0", b"")
        return real(args, cwd, **kwargs)

    monkeypatch.setattr(gitsafe, "run", bare_record)
    code, payload, err = lease_cli("gc")
    assert (code, payload["status"], payload["warnings"], err) == (0, "collected", [], "")
    assert payload["collected"][0]["previous"] == old.oid
    assert "private-" not in json.dumps(payload)


@pytest.mark.parametrize("illegal", [b"HEAD " + b"a" * 40, b"branch refs/heads/main", b"detached"])
def test_cli_liveness_bare_worktree_record_still_rejects_checkout_state(
        repo, lease_cli, lease_now, monkeypatch, illegal):
    old = team.claim(repo, "docs", ["docs/**"], branch="main", owner="o@h", ttl_s=60, now=lease_now - 100)
    real = gitsafe.run

    def bare_record(args, cwd, **kwargs):
        if args[0] == "worktree":
            return subprocess.CompletedProcess(args, 0, b"worktree /private\0bare\0locked\0" + illegal + b"\0\0", b"")
        return real(args, cwd, **kwargs)

    monkeypatch.setattr(gitsafe, "run", bare_record)
    code, payload, err = lease_cli("gc")
    assert (code, payload["reason"], err) == (1, "liveness_unknown", "")
    assert _ref(repo, "docs") == old.oid


@pytest.mark.parametrize("action", ["renew", "gc"])
@pytest.mark.parametrize("failure_code", ["git_failed", "git_timeout", "git_output_limit", "git_cleanup_failed"])
def test_cli_liveness_transport_read_failure_is_global_and_retryable(
        repo, lease_cli, lease_now, monkeypatch, action, failure_code):
    old = team.claim(repo, "docs", ["docs/**"], branch="main", owner="o@h", ttl_s=60, now=lease_now - 100)
    real = gitsafe.read_object

    def transport_failure(cwd, oid, limit):
        if oid == old.oid:
            raise gitsafe.GitError("private-transport-marker", code=failure_code)
        return real(cwd, oid, limit)

    monkeypatch.setattr(gitsafe, "read_object", transport_failure)
    args = ("renew", "docs", "--expect", old.oid) if action == "renew" else ("gc",)
    for _ in range(2):
        code, payload, err = lease_cli(*args)
        assert (code, payload["reason"], err) == (1, "liveness_unknown", "")
        assert "private-transport-marker" not in json.dumps(payload)
        assert _ref(repo, "docs") == old.oid
    monkeypatch.setattr(gitsafe, "read_object", real)
    assert lease_cli(*args)[0] == 0


def test_cli_liveness_direct_branch_can_become_symbolic_during_probe(repo, lease_cli, lease_now, monkeypatch):
    branch = "refs/heads/lane/docs"
    _git(repo, "update-ref", branch, "HEAD")
    old = team.claim(repo, "docs", ["docs/**"], branch=branch, owner="o@h", now=lease_now)
    real = gitsafe.run
    changed = []

    def symbolize_during_read(args, cwd, **kwargs):
        if args[0] == "for-each-ref" and branch in args and not changed:
            _git(repo, "symbolic-ref", branch, "refs/heads/main")
            changed.append(True)
        return real(args, cwd, **kwargs)

    monkeypatch.setattr(gitsafe, "run", symbolize_during_read)
    code, payload, err = lease_cli("renew", "docs", "--expect", old.oid)
    assert changed == [True]
    assert (code, payload["status"], err) == (0, "renewed", "")
    assert _ref(repo, "docs") == payload["oid"] != old.oid
