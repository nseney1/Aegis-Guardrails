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
import subprocess
import sys
import time
from typing import Dict, List, Optional

import pytest

from aegis_core import events, gitsafe, lane_gate, match, storage_confined, team, team_paths, team_status
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
