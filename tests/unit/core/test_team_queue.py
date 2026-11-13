"""Queue behaviour through its service, with real storage and process races."""
from concurrent.futures import ProcessPoolExecutor
import json
import os
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from conftest import symlink_or_skip
from aegis_core import atomicio, storage, storage_confined, team, team_queue as queue


@pytest.fixture
def make_store(tmp_path):
    if not queue.descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    if shutil.which("git") is None:
        pytest.skip("requires git")
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / ".aegis").mkdir()
    (root / ".aegis" / "team.json").write_text(json.dumps({
        "v": 1, "lanes": {"alpha": ["src/**"], "beta": ["docs/**"]}}), encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir()
    # Restored by the repository's autouse environment-isolation fixture.
    os.environ.update({"HOME": str(home), "USERPROFILE": str(home)})
    return root


def item(identifier="ONE", **fields):
    return {"id": identifier, "title": "Queue work", "paths": ["src/**"],
            "capabilities": ["core"], **fields}


def add(root, identifier="ONE", **fields):
    result = queue.add(root, item(identifier, **fields), now=100)
    assert not result["refused"], result
    return result["item"]["revision"]


def claim(root, revision, identifier="ONE", lane="alpha", now=101, ttl_s=10, branch="lane/alpha"):
    return queue.claim(root, identifier, expect=revision, lane=lane,
                       capabilities=["core"], ttl_s=ttl_s, now=now, branch=branch)


def race_claim(arguments):
    root, revision = arguments
    return claim(root, revision)


@pytest.mark.parametrize("spelling,accepted", [
    ("/workspace", True), ("workspace", True), ("./workspace", True),
    ("workspace/..cache", True), ("C:workspace", True), ("C:\\workspace", True),
    ("C:..\\ws", False), ("C:..", False), ("\\..\\ws", False), ("ws/../x", False),
    ("/workspace/../other", False), ("workspace\\..\\other", False),
    ("", False), ("/workspace/\x00", False), (None, False), (1, False), (b"/workspace", False),
    ("x" * 32768, True), ("x" * 32769, False),
    ("/" * 256, True), ("/" * 257, False), ("\\" * 257, False),
    ("/" * 128 + "\\" * 129, False),
], ids=["absolute", "relative", "current", "nonparent-name", "drive-relative", "drive-absolute",
        "drive-parent", "drive-parent-only", "rooted-parent", "relative-parent", "absolute-parent",
        "backslash-parent", "empty", "nul", "none", "integer", "bytes", "max-length", "over-length",
        "max-depth", "over-depth", "backslash-depth", "mixed-depth"])
def test_workspace_spelling_predicate_is_pure_and_cross_platform(spelling, accepted):
    assert queue.valid_workspace_spelling(spelling) is accepted


@pytest.mark.parametrize("spelling", ["C:..\\ws", "C:..", "\\..\\ws", "ws/../x"])
@pytest.mark.parametrize("verb", ["list", "audit", "add"])
def test_invalid_workspace_precedes_platform_and_filesystem_checks(monkeypatch, spelling, verb):
    monkeypatch.setattr(queue, "descriptor_supported", lambda: False)
    arguments = {"item": item(), "caller": "owner"} if verb == "add" else {}
    result = getattr(queue, verb)(spelling, now=100, **arguments)
    assert result["refused"] is True and result["reason"] == "invalid_arguments"
    assert result["exit_code"] == 2 and result["next_action"]
    assert all(spelling not in value for value in result.values() if isinstance(value, str))


def test_claim_cas_expiry_release_done_and_retry(make_store):
    root = make_store
    revision = add(root)
    claimed = claim(root, revision)
    assert not claimed["refused"]
    token = claimed["item"]["revision"]
    assert queue.list(root, now=102)["items"][0]["label"] == "alpha [ONE: Queue work]"
    assert claim(root, revision)["reason"] == "stale_revision"
    assert claim(root, token)["reason"] == "already_claimed"
    assert queue.done(root, "ONE", expect=token, now=111)["reason"] == "lease_expired"
    replacement = claim(root, token, lane="beta", now=111)
    assert not replacement["refused"]
    newer = replacement["item"]["revision"]
    assert queue.release(root, "ONE", expect=token, now=112)["reason"] == "stale_revision"
    released = queue.release(root, "ONE", expect=newer, lane="beta", now=112)
    assert not released["refused"]
    final = claim(root, released["item"]["revision"], now=113)
    completed = queue.done(root, "ONE", expect=final["item"]["revision"], lane="alpha", now=114)
    assert completed["item"]["state"] == "done"
    assert queue.done(root, "ONE", expect=completed["item"]["revision"], now=115)["reason"] == "not_claimed"


def test_concurrent_process_claims_have_one_winner(make_store):
    root = make_store
    revision = add(root)
    with ProcessPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(race_claim, [(root, revision)] * 2))
    assert sorted(result["refused"] for result in results) == [False, True]
    assert next(result for result in results if result["refused"])["reason"] == "stale_revision"


def test_capabilities_dependencies_and_typed_holds(make_store):
    root = make_store
    revision = add(root, hold_until=[{"kind": "owner"}], after=["MISSING"])
    refused = claim(root, revision)
    assert refused["reason"] == "blocked"
    assert {row["reason"] for row in refused["blockers"]} == {"owner", "after"}
    assert all(row["refused"] and row["next_action"] for row in refused["blockers"])
    assert queue.list(root, capabilities=["docs"], now=101)["items"] == []
    assert queue.claim(root, "ONE", expect=revision, lane="alpha", capabilities=[], now=101)["reason"] == "capability_mismatch"


def test_missing_lane_config_is_coordinator_condition(make_store):
    root = make_store
    revision = add(root)
    (root / ".aegis" / "team.json").unlink()
    result = claim(root, revision)
    assert result["reason"] == "blocked"
    assert result["blockers"][0]["reason"] == "coordinator"
    assert queue.audit(root, now=101)["findings"][0]["code"] == "WAITING_ONLY_COORDINATOR"


def test_milestone_and_lease_free_evaluated_at_claim(make_store):
    root = make_store
    revision = add(root, hold_until=[{"kind": "milestone", "name": "landed"},
                                    {"kind": "lease_free", "paths": ["src/**"]}])
    lease = team.claim(root, "beta", ["src/**"], owner="owner", now=100, ttl_s=10)
    result = claim(root, revision)
    assert {row["reason"] for row in result["blockers"]} == {"milestone", "lease_free", "foreign_lease"}
    state = root / ".aegis" / "state" / "team-queue.json"
    document = json.loads(state.read_text(encoding="utf-8"))
    document["milestones"] = ["landed"]
    state.write_text(json.dumps(document), encoding="utf-8")
    assert claim(root, revision)["reason"] == "blocked"
    assert not claim(root, revision, now=110)["refused"]
    assert lease.lease.expired(110)


@pytest.mark.parametrize("held,wanted,blocked", [
    ("/pyproject.toml", "/pyproject.toml", True),
    ("/pyproject.toml", "/nested/pyproject.toml", False),
    ("pyproject.toml", "/nested/pyproject.toml", True),
    ("/docs/", "/docs/guide.md", True),
    ("/docs/", "/docs2/guide.md", False),
    ("src/*.rs", "src/readme.txt", True),
])
def test_repository_lease_free_uses_lease_path_semantics_and_expiry(make_store, held, wanted, blocked):
    root = make_store
    revision = add(root, paths=["work/**"], hold_until=[{"kind": "lease_free", "paths": [wanted]}])
    team.claim(root, "beta", [held], owner="owner", now=100, ttl_s=10)
    result = claim(root, revision)
    if blocked:
        assert result["reason"] == "blocked"
        assert any(row["reason"] == "lease_free" for row in result["blockers"])
    else:
        # The external lane still occupies the default writer slot, even when
        # its anchored scope does not cover this hold's path.
        assert result["reason"] == "capacity_full"
    listed = queue.list(root, now=101)
    assert any(row["reason"] == "lease_free" for row in listed["items"][0]["blockers"]) is blocked
    assert not claim(root, revision, now=110)["refused"]


@pytest.mark.parametrize("held,wanted,blocked", [
    ("/pyproject.toml", "/nested/pyproject.toml", False),
    ("pyproject.toml", "/nested/pyproject.toml", True),
    ("/docs/", "/docs/guide.md", True),
    ("src/*.rs", "src/readme.txt", True),
])
@pytest.mark.parametrize("judgment", ("scope", "lease_free"))
def test_queue_lease_paths_gate_scope_and_holds_with_release_retry(make_store, held, wanted, blocked, judgment):
    root = make_store
    first = add(root, paths=[held])
    second = add(root, "TWO", paths=[wanted] if judgment == "scope" else ["work/**"],
                 hold_until=[] if judgment == "scope" else [{"kind": "lease_free", "paths": [wanted]}])
    active = claim(root, first)
    assert not active["refused"]
    result = claim(root, second, "TWO", lane="beta")
    if blocked:
        assert result["reason"] == "blocked"
        expected = "scope_overlap" if judgment == "scope" else "lease_free"
        assert any(row["reason"] == expected for row in result["blockers"])
    else:
        assert result["reason"] == "capacity_full"
    assert not queue.release(root, "ONE", expect=active["item"]["revision"], lane="alpha", now=102)["refused"]
    assert not claim(root, second, "TWO", lane="beta", now=103)["refused"]


def race_scoped_claim(arguments):
    root, revision, identifier, lane = arguments
    return claim(root, revision, identifier, lane=lane)


def test_concurrent_overlapping_lease_scopes_have_one_winner(make_store):
    root = make_store
    first = add(root, paths=["/src/one.py"])
    second = add(root, "TWO", paths=["/src/*.txt"])
    with ProcessPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(race_scoped_claim, [(root, first, "ONE", "alpha"),
                                                  (root, second, "TWO", "beta")], timeout=30))
    assert sorted(row["refused"] for row in results) == [False, True]
    loser = next(row for row in results if row["refused"])
    assert loser["reason"] == "blocked"
    assert any(row["reason"] == "scope_overlap" for row in loser["blockers"])


def test_audit_identifies_satisfied_conditions_and_judgment_hold(make_store):
    root = make_store
    add(root, hold="Await decision", hold_until=[{"kind": "lease_free", "paths": ["src/**"]}])
    result = queue.audit(root, now=101)
    assert [row["code"] for row in result["findings"]] == ["CONDITIONS_MET_STILL_HELD"]
    assert result["findings"][0]["next_action"]


def test_writer_capacity_comes_from_layered_profile_and_release_frees_slot(make_store):
    root = make_store
    first = add(root)
    second = add(root, "TWO", paths=["docs/**"])
    claimed = claim(root, first)
    assert claim(root, second, "TWO", lane="beta")["reason"] == "capacity_full"
    queue.release(root, "ONE", expect=claimed["item"]["revision"], lane="alpha", now=102)
    assert not claim(root, second, "TWO", lane="beta", now=103)["refused"]


@pytest.mark.parametrize("value", [None, {}, item(id="../escape"), item(title="one\ntwo"),
                                  item(paths=["../outside"]), item(paths=["/../outside"]),
                                  item(paths=["C:/outside"]), item(paths=["src\\outside"]),
                                  item(capabilities=["core"] * 129),
                                  item(hold_until=[{"kind": "unknown"}]), item(unknown=True)])
def test_malformed_items_refuse_without_echo_or_write(make_store, value):
    result = queue.add(make_store, value, now=100)
    assert result["refused"] and result["reason"] == "invalid_item" and result["next_action"]
    assert not (make_store / ".aegis" / "state").exists()


def test_unsupported_platform_has_stable_refusal(tmp_path, monkeypatch):
    monkeypatch.setattr(queue, "descriptor_supported", lambda: False)
    for verb, kwargs in [("list", {}), ("audit", {}), ("compact", {}), ("add", {"item": item()})]:
        result = getattr(queue, verb)(tmp_path, **kwargs)
        assert result["reason"] == "unsupported_platform" and result["refused"]


def test_symlinked_state_is_refused_without_touching_target(make_store, tmp_path):
    target = tmp_path / "outside"
    target.mkdir()
    symlink_or_skip(target, make_store / ".aegis" / "state", target_is_directory=True)
    assert queue.add(make_store, item(), now=100)["reason"] == "queue_io_unavailable"
    assert list(target.iterdir()) == []


def test_size_limit_before_json_parse_and_lock_timeout(make_store, monkeypatch):
    root = make_store
    add(root)
    state = root / ".aegis" / "state" / "team-queue.json"
    state.write_bytes(b" " * (queue.MAX_BYTES + 1))
    assert queue.list(root, now=101)["reason"] == "queue_size_limit"
    assert queue.parse_item("[" * 10000)["reason"] == "invalid_item"
    def timeout(*args, **kwargs):
        raise storage.LockTimeoutError("untrusted detail")
    monkeypatch.setattr(queue, "locked", timeout)
    result = queue.add(root, item("TWO"), now=101)
    assert result["reason"] == "queue_lock_timeout"
    assert "untrusted detail" not in json.dumps(result)


def test_read_keeps_its_opened_file_during_an_ancestor_swap(make_store, tmp_path, monkeypatch):
    root = make_store
    add(root)
    outside = tmp_path / "outside"
    outside.mkdir()
    original = root / ".aegis"
    moved = root / "original-aegis"

    def opened(path, *args, **kwargs):
        fd = os.open(path, *args, **kwargs)
        if path == "team.json":
            original.rename(moved)
            symlink_or_skip(outside, original, target_is_directory=True)
        return fd

    monkeypatch.setattr(storage_confined, "os", SimpleNamespace(**{**vars(os), "open": opened}))
    result = queue.list(root, now=101)
    assert not result["refused"], result
    assert list(outside.iterdir()) == []
    assert result["items"][0]["id"] == "ONE"


@pytest.mark.parametrize("failure", ["open", "fstat", "read", "write", "fsync", "replace"])
def test_descriptor_failures_close_handles_and_refuse_without_echo(make_store, monkeypatch, failure):
    root = make_store
    add(root)
    state = root / ".aegis" / "state" / "team-queue.json"
    before = state.read_bytes()
    live = set()

    def opened(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        live.add(fd)
        return fd

    def closed(fd):
        os.close(fd)
        live.remove(fd)

    def failed(*args, **kwargs):
        raise OSError("token=private-value\nuntrusted")

    proxy = SimpleNamespace(**{**vars(os),
        "open": failed if failure == "open" else opened, "close": closed,
        "fstat": failed if failure == "fstat" else os.fstat,
        "read": failed if failure == "read" else os.read,
        "write": failed if failure == "write" else os.write,
        "fsync": failed if failure == "fsync" else os.fsync,
        "replace": failed if failure == "replace" else os.replace})
    def publication(*args, **kwargs):
        # Scope the OS fault to the actual publisher. The workspace lock also
        # uses atomicio's opener but closes through storage's OS reference.
        monkeypatch.setattr(atomicio, "os", proxy)
        try:
            return atomicio.atomic_write_bytes(*args, **kwargs)
        finally:
            monkeypatch.setattr(atomicio, "os", os)

    if failure in ("write", "fsync", "replace"):
        monkeypatch.setattr(queue, "atomic_write_bytes", publication)
    else:
        monkeypatch.setattr(storage_confined, "os", proxy)
    result = queue.add(root, item("TWO"), now=101)
    assert result["reason"] == "queue_io_unavailable" and result["refused"]
    assert "private-value" not in json.dumps(result)
    assert not live
    assert state.read_bytes() == before
    if failure in ("write", "fsync", "replace"):
        monkeypatch.setattr(queue, "atomic_write_bytes", atomicio.atomic_write_bytes)
    else:
        monkeypatch.setattr(storage_confined, "os", os)
    assert not queue.add(root, item("TWO"), now=102)["refused"]


def test_large_utf8_and_serialized_items_are_refused_without_changing_state(make_store):
    root = make_store
    add(root)
    state = root / ".aegis" / "state" / "team-queue.json"
    before = state.read_bytes()
    assert queue.parse_item('"' + "😀" * (queue.MAX_BYTES // 4) + '"')["reason"] == "invalid_item"
    oversized = item("TWO", invariants=["😀" * queue.MAX_TEXT] * queue.MAX_FIELDS)
    assert queue.add(root, oversized, now=101)["reason"] == "queue_size_limit"
    assert state.read_bytes() == before


@pytest.mark.parametrize("raw", [b"{}", b'{"version":1,"version":1}', b"[", b"NaN"])
def test_corrupt_queue_state_has_a_fixed_refusal(make_store, raw):
    root = make_store
    add(root)
    (root / ".aegis" / "state" / "team-queue.json").write_bytes(raw)
    result = queue.list(root, now=101)
    assert result["reason"] == "invalid_queue_state" and result["exit_code"] == 1

@pytest.mark.parametrize("text", ["é" * 4096, "😀" * 2048, "😀" * 4096], ids=["bmp", "astral-half", "astral-full"])
@pytest.mark.parametrize("field", ["hold", "scope_rulings", "invariants"])
def test_accepted_constraint_roundtrips_without_loss(make_store, text, field):
    fields = {field: text if field == "hold" else [text]}
    result = queue.add(make_store, item(**fields), now=100)
    assert not result["refused"], result
    assert result["item"][field] == fields[field]
    listed = queue.list(make_store, now=101)
    assert not listed["refused"], listed
    assert listed["items"][0][field] == fields[field]


def test_aggregate_parser_limit_refuses_before_publication_and_retry(make_store):
    paths = ["scope/%03d" % index for index in range(128)]
    conditions = [{"kind": "lease_free", "paths": paths} for _ in range(128)]
    for index in range(4):
        before = queue.list(make_store, now=100)
        result = queue.add(make_store, item("HEAVY%d" % index, hold_until=conditions), now=100)
        listed = queue.list(make_store, now=101)
        assert not listed["refused"], (result, listed)
        if result["refused"]:
            assert result["reason"] == "queue_size_limit"
            assert listed["items"] == before["items"]
            assert not queue.add(make_store, item("SMALL"), now=102)["refused"]
            break
    else:
        pytest.fail("aggregate parser limit was not exercised")


def test_queue_transitions_have_correlated_events_and_lane_checks(make_store):
    from aegis_core import events
    root = make_store
    added = queue.add(root, item(), now=100, caller="router")
    assert not added["refused"]
    claimed = queue.claim(root, "ONE", expect=added["item"]["revision"], lane="alpha",
                          capabilities=["core"], now=101, caller="worker")
    assert not claimed["refused"]
    token = claimed["item"]["revision"]
    assert queue.done(root, "ONE", expect=token, now=102)["reason"] == "lane_required"
    assert queue.done(root, "ONE", expect=token, lane="beta", now=102)["reason"] == "lane_mismatch"
    released = queue.release(root, "ONE", expect=token, lane="alpha", now=102, caller="worker")
    assert not released["refused"]
    claimed_again = queue.claim(root, "ONE", expect=released["item"]["revision"], lane="alpha",
                                capabilities=["core"], now=103, caller="worker")
    completed = queue.done(root, "ONE", expect=claimed_again["item"]["revision"], lane="alpha",
                           now=104, caller="worker")
    assert not completed["refused"]
    rows = [row["detail"] for row in events.read(root).rows if row["detail"].get("queue") is True]
    assert [row["action"] for row in rows] == ["add", "claim", "release", "claim", "done"]
    assert rows[0]["caller"] == "router"
    assert rows[1]["label"] == "alpha [ONE: Queue work]"
    assert rows[1]["from_revision"] == added["item"]["revision"]
    assert rows[1]["to_revision"] == claimed["item"]["revision"]
    assert rows[2]["from_holder"] == "alpha" and rows[2]["to_holder"] is None
    assert rows[2]["from_expires_at"] == claimed["item"]["expires_at"]
    assert rows[-1]["to_revision"] == completed["item"]["revision"]


@pytest.mark.parametrize("identifier", ["BL-AUTH", "BL-TOKEN", "BL-SECRET", "BL-CREDENTIAL"])
def test_queue_labels_preserve_separately_validated_components(make_store, identifier):
    from aegis_core import events
    (make_store / ".aegis" / "team.json").write_text(
        json.dumps({"v": 1, "lanes": {"docs": ["src/**"]}}), encoding="utf-8")
    added = queue.add(make_store, item(identifier, title="Update guide"), now=100)
    assert not added["refused"]
    unclaimed_label = identifier + ": Update guide"
    claimed_label = "docs [" + unclaimed_label + "]"
    assert added["item"]["label"] == unclaimed_label
    claimed = claim(make_store, added["item"]["revision"], identifier, lane="docs")
    assert not claimed["refused"] and claimed["item"]["label"] == claimed_label
    assert queue.list(make_store, now=102)["items"][0]["label"] == claimed_label
    assert queue.audit(make_store, now=102)["items"][0]["label"] == claimed_label
    released = queue.release(make_store, identifier, expect=claimed["item"]["revision"], lane="docs", now=102)
    assert not released["refused"] and released["item"]["label"] == unclaimed_label
    reclaimed = claim(make_store, released["item"]["revision"], identifier, lane="docs", now=103)
    completed = queue.done(make_store, identifier, expect=reclaimed["item"]["revision"], lane="docs", now=104)
    assert not completed["refused"] and completed["item"]["label"] == claimed_label
    receipts = [row["detail"] for row in events.read(make_store).rows if row["detail"].get("queue") is True]
    assert [row["label"] for row in receipts] == [unclaimed_label] + [claimed_label] * 4


@pytest.mark.parametrize("field", ["id", "milestone", "lane"])
def test_secret_identifiers_refuse_before_acceptance(make_store, field):
    secret = "sk-" + "a" * 24
    if field == "id":
        result = queue.add(make_store, item(secret), now=100)
        assert result["reason"] == "invalid_item"
    elif field == "milestone":
        result = queue.add(make_store, item(hold_until=[{"kind": "milestone", "name": secret}]), now=100)
        assert result["reason"] == "invalid_item"
    else:
        revision = add(make_store)
        result = claim(make_store, revision, lane=secret)
        assert result["reason"] == "invalid_arguments"
    assert secret not in json.dumps(result)
    assert not queue.list(make_store, now=101)["refused"]

@pytest.mark.parametrize("size", [513, 4096])
def test_constraints_remain_complete_through_all_views_and_transitions(make_store, size):
    text = "x" * size
    value = item(hold=text, scope_rulings=[text], invariants=[text])
    added = queue.add(make_store, value, now=100)
    assert not added["refused"]
    for row in [added["item"], queue.list(make_store, now=101)["items"][0],
                queue.audit(make_store, now=101)["items"][0]]:
        assert row["hold"] == text and row["scope_rulings"] == [text] and row["invariants"] == [text]
    # Judgment holds deliberately refuse claims; the same validated constraints
    # without a hold must survive every claimed/released/completed response.
    revision = add(make_store, "TWO", paths=["docs/**"], scope_rulings=[text], invariants=[text])
    claimed = claim(make_store, revision, identifier="TWO")
    released = queue.release(make_store, "TWO", expect=claimed["item"]["revision"], lane="alpha", now=102)
    claimed = claim(make_store, released["item"]["revision"], identifier="TWO", now=103)
    completed = queue.done(make_store, "TWO", expect=claimed["item"]["revision"], lane="alpha", now=104)
    for result in [released, claimed, completed]:
        assert not result["refused"], result
        assert result["item"]["scope_rulings"] == [text] and result["item"]["invariants"] == [text]


@pytest.mark.parametrize("policy", [b"\xef\xbb\xbf{\"v\":1,\"lanes\":{\"alpha\":[\"src/**\"]}}",
    json.dumps({"v": 1, "lanes": {"lane%d" % i: ["src/**"] for i in range(300)}}).encode()], ids=["bom", "many-lanes"])
def test_team_policy_uses_its_own_parser(make_store, policy):
    (make_store / ".aegis" / "team.json").write_bytes(policy)
    revision = add(make_store)
    listed = queue.list(make_store, now=101)
    assert not listed["refused"], listed
    lane = "alpha" if policy.startswith(b"\xef") else "lane0"
    assert not claim(make_store, revision, lane=lane)["refused"]


@pytest.mark.parametrize("policy", [b"{", b"{}", b'{"v":1}', b'{"v":1,"lanes":{}}',
    b"x" * (team.MAX_CONFIG_BYTES + 1),
    json.dumps({"v": 1, "lanes": {"sk-" + "a" * 24: ["src/**"]}}).encode()],
    ids=["syntax", "missing-version", "missing-lanes", "empty-lanes", "oversized", "secret-lane"])
def test_bad_policy_is_only_a_coordinator_claim_blocker(make_store, policy):
    (make_store / ".aegis" / "team.json").write_bytes(policy)
    revision = add(make_store)
    listed = queue.list(make_store, now=101)
    assert not listed["refused"], listed
    audited = queue.audit(make_store, now=101)
    assert not audited["refused"]
    assert [finding["code"] for finding in audited["findings"]] == ["WAITING_ONLY_COORDINATOR"]
    result = claim(make_store, revision)
    assert result["reason"] == "blocked"
    assert result["blockers"][0]["reason"] == "coordinator"
    assert "team.json" in result["blockers"][0]["next_action"]
    assert "queue state" not in json.dumps(result)
    (make_store / ".aegis" / "team.json").write_text(
        json.dumps({"v": 1, "lanes": {"alpha": ["src/**"]}}), encoding="utf-8")
    assert not claim(make_store, revision)["refused"]


def test_done_rows_do_not_count_toward_live_cap(make_store):
    add(make_store)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    seed = json.loads(path.read_text())
    row = seed["items"].pop("ONE")
    # Owner-managed seed document at the documented persistence boundary.
    for index in range(256):
        identifier = "ITEM%d" % index
        seed["items"][identifier] = {**row, "item": {**row["item"], "id": identifier}}
    path.write_text(json.dumps(seed), encoding="utf-8")
    result = queue.add(make_store, item("OVER"), now=100)
    assert result["reason"] == "queue_live_limit"
    claimed = claim(make_store, row["revision"], identifier="ITEM0")
    assert not claimed["refused"]
    assert not queue.done(make_store, "ITEM0", expect=claimed["item"]["revision"], lane="alpha", now=102)["refused"]
    assert not queue.add(make_store, item("OVER"), now=103)["refused"]
    assert len(queue.list(make_store, now=104)["items"]) == 256
    assert len(queue.list(make_store, include_done=True, now=104)["items"]) == 257


def test_audit_requires_judgment_hold_and_live_claim_does_not_block_itself(make_store):
    revision = add(make_store, hold_until=[{"kind": "lease_free", "paths": ["src/**"]}])
    assert queue.audit(make_store, now=101)["findings"] == []
    claimed = claim(make_store, revision)
    assert not claimed["refused"]
    listed = queue.list(make_store, now=102)
    assert listed["items"][0]["conditions_met"] is True


@pytest.mark.parametrize("existing_lease", [False, True], ids=["empty-metrics", "lease-metrics"])
def test_queue_receipts_do_not_change_lease_metrics(make_store, existing_lease):
    if existing_lease:
        team.claim(make_store, "alpha", ["src/**"], owner="owner", now=100)
        with pytest.raises(team.LeaseRefused, match="overlap"):
            team.claim(make_store, "beta", ["src/**"], owner="owner", now=100)
    before = team.event_counts(make_store)
    revision = add(make_store)
    claimed = claim(make_store, revision)
    assert not claimed["refused"]
    released = queue.release(make_store, "ONE", expect=claimed["item"]["revision"], lane="alpha", now=102)
    assert not released["refused"]
    reclaimed = claim(make_store, released["item"]["revision"], now=103)
    assert not reclaimed["refused"]
    completed = queue.done(make_store, "ONE", expect=reclaimed["item"]["revision"], lane="alpha", now=104)
    assert not completed["refused"]
    assert team.event_counts(make_store) == before


def test_live_claim_ignores_only_its_holders_repository_lease(make_store):
    root = make_store
    revision = add(root, hold_until=[{"kind": "lease_free", "paths": ["src/**"]}])
    claimed = claim(root, revision)
    assert not claimed["refused"]
    own = team.claim(root, "alpha", ["src/**"], owner="owner", now=102)
    listed = queue.list(root, now=103)["items"][0]
    assert listed["conditions_met"] is True and listed["blockers"] == []
    assert queue.audit(root, now=103)["items"][0]["conditions_met"] is True
    team.release(root, "alpha", own.oid, caller="owner")
    other = team.claim(root, "beta", ["src/**"], owner="owner", now=104)
    listed = queue.list(root, now=105)["items"][0]
    assert listed["conditions_met"] is False
    assert [block["reason"] for block in listed["blockers"]] == ["lease_free"]
    assert listed["blockers"][0]["next_action"] == "Wait for the covering live leases to expire or be released."
    team.release(root, "beta", other.oid, caller="owner")
    assert queue.list(root, now=106)["items"][0]["conditions_met"] is True
    team.claim(root, "alpha", ["src/**"], owner="owner", now=107)
    expired = queue.list(root, now=111)["items"][0]
    assert expired["lease_expired"] is True and expired["conditions_met"] is False


def test_same_lane_is_busy_and_none_capabilities_refuses(make_store):
    revision = add(make_store)
    other = add(make_store, "TWO", paths=["docs/**"])
    assert queue.claim(make_store, "ONE", expect=revision, lane="alpha",
                       capabilities=None, now=101)["reason"] == "invalid_arguments"
    assert not claim(make_store, revision)["refused"]
    assert claim(make_store, other, identifier="TWO")["reason"] == "lane_busy"


def test_mutation_without_lease_observation_and_event_failure_retry(make_store, monkeypatch):
    from aegis_core import events
    revision = add(make_store)
    claimed = claim(make_store, revision)
    def broken(*args, **kwargs):
        raise gitsafe.GitError("untrusted")
    from aegis_core import gitsafe
    monkeypatch.setattr(queue, "team", SimpleNamespace(**{**vars(team), "read_leases": broken}))
    monkeypatch.setattr(queue, "events", SimpleNamespace(try_append=lambda *a, **k: OSError("token=private-value")))
    added = queue.add(make_store, item("TWO", hold_until=[{"kind": "lease_free", "paths": ["docs/**"]}]), now=102)
    assert not added["refused"] and added["warnings"][0]["reason"] == "event_not_recorded"
    released = queue.release(make_store, "ONE", expect=claimed["item"]["revision"], lane="alpha", now=102)
    assert not released["refused"] and "private-value" not in json.dumps(released)
    assert queue.release(make_store, "ONE", expect=claimed["item"]["revision"], lane="alpha", now=102)["reason"] == "stale_revision"
    monkeypatch.setattr(queue, "team", team)
    monkeypatch.setattr(queue, "events", events)
    assert not queue.list(make_store, now=103)["refused"]

def race_finish(arguments):
    root, verb, revision = arguments
    return getattr(queue, verb)(root, "ONE", expect=revision, lane="alpha", now=102)


@pytest.mark.parametrize("verb", ["release", "done"])
def test_concurrent_finishes_emit_one_transition(make_store, verb):
    from aegis_core import events
    revision = add(make_store)
    claimed = claim(make_store, revision)
    with ProcessPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(race_finish, [(make_store, verb, claimed["item"]["revision"])] * 2, timeout=30))
    assert sorted(result["refused"] for result in results) == [False, True]
    assert next(result for result in results if result["refused"])["reason"] == "stale_revision"
    receipts = [row["detail"] for row in events.read(make_store).rows
                if row["detail"].get("queue") and row["detail"]["action"] == verb]
    assert len(receipts) == 1
    assert receipts[0]["from_revision"] == claimed["item"]["revision"]
    assert receipts[0]["to_revision"] == next(result for result in results if not result["refused"])["item"]["revision"]
    assert receipts[0]["to_holder"] is None and receipts[0]["expires_at"] is None

def test_existing_repository_lanes_over_capacity_refuse_until_release(make_store):
    root = make_store
    alpha = team.claim(root, "alpha", ["/src/"], owner="owner", now=100)
    beta = team.claim(root, "beta", ["/docs/"], owner="owner", now=100)
    revision = add(root)
    result = claim(root, revision)
    assert result["reason"] == "capacity_full"
    team.release(root, "beta", beta.oid, caller="owner")
    assert not claim(root, revision, now=102)["refused"]
    assert alpha.oid


def test_added_dependencies_and_unobserved_lease_conditions_are_visible(make_store):
    result = queue.add(make_store, item(after=["MISSING"]), now=100)
    assert not result["refused"]
    assert result["item"]["conditions_met"] is False
    assert result["item"]["blockers"][0]["reason"] == "after"
    assert result["item"]["blockers"][0]["next_action"]
    prerequisite = add(make_store, "MISSING", paths=["docs/**"])
    claimed = claim(make_store, prerequisite, identifier="MISSING")
    completed = queue.done(make_store, "MISSING", expect=claimed["item"]["revision"], lane="alpha", now=102)
    assert not completed["refused"]
    assert not claim(make_store, result["item"]["revision"], now=103)["refused"]
    held = queue.add(make_store, item("HELD", paths=["misc/**"],
        hold_until=[{"kind": "lease_free", "paths": ["misc/**"]}]), now=104)
    assert held["item"]["conditions_met"] is False
    assert held["item"]["blockers"][0]["reason"] == "lease_free"
    assert "list" in held["item"]["blockers"][0]["next_action"]


def test_concurrent_disjoint_claims_enforce_writer_capacity(make_store):
    first = add(make_store, paths=["/src/one.py"])
    second = add(make_store, "TWO", paths=["/docs/one.md"])
    with ProcessPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(race_scoped_claim, [(make_store, first, "ONE", "alpha"),
            (make_store, second, "TWO", "beta")], timeout=30))
    assert sorted(result["refused"] for result in results) == [False, True]
    assert next(result for result in results if result["refused"])["reason"] == "capacity_full"


@pytest.mark.parametrize("spelling", [r"\\?\C:..\ws", r"1:..\ws", r"\\srv\..\ws",
                                     r"\\..\ws\x", r"\\.\..\ws"])
@pytest.mark.parametrize("verb", ["list", "audit", "add", "compact", "claim", "release", "done"])
def test_prefix_parent_components_refuse_before_io(monkeypatch, spelling, verb):
    monkeypatch.setattr(queue, "descriptor_supported", lambda: False)
    assert queue.valid_workspace_spelling(spelling) is False
    kwargs = {"item": item()} if verb == "add" else {}
    if verb in ("claim", "release", "done"):
        kwargs.update(identifier="ONE", expect="0" * 64, lane="alpha")
    result = getattr(queue, verb)(spelling, **kwargs)
    assert result["reason"] == "invalid_arguments" and result["exit_code"] == 2
    assert all(spelling not in value for value in result.values() if isinstance(value, str))


@pytest.mark.parametrize("text", ["Auth: update login flow", "Fix token: refresh handling", "token=private-value"])
@pytest.mark.parametrize("field", ["title", "hold", "scope_rulings", "invariants"])
def test_credential_text_has_rephrase_guidance_and_no_echo(make_store, text, field):
    value = item(**{field: [text] if field in ("scope_rulings", "invariants") else text})
    parsed = queue.parse_item(json.dumps(value))
    result = queue.add(make_store, value, now=100)
    for response in (parsed, result):
        assert response["reason"] == "credential_like_text"
        assert "rephrase" in response["next_action"].lower()
        assert all(text not in value for value in response.values() if isinstance(value, str))
    assert result["exit_code"] == 2
    assert not (make_store / ".aegis" / "state" / "team-queue.json").exists()
    assert not queue.add(make_store, item(title="Update login flow"), now=101)["refused"]


@pytest.mark.parametrize("mode", ["foreign", "own", "expired", "disjoint", "unreadable"])
def test_claim_preflight_rechecks_repository_leases_after_list(make_store, mode):
    revision = add(make_store)
    assert queue.list(make_store, now=100)["items"][0]["conditions_met"]
    lane = "alpha" if mode == "own" else "beta"
    lease = team.claim(make_store, lane, ["docs/**" if mode == "disjoint" else "src/**"],
                       owner="owner", now=90 if mode == "expired" else 100, ttl_s=10)
    if mode == "unreadable":
        from aegis_core import gitsafe
        blob = gitsafe.write_blob(make_store, b"{}")
        gitsafe.update_ref(make_store, team.lane_ref(lane), blob, lease.oid)
    result = claim(make_store, revision)
    if mode in ("foreign", "unreadable"):
        assert result["reason"] == "blocked"
        assert result["blockers"][0]["reason"] == "foreign_lease"
        assert queue.list(make_store, now=102)["items"][0]["revision"] == revision
        current = team.read_leases(make_store)
        oid = current.unreadable[0].oid if mode == "unreadable" else lease.oid
        team.release(make_store, lane, oid, caller="owner")
        assert not claim(make_store, revision, now=103)["refused"]
    elif mode == "disjoint":
        assert result["reason"] == "capacity_full"
    else:
        assert not result["refused"], result


@pytest.mark.parametrize("path,allowed", [("src/a.py", True), ("docs/a.md", False)])
def test_brief_paths_must_be_admitted_at_add(make_store, path, allowed):
    value = item(brief_paths=[path])
    parsed = queue.parse_item(json.dumps(value))
    result = queue.add(make_store, value, now=100)
    if allowed:
        assert not result["refused"]
        assert not claim(make_store, result["item"]["revision"])["refused"]
    else:
        for response in (parsed, result):
            assert response["reason"] == "brief_outside_scope"
            assert response["next_action"]
        assert result["exit_code"] == 2
        assert not (make_store / ".aegis" / "state" / "team-queue.json").exists()
        assert not queue.add(make_store, item(brief_paths=["src/a.py"]), now=101)["refused"]


@pytest.mark.parametrize("paths", [["../escape"], ["src/*.py"], ["src/one\ntwo.py"], ["x"] * 129, "src/a.py"])
def test_malformed_brief_paths_refuse_before_storage(make_store, paths):
    result = queue.add(make_store, item(brief_paths=paths), now=100)
    assert result["reason"] == "invalid_item" and result["exit_code"] == 2
    assert not (make_store / ".aegis" / "state" / "team-queue.json").exists()


@pytest.mark.parametrize("mode,code", [("missing", "LANE-NO-LEASE"), ("expired", "LANE-NO-LEASE"),
                                      ("mismatch", "LEASE-BRANCH-MISMATCH"), ("matching", None)])
def test_audit_claim_lease_branch_and_retry(make_store, mode, code):
    revision = add(make_store)
    claimed = claim(make_store, revision)
    assert not claimed["refused"], claimed
    branch = "refs/heads/lane/alpha"
    if mode != "missing":
        team.claim(make_store, "alpha", ["src/**"], owner="owner",
                   branch="other" if mode == "mismatch" else branch,
                   now=90 if mode == "expired" else 100, ttl_s=10)
    audited = queue.audit(make_store, now=102)
    assert not audited["refused"], audited
    assert [row["code"] for row in audited["findings"]] == ([] if code is None else [code])
    assert all(row["refused"] and row["reason"] and row["next_action"] for row in audited["findings"])
    assert not queue.release(make_store, "ONE", expect=claimed["item"]["revision"], lane="alpha", now=103)["refused"]
    assert queue.audit(make_store, now=104)["findings"] == []


def finish_one(root, identifier="ONE"):
    revision = add(root, identifier)
    claimed = claim(root, revision, identifier)
    assert not claimed["refused"], claimed
    completed = queue.done(root, identifier, expect=claimed["item"]["revision"], lane="alpha", now=102)
    assert not completed["refused"], completed


def test_completed_filter_and_compaction_preserve_live_dependencies(make_store):
    finish_one(make_store)
    finish_one(make_store, "UNUSED")
    revision = add(make_store, "TWO", after=["ONE"])
    assert [row["id"] for row in queue.list(make_store, now=103)["items"]] == ["TWO"]
    assert len(queue.list(make_store, include_done=True, now=103)["items"]) == 3
    path = make_store / ".aegis" / "state" / "team-queue.json"
    size = path.stat().st_size
    compacted = queue.compact(make_store, now=103)
    assert not compacted["refused"] and compacted["removed_count"] == 1
    assert path.stat().st_size < size
    assert compacted["retained_done_count"] == 1
    assert queue.compact(make_store, now=104)["removed_count"] == 0
    assert not claim(make_store, revision, "TWO", now=104)["refused"]


def race_compact(root):
    return queue.compact(root, now=103)


def test_compaction_concurrency_failure_and_retry(make_store, monkeypatch):
    finish_one(make_store)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    before = path.read_bytes()
    def failed(*args, **kwargs):
        raise OSError("token=private-value")
    monkeypatch.setattr(queue, "atomic_write_bytes", failed)
    refused = queue.compact(make_store, now=103)
    assert refused["reason"] == "queue_io_unavailable" and refused["exit_code"] == 1
    assert "private-value" not in json.dumps(refused)
    assert path.read_bytes() == before
    monkeypatch.setattr(queue, "atomic_write_bytes", atomicio.atomic_write_bytes)
    with ProcessPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(race_compact, [make_store] * 2, timeout=30))
    assert all(not row["refused"] for row in results)
    assert sorted(row["removed_count"] for row in results) == [0, 1]
    assert queue.list(make_store, include_done=True, now=104)["items"] == []


@pytest.mark.parametrize("value", [None, 0, "true", [], {}])
def test_include_done_is_strict_before_platform(monkeypatch, value):
    monkeypatch.setattr(queue, "descriptor_supported", lambda: False)
    result = queue.list("/workspace", include_done=value)
    assert result["reason"] == "invalid_arguments" and result["exit_code"] == 2


@pytest.mark.parametrize("verb", ["list", "audit", "compact"])
@pytest.mark.parametrize("data,reason", [(b"{", "invalid_queue_state"),
    (b" " * (queue.MAX_BYTES + 1), "queue_size_limit")], ids=["malformed", "oversized"])
def test_new_observation_and_compaction_failures_preserve_state(make_store, verb, data, reason):
    add(make_store)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    path.write_bytes(data)
    refused = getattr(queue, verb)(make_store, now=101)
    assert refused["reason"] == reason and refused["exit_code"] == 1
    assert path.read_bytes() == data


@pytest.mark.parametrize("branch", ["private-value\ninjected", "private-value topic", "x" * 201,
    "refs/tags/private-value", "refs/heads/HEAD", "refs/heads/", "HEAD", 1, ""])
def test_branch_input_failure_is_fixed_and_retryable(make_store, branch):
    revision = add(make_store)
    result = claim(make_store, revision, branch=branch)
    assert result["reason"] == "invalid_arguments" and result["exit_code"] == 2
    assert "private-value" not in json.dumps(result)
    assert not claim(make_store, revision)["refused"]


def test_compact_empty_unsupported_lock_timeout_and_event_failure(make_store, monkeypatch):
    from aegis_core import events
    root = make_store
    assert queue.compact(root, now=100)["removed_count"] == 0
    assert not (root / ".aegis" / "state" / "team-queue.json").exists()
    supported = queue.descriptor_supported
    monkeypatch.setattr(queue, "descriptor_supported", lambda: False)
    assert queue.compact(root, now=100)["reason"] == "unsupported_platform"
    monkeypatch.setattr(queue, "descriptor_supported", supported)
    def timeout(*args, **kwargs):
        raise storage.LockTimeoutError("token=private-value")
    monkeypatch.setattr(queue, "locked", timeout)
    assert queue.compact(root, now=100)["reason"] == "queue_lock_timeout"
    monkeypatch.setattr(queue, "locked", storage.locked)
    finish_one(root)
    monkeypatch.setattr(queue, "events", SimpleNamespace(try_append=lambda *a, **k: OSError("private-value")))
    result = queue.compact(root, now=103)
    assert not result["refused"] and result["warnings"][0]["reason"] == "event_not_recorded"
    assert "private-value" not in json.dumps(result)
    monkeypatch.setattr(queue, "events", events)
    assert queue.compact(root, now=104)["removed_count"] == 0


@pytest.mark.parametrize("branch", ["lane/alpha", "refs/heads/lane/alpha"])
def test_claim_branch_comes_from_lane_and_audit_never_uses_head(make_store, branch):
    revision = add(make_store)
    claimed = claim(make_store, revision, branch=branch)
    assert not claimed["refused"], claimed
    assert claimed["item"]["branch"] == "lane/alpha"
    team.claim(make_store, "alpha", ["src/**"], owner="owner", branch="lane/alpha", now=100)
    subprocess.run(["git", "symbolic-ref", "HEAD", "refs/heads/main"], cwd=make_store, check=True)
    assert queue.audit(make_store, now=102)["findings"] == []


@pytest.mark.parametrize("mode", ["null", "absent"])
def test_unknown_claim_branch_cannot_be_replaced_by_later_checkout(make_store, mode):
    # This history belongs entirely to the temporary repo, not the source checkout.
    subprocess.run(["git", "symbolic-ref", "HEAD", "refs/heads/seed"], cwd=make_store, check=True)
    subprocess.run(["git", "-c", "user.name=Queue Test", "-c", "user.email=queue@example.test",
                    "commit", "--allow-empty", "-q", "-m", "seed"], cwd=make_store, check=True)
    subprocess.run(["git", "checkout", "--detach", "-q"], cwd=make_store, check=True)
    revision = add(make_store)
    claimed = claim(make_store, revision, branch=None)
    assert not claimed["refused"], claimed
    assert claimed["item"].get("branch") is None
    if mode == "absent":
        path = make_store / ".aegis" / "state" / "team-queue.json"
        document = json.loads(path.read_text())
        document["items"]["ONE"].pop("branch", None)
        path.write_text(json.dumps(document), encoding="utf-8")
    subprocess.run(["git", "checkout", "-q", "-b", "main"], cwd=make_store, check=True)
    team.claim(make_store, "alpha", ["src/**"], owner="owner", branch="main", now=100)
    result = queue.audit(make_store, now=102)
    assert [row["code"] for row in result["findings"]] == ["CLAIM-BRANCH-UNKNOWN"]
    assert result["findings"][0]["next_action"]


def test_unrecorded_lease_branch_is_unknown_not_mismatch(make_store):
    revision = add(make_store)
    assert not claim(make_store, revision)["refused"]
    team.claim(make_store, "alpha", ["src/**"], owner="owner", now=100)
    result = queue.audit(make_store, now=102)
    assert [row["code"] for row in result["findings"]] == ["LEASE-BRANCH-UNKNOWN"]


def test_unreadable_lease_audit_has_a_working_recovery_action(make_store):
    from aegis_core import gitsafe
    revision = add(make_store)
    assert not claim(make_store, revision)["refused"]
    bad = gitsafe.write_blob(make_store, b"{}")
    gitsafe.update_ref(make_store, team.lane_ref("alpha"), bad, None)
    result = queue.audit(make_store, now=102)
    assert [row["code"] for row in result["findings"]] == ["LEASE-UNREADABLE"]
    assert "release" in result["findings"][0]["next_action"]
    team.release(make_store, "alpha", bad, caller="owner")
    team.claim(make_store, "alpha", ["src/**"], owner="owner", branch="lane/alpha", now=100)
    assert queue.audit(make_store, now=103)["findings"] == []


def test_compacted_ids_satisfy_future_dependencies_and_cannot_be_reused(make_store):
    from aegis_core import events
    finish_one(make_store)
    compacted = queue.compact(make_store, now=103)
    assert compacted["removed_count"] == 1
    listed = queue.list(make_store, include_done=True, now=104)
    assert listed["completed_ids"] == ["ONE"]
    refused = queue.add(make_store, item(), now=104)
    assert refused["reason"] == "item_exists" and "include-done" in refused["next_action"]
    assert claim(make_store, "0" * 64)["reason"] == "item_done"
    revision = add(make_store, "TWO", after=["ONE"])
    assert not claim(make_store, revision, "TWO", now=104)["refused"]
    receipts = [row["detail"] for row in events.read(make_store).rows if row["detail"].get("action") == "compact"]
    assert receipts[0]["removed_ids"] == ["ONE"]
    assert queue.compact(make_store, now=105)["removed_count"] == 0


def test_refusal_guidance_names_completed_filter_and_compact(make_store):
    finish_one(make_store)
    result = queue.add(make_store, item(), now=103)
    assert "include-done" in result["next_action"]
    path = make_store / ".aegis" / "state" / "team-queue.json"
    path.write_bytes(b" " * (queue.MAX_BYTES + 1))
    assert "aegis team queue compact" in queue.list(make_store)["next_action"]


def test_completion_history_limit_preserves_state_and_retry(make_store):
    finish_one(make_store)
    assert queue.compact(make_store, now=103)["removed_ids"] == ["ONE"]
    finish_one(make_store, "TWO")
    path = make_store / ".aegis" / "state" / "team-queue.json"
    state = json.loads(path.read_text())
    state["completed"].update({"OLD%d" % i: True for i in range(queue.MAX_COMPLETED - 1)})
    path.write_text(json.dumps(state), encoding="utf-8")
    before = path.read_bytes()
    for moment in (104, 105):
        refused = queue.compact(make_store, now=moment)
        assert refused["reason"] == "queue_history_limit" and refused["exit_code"] == 1
        assert path.read_bytes() == before
    listed = queue.list(make_store, include_done=True, now=106)
    assert len(listed["completed_ids"]) == queue.MAX_COMPLETED
    assert listed["items"][0]["id"] == "TWO" and listed["items"][0]["state"] == "done"
    revision = add(make_store, "THREE", after=["ONE"])
    assert not claim(make_store, revision, "THREE", now=106)["refused"]


@pytest.mark.parametrize("completed", [["OLD"], {"OLD": False}, {"../private-value": True},
    {"ONE": True}, {"OLD%d" % i: True for i in range(queue.MAX_COMPLETED + 1)}],
    ids=["wrong-type", "wrong-marker", "bad-id", "overlaps-body", "over-limit"])
def test_invalid_completion_history_has_fixed_refusal(make_store, completed):
    add(make_store)
    path = make_store / ".aegis" / "state" / "team-queue.json"
    state = json.loads(path.read_text())
    state["completed"] = completed
    path.write_text(json.dumps(state), encoding="utf-8")
    result = queue.list(make_store, now=101)
    assert result["reason"] == "invalid_queue_state" and result["exit_code"] == 1
    assert "private-value" not in json.dumps(result)


def race_branch_claim(arguments):
    root, revision, branch = arguments
    return claim(root, revision, branch=branch)


def test_concurrent_claims_record_only_the_winners_branch(make_store):
    revision = add(make_store)
    with ProcessPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(race_branch_claim, [(make_store, revision, "lane/a"),
                                                  (make_store, revision, "lane/b")], timeout=30))
    assert sorted(result["refused"] for result in results) == [False, True]
    winner = next(result for result in results if not result["refused"])
    assert next(result for result in results if result["refused"])["reason"] == "stale_revision"
    listed = queue.list(make_store, now=102)["items"][0]
    assert listed["branch"] == winner["item"]["branch"]
    team.claim(make_store, "alpha", ["src/**"], owner="owner", branch=listed["branch"], now=100)
    assert queue.audit(make_store, now=102)["findings"] == []


@pytest.mark.parametrize("branch,valid", [(None, True), ("lane/x", True),
    ("refs/heads/lane/x", True), ("x" * 200, True), ("refs/heads/" + "x" * 189, True),
    ("x" * 201, False), ("refs/heads/" + "x" * 191, False),
    ("private-value\ninjected", False), ("", False), ({}, False)],
    ids=["unknown", "short", "full", "short-limit", "full-limit", "short-over", "full-over", "multiline", "empty", "type"])
def test_branch_validation_precedes_platform_probe(tmp_path, monkeypatch, branch, valid):
    monkeypatch.setattr(queue, "descriptor_supported", lambda: False)
    result = queue.claim(tmp_path, "ONE", expect="0" * 64, lane="alpha", branch=branch, now=100)
    assert result["reason"] == ("unsupported_platform" if valid else "invalid_arguments")
    assert result["exit_code"] == (1 if valid else 2)
    assert "private-value" not in json.dumps(result)


@pytest.mark.parametrize("field", ["after", "capabilities"])
def test_identifier_fields_refuse_before_credential_heuristic(make_store, field):
    value = item(**{field: ["Auth: update login flow"]})
    for result in (queue.parse_item(json.dumps(value)), queue.add(make_store, value, now=100)):
        assert result["reason"] == "invalid_item" and result["next_action"]
        assert "Auth: update login flow" not in json.dumps(result)
    assert not (make_store / ".aegis" / "state" / "team-queue.json").exists()


@pytest.mark.parametrize("branch,accepted", [
    ("feature/c++", True), ("fix/issue#12", True), ("user@topic", True), ("feat/naïve", True),
    ("x", True), ("refs/heads/x", True), ("x" * 200, True), ("x" * 201, False),
    ("refs/heads/" + "x" * 189, True), ("refs/heads/" + "x" * 191, False),
    ("../label", True), ("label..x", True), ("label.lock", True), ("label//x", True),
    ("label/.", True), ("label?x", True), ("-label", True),
    ("private-value topic", False), ("private-value\ninjected", False),
    ("private-value\rtrailer", False), ("private-value\tfield", False),
    ("private-value\x00", False), ("private-value\x1b[31m", False),
    ("private-value\x85", False), ("private-value\u2028line", False),
    ("", False), (1, False),
], ids=["plus", "hash", "at", "unicode", "short", "full", "limit", "over-limit",
        "full-limit", "full-over-limit", "parent-label", "dots-label", "lock-label",
        "empty-component-label", "dot-component-label", "question-label", "leading-hyphen-label",
        "space", "newline", "carriage-return", "tab", "nul", "ansi", "c1", "line-separator", "empty", "type"])
def test_queue_and_lease_claim_share_branch_predicate(make_store, branch, accepted):
    revision = add(make_store)
    if accepted:
        lease = team.claim(make_store, "alpha", ["src/**"], owner="owner", branch=branch, now=100)
        assert lease.lease.branch == branch
    else:
        with pytest.raises(team.TeamUsageError, match="^branch must be 1 to 200 characters with no spaces or control characters$"):
            team.claim(make_store, "alpha", ["src/**"], owner="owner", branch=branch, now=100)
    result = claim(make_store, revision, branch=branch)
    assert result["refused"] is not accepted, result
    if accepted:
        normalized = branch.removeprefix("refs/heads/")
        assert result["item"]["branch"] == normalized
        assert queue.list(make_store, now=102)["items"][0]["branch"] == normalized
        assert queue.audit(make_store, now=102)["findings"] == []
    else:
        assert result["reason"] == "invalid_arguments" and result["exit_code"] == 2
        assert "private-value" not in json.dumps(result)
        assert not claim(make_store, revision)["refused"]


@pytest.mark.parametrize("lease_branch,queue_branch", [("refs/heads/x", "x"), ("x", "refs/heads/x")])
def test_audit_normalizes_both_lease_and_queue_local_refs(make_store, lease_branch, queue_branch):
    revision = add(make_store)
    team.claim(make_store, "alpha", ["src/**"], owner="owner", branch=lease_branch, now=100)
    assert not claim(make_store, revision, branch=queue_branch)["refused"]
    assert queue.audit(make_store, now=102)["findings"] == []


@pytest.mark.parametrize("branch", ["refs/tags/x", "refs/remotes/origin/x", "HEAD", "refs/heads/HEAD"])
def test_queue_refuses_nonlocal_or_head_labels_even_when_lease_accepts(make_store, branch):
    revision = add(make_store)
    team.claim(make_store, "alpha", ["src/**"], owner="owner", branch=branch, now=100)
    result = claim(make_store, revision, branch=branch)
    assert result["reason"] == "invalid_arguments" and result["exit_code"] == 2
    assert branch not in json.dumps(result)
    assert not claim(make_store, revision, branch="x")["refused"]
    audited = queue.audit(make_store, now=102)
    assert [row["code"] for row in audited["findings"]] == ["LEASE-BRANCH-UNKNOWN"]
    assert branch not in json.dumps(audited)


def test_legacy_prefixed_claim_branch_remains_readable(make_store):
    revision = add(make_store)
    assert not claim(make_store, revision)["refused"]
    path = make_store / ".aegis" / "state" / "team-queue.json"
    state = json.loads(path.read_text(encoding="utf-8"))
    state["items"]["ONE"]["branch"] = "refs/heads/lane/alpha"
    path.write_text(json.dumps(state), encoding="utf-8")
    team.claim(make_store, "alpha", ["src/**"], owner="owner", branch="lane/alpha", now=100)
    assert queue.list(make_store, now=102)["items"][0]["branch"] == "refs/heads/lane/alpha"
    assert queue.audit(make_store, now=102)["findings"] == []


def test_branch_display_redacts_each_returned_field(make_store):
    branch = "token=private-value"
    revision = add(make_store)
    team.claim(make_store, "alpha", ["src/**"], owner="owner", branch=branch, now=100)
    claimed = claim(make_store, revision, branch=branch)
    assert not claimed["refused"], claimed
    listed = queue.list(make_store, now=102)
    audited = queue.audit(make_store, now=102)
    for result in (claimed, listed, audited):
        assert "private-value" not in json.dumps(result)
    assert "REDACTED" in claimed["item"]["branch"]
    assert audited["findings"] == []


def stored_branch_item(root, branch, state):
    profile = root / ".aegis" / "team" / "profile.json"
    profile.parent.mkdir()
    profile.write_text(json.dumps({"version": 1, "run_config": {"limits": {"writers_max": 2}}}), encoding="utf-8")
    revision = add(root)
    second = add(root, "TWO", paths=["docs/**"])
    claimed = claim(root, revision)
    assert not claimed["refused"], claimed
    if state == "completed":
        assert not queue.done(root, "ONE", expect=claimed["item"]["revision"], lane="alpha", now=102)["refused"]
    path = root / ".aegis" / "state" / "team-queue.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    # Seed an older record at the documented persistence boundary, without
    # depending on commits or history in the source checkout.
    document["items"]["ONE"]["branch"] = branch
    path.write_text(json.dumps(document), encoding="utf-8")
    team.claim(root, "alpha", ["src/**"], owner="owner", branch="lane/alpha", now=100)
    team.claim(root, "beta", ["docs/**"], owner="owner", branch="lane/beta", now=100)
    return path, document["items"]["ONE"]["revision"], second, 112 if state == "expired" else 103


@pytest.mark.parametrize("branch,unsupported", [
    ("refs/heads/refs/tags/x", True), ("refs/heads/refs/heads/x", True),
    ("refs/heads/refs/remotes/origin/x", True), ("lane/alpha", False),
], ids=["nested-tag", "nested-head", "nested-remote", "valid"])
@pytest.mark.parametrize("state", ["active", "expired", "completed"])
@pytest.mark.parametrize("verb", ["list", "audit", "compact", "add", "claim", "release", "done"])
def test_stored_branch_isolated_from_queue_operations(make_store, branch, unsupported, state, verb):
    root = make_store
    path, revision, second, moment = stored_branch_item(root, branch, state)
    if verb == "list":
        result = queue.list(root, include_done=True, now=moment)
    elif verb == "add":
        result = queue.add(root, item("THREE", paths=["other/**"]), now=moment)
    elif verb == "claim":
        result = claim(root, second, "TWO", lane="beta", branch="lane/beta", now=moment)
    elif verb in ("release", "done"):
        result = getattr(queue, verb)(root, "ONE", expect=revision, lane="alpha", now=moment)
    else:
        result = getattr(queue, verb)(root, now=moment)
    expected_error = ("not_claimed" if state == "completed" else "lease_expired"
                      if state == "expired" and verb == "done" else None) if verb in ("release", "done") else None
    if expected_error:
        assert result["refused"] and result["reason"] == expected_error and result["exit_code"] == 1
    else:
        assert not result["refused"], result
    cleared = ((verb == "release" and state != "completed") or
               (verb == "done" and state == "active") or (verb == "compact" and state == "completed"))
    audited = queue.audit(root, now=moment)
    assert not audited["refused"], audited
    findings = audited["findings"]
    assert [row["code"] for row in findings] == (["CLAIM-BRANCH-UNSUPPORTED"] if unsupported and not cleared else [])
    if findings:
        assert findings[0]["item_id"] == "ONE" and findings[0]["reason"] == "claim_branch_unsupported"
        assert findings[0]["next_action"] and branch not in json.dumps(findings)
    persisted = json.loads(path.read_text(encoding="utf-8"))
    if not cleared:
        assert persisted["items"]["ONE"]["branch"] == branch
    if verb == "list":
        row = next(row for row in result["items"] if row["id"] == "ONE")
        assert row["branch"] == branch
        assert row.get("branch_supported", True) is not unsupported
    if unsupported and not cleared:
        if state == "completed":
            recovery = queue.compact(root, now=moment)
        else:
            recovery = queue.release(root, "ONE", expect=revision, lane="alpha", now=moment)
        assert not recovery["refused"], recovery
        assert queue.audit(root, now=moment)["findings"] == []


@pytest.mark.parametrize("branch", ["refs/heads/refs/tags/x", "refs/heads/refs/heads/x",
    "refs/heads/refs/remotes/origin/x"])
def test_new_claim_still_refuses_unsupported_stored_spellings(make_store, branch):
    revision = add(make_store)
    refused = claim(make_store, revision, branch=branch)
    assert refused["reason"] == "invalid_arguments" and refused["exit_code"] == 2
    assert branch not in json.dumps(refused)
    assert not claim(make_store, revision)["refused"]


@pytest.mark.parametrize("branch", ["private-value\ntrailer", "x" * 201, 1, {}, ["private-value"]],
    ids=["multiline", "over-label-limit", "integer", "object", "array"])
def test_malformed_stored_branch_is_per_item_not_queue_failure(make_store, branch):
    root = make_store
    path, revision, _, moment = stored_branch_item(root, branch, "active")
    result = queue.audit(root, now=moment)
    assert not result["refused"], result
    assert [row["code"] for row in result["findings"]] == ["CLAIM-BRANCH-UNSUPPORTED"]
    assert "private-value" not in json.dumps(result["findings"])
    assert json.loads(path.read_text(encoding="utf-8"))["items"]["ONE"]["branch"] == branch
    released = queue.release(root, "ONE", expect=revision, lane="alpha", now=moment)
    assert not released["refused"], released
    assert queue.audit(root, now=moment)["findings"] == []


@pytest.mark.parametrize("lease_state,lease_code", [
    ("missing", "LANE-NO-LEASE"), ("branchless", "LEASE-BRANCH-UNKNOWN"),
    ("unreadable", "LEASE-UNREADABLE"), ("healthy", None),
])
def test_unsupported_branch_preserves_independent_lease_findings(make_store, lease_state, lease_code):
    from aegis_core import gitsafe

    root = make_store
    branch = "refs/heads/refs/tags/private-value"
    path, _, _, moment = stored_branch_item(root, branch, "active")
    current = team.read_leases(root).get("alpha")
    team.release(root, "alpha", current.oid, caller="owner")
    if lease_state == "unreadable":
        bad = gitsafe.write_blob(root, b"{}")
        gitsafe.update_ref(root, team.lane_ref("alpha"), bad, None)
    elif lease_state != "missing":
        # A different healthy branch must not produce a mismatch when the
        # claim's stored branch evidence is unsupported.
        team.claim(root, "alpha", ["src/**"], owner="owner", now=100,
                   branch=None if lease_state == "branchless" else "other/branch")
    result = queue.audit(root, now=moment)
    assert not result["refused"], result
    findings = result["findings"]
    expected = ["CLAIM-BRANCH-UNSUPPORTED"] + ([lease_code] if lease_code else [])
    assert [row["code"] for row in findings] == expected
    assert all(row["item_id"] == "ONE" and row["lane"] == "alpha" and
               row["refused"] and row["reason"] and row["next_action"] for row in findings)
    assert "private-value" not in json.dumps(findings)
    assert json.loads(path.read_text(encoding="utf-8"))["items"]["ONE"]["branch"] == branch
