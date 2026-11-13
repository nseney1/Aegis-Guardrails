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


def claim(root, revision, identifier="ONE", lane="alpha", now=101, ttl_s=10):
    return queue.claim(root, identifier, expect=revision, lane=lane,
                       capabilities=["core"], ttl_s=ttl_s, now=now)


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
    assert spelling not in json.dumps(result)


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
    assert {row["reason"] for row in result["blockers"]} == {"milestone", "lease_free"}
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
    for verb, kwargs in [("list", {}), ("audit", {}), ("add", {"item": item()})]:
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
    assert len(queue.list(make_store, now=104)["items"]) == 257


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
