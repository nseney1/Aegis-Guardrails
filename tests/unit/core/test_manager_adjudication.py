"""Manager fitness from signatures made by a disposable owner in a separate Git process."""
import hashlib
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from aegis_core import gitsafe, manager
from aegis_core import manager_adjudication as adjudication
from aegis_core.fitness import for_rules
from aegis_core.manager import ManagerService
from aegis_core.manager_policy import ManagerError, canonical, digest
from aegis_core.manager_store import ManagerStore
from tests.conftest import run
from tests.helpers_humangate import Home, keygen, signing_ok
from tests.helpers_manager import git, manager_root, prepare


@pytest.fixture
def review(manager_root):
    if not signing_ok():
        pytest.skip("needs Git SSH commit signing")
    env = prepare(manager_root)
    env["owner_home"] = Home(manager_root / "owner-home").env
    env["service"] = ManagerService(env["config"], provenance={"transport": "test", "native_identity": None})
    env["pin"] = hashlib.sha256(env["config"].read_bytes()).hexdigest()
    candidate = env["service"].candidate(env["revision"])
    env["service"].activate(env["revision"], None, approve(env, candidate))
    return env


def scan(review):
    return review["service"].scan("handoff", review["context"])


def manifest(review, decisions, *, with_checkpoint=True, **changes):
    first = decisions[0]
    rule = first["rules"][0]
    changes.setdefault("audit_head", review["service"].status()["audit_head"])
    label = {"schema": "aegis.manager-label/v2", "workspace_id": first["workspace_id"],
             "episode_id": "artifact-review", "decision_refs": [item["decision_ref"] for item in decisions],
             "rule_id": rule["id"], "rule_revision": rule["revision"], "assessment": "helpful",
             "evidence_digest": hashlib.sha256(b"independent verification record").hexdigest(),
             "previous_anchor": None, "predecessor": None, **changes}
    if not with_checkpoint:
        del label["audit_head"]
    path = review["control"] / "adjudication" / "label.json"
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(canonical(label))
    git(review["control"], "add", "adjudication/label.json")
    git(review["control"], "commit", "--allow-empty", "-qm", "Review label manifest")
    return git(review["control"], "rev-parse", "HEAD")


def draft(review, revision):
    return adjudication.prepare(review["config"], review["pin"], revision)


def sign(review, statement, *, key=None, trailer=None):
    key = review["key"] if key is None else key
    message = "Owner reviews operational evidence\n\n" + (trailer or statement["required_trailer"])
    signed = run(["git", "-c", "user.name=Owner", "-c", "user.email=owner@example.invalid",
                  "-c", "gpg.format=ssh", "-c", "user.signingkey=" + str(key), "commit",
                  "--allow-empty", "--no-verify", "--cleanup=verbatim", "-S", "-qm", message],
                 cwd=review["control"], env=review["owner_home"], timeout=10)
    assert signed.returncode == 0, signed.stderr
    return git(review["control"], "rev-parse", "HEAD")


def approve(review, candidate):
    return {"statement": candidate["approval_statement"], "commit": sign(review, candidate)}


def project(review, anchor):
    return adjudication.verify(review["config"], review["pin"], anchor)


def totals(projection):
    row, = projection["by_revision"]
    return {key: row[key] for key in ("tp", "fp", "unresolved", "eligible")}


def test_rebuild_counts_owner_votes_and_measures_coverage_including_failures(review):
    service = review["service"]
    helpful, repeated, misleading, missing, ignored, unreviewed = [scan(review) for _ in range(6)]
    rule = helpful["rules"][0]
    for decision, outcome in [(helpful, "tp"), (misleading, "fail"), (unreviewed, "fp")]:
        ack = service.report(decision["decision_ref"], [rule["id"]], outcome, [], decision["decision_ref"])
        assert ack["fitness_credit"] == 0
        assert service.report(decision["decision_ref"], [rule["id"]], outcome, [], decision["decision_ref"]) == ack
    inputs = [SimpleNamespace(id=rule["id"])]
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def repo_fitness():
        return canonical({key: asdict(value) for key, value in for_rules(review["member"], inputs, now=now).items()})

    before = repo_fitness()
    audit = review["store"] / "audit.jsonl"
    audit_before = audit.read_bytes()
    positive = draft(review, manifest(review, [helpful, repeated]))
    anchor = sign(review, positive)
    anchor = sign(review, draft(review, manifest(review, [misleading], episode_id="failed-review",
                                                assessment="misleading", previous_anchor=anchor)))
    anchor = sign(review, draft(review, manifest(review, [missing], episode_id="missing-record",
                                                assessment="missing_evidence", evidence_digest=None,
                                                previous_anchor=anchor)))
    anchor = sign(review, draft(review, manifest(review, [ignored], episode_id="ignored-guidance",
                                                assessment="ignored_appropriate", previous_anchor=anchor)))
    result = project(review, anchor)
    assert totals(result) == {"tp": 1, "fp": 1, "unresolved": 3, "eligible": 5}
    assert result["by_action"] == [{"action": "handoff", "tp": 1, "fp": 1, "unresolved": 3,
                                    "eligible": 5, "covered": 2}]
    assert len(result["decisions"]) == 6
    assert next(row for row in result["decisions"] if row["decision_ref"] == helpful["decision_ref"]) == {
        "workspace_id": helpful["workspace_id"], "activation_ref": helpful["activation_ref"],
        "decision_ref": helpful["decision_ref"], "episode_id": "artifact-review", "action": "handoff",
        "member_id": review["context"]["member_id"], "worktree_id": review["context"]["worktree_id"],
        "rule_id": rule["id"], "rule_revision": rule["revision"], "verdict": "tp",
        "adjudication_ref": positive["statement_digest"],
    }
    with ThreadPoolExecutor(max_workers=2) as pool:
        rebuilds = list(pool.map(lambda _: canonical(project(review, anchor)), range(2), timeout=30))
    assert rebuilds == [canonical(result), canonical(result)]
    assert audit.read_bytes() == audit_before
    assert service.status()["fitness_credit"] == 0
    assert repo_fitness() == before


def test_correction_uses_current_predecessor_and_preserves_historical_anchor(review):
    first, second = scan(review), scan(review)
    original = draft(review, manifest(review, [first]))
    anchor = sign(review, original)
    before = canonical(project(review, anchor))
    revision = manifest(review, [second], previous_anchor=anchor, predecessor="a" * 64, assessment="misleading")
    with pytest.raises(ManagerError, match="^divergent_predecessor$"):
        draft(review, revision)
    corrected = draft(review, manifest(review, [second], previous_anchor=anchor,
                                      predecessor=original["statement_digest"], assessment="misleading"))
    successor = sign(review, corrected)
    assert totals(project(review, successor)) == {"tp": 0, "fp": 1, "unresolved": 0, "eligible": 1}
    assert canonical(project(review, anchor)) == before
    stale = manifest(review, [first], previous_anchor=successor, predecessor=original["statement_digest"])
    with pytest.raises(ManagerError, match="^divergent_predecessor$"):
        draft(review, stale)
    stolen = manifest(review, [first], previous_anchor=successor, episode_id="invented-episode")
    with pytest.raises(ManagerError, match="^episode_conflict$"):
        draft(review, stolen)


def test_signed_checkpoint_refuses_prefix_loss_and_allows_restoration(review):
    decision = scan(review)
    audit = review["store"] / "audit.jsonl"
    reduced = audit.read_bytes()
    failed = scan(review)
    review["service"].report(failed["decision_ref"], [], "failure", [], "failed-checkpoint")
    intact = audit.read_bytes()
    anchor = sign(review, draft(review, manifest(review, [decision])))
    before = project(review, anchor)
    audit.write_bytes(reduced)
    try:
        with pytest.raises(ManagerError, match="^audit_checkpoint_unavailable$"):
            project(review, anchor)
    finally:
        audit.write_bytes(intact)
    assert project(review, anchor) == before


def test_prepare_and_replay_refuse_regression_and_decisions_after_checkpoint(review):
    first = scan(review)
    early = review["service"].status()["audit_head"]
    second = scan(review)
    late = review["service"].status()["audit_head"]
    anchor = sign(review, draft(review, manifest(review, [first])))
    cases = [
        (manifest(review, [first], previous_anchor=anchor, episode_id="new-episode", audit_head=early),
         "audit_checkpoint_regressed"),
        (manifest(review, [second], audit_head=early), "decision_after_checkpoint"),
        (manifest(review, [first], audit_head="a" * 64), "audit_checkpoint_unavailable"),
        (manifest(review, [first], schema="aegis.manager-label/v1", with_checkpoint=False), "uncheckpointed_history"),
        (manifest(review, [first], with_checkpoint=False), "uncheckpointed_history"),
    ]
    for revision, reason in cases:
        with pytest.raises(ManagerError, match="^" + reason + "$"):
            draft(review, revision)
        git(review["control"], "checkout", "--detach", revision)
        signed = sign(review, {}, trailer="Aegis-Manager-Approve: " + "b" * 64)
        with pytest.raises(ManagerError, match="^" + reason + "$"):
            project(review, signed)
    assert project(review, anchor)["signed_audit_head"] == late


def test_historical_activation_and_concurrent_unmatched_decision(review):
    service = review["service"]
    older = scan(review)
    service.report(older["decision_ref"], [], "failure", [], "closed-review")
    path = review["control"] / "manager-policy" / "policy.json"
    policy = json.loads(path.read_bytes())
    policy["rules"] = [{"id": "inspect-package", "actions": ["evidence_review"], "match": {},
                        "text": "Inspect the package inventory before accepting the artifact."}]
    path.write_bytes(canonical(policy))
    git(review["control"], "commit", "-qam", "Review a new policy")
    revised = git(review["control"], "rev-parse", "HEAD")
    candidate = service.candidate(revised)
    service.activate(revised, older["activation_ref"], approve(review, candidate))
    pinned_pending = service.scan("evidence_review", review["context"])
    original = draft(review, manifest(review, [older]))
    signed_head = original["statement"]["audit_head"]
    anchor = sign(review, original)
    newer = service.scan("evidence_review", review["context"])
    before = project(review, anchor)
    with ThreadPoolExecutor(max_workers=2) as pool:
        building = pool.submit(project, review, anchor)
        scan_future = pool.submit(service.scan, "checkpoint", review["context"])
        scan_future.result(timeout=30)
        concurrent = building.result(timeout=30)
    after = project(review, anchor)
    assert concurrent in (before, after)
    assert after["signed_audit_head"] == signed_head != after["audit_head"]
    assert [row["decision_ref"] for row in after["decisions"]] == [
        older["decision_ref"], pinned_pending["decision_ref"]]
    package, = [row for row in after["by_revision"] if row["rule_id"] == "inspect-package"]
    assert package["unresolved"] == 1
    tail = after["unsigned_tail"]
    assert tail["by_action"][0] == {"action": "checkpoint", "eligible": 0, "covered": 0,
                                    "tp": 0, "fp": 0, "unresolved": 0}
    assert [row["decision_ref"] for row in tail["decisions"]] == [
        newer["decision_ref"], scan_future.result()["decision_ref"]]
    assert [row["decision_ref"] for row in tail["opportunities"]] == [newer["decision_ref"]]
    successor = sign(review, draft(review, manifest(review, [newer], episode_id="package-review",
                                                    previous_anchor=anchor)))
    advanced = project(review, successor)
    assert advanced["audit_head"] == advanced["signed_audit_head"]
    assert advanced["unsigned_tail"] == {"decisions": [], "opportunities": [],
                                        "by_revision": [], "by_action": []}
    assert project(review, anchor) == after


@pytest.mark.parametrize(("changes", "reason"), [
    ({"workspace_id": "different-workspace"}, "workspace_mismatch"),
    ({"rule_revision": "0" * 64}, "unserved_revision"),
    ({"decision_refs": ["0" * 64]}, "unknown_decision"),
    ({"assessment": ["helpful"]}, "invalid_label_manifest"),
    ({"evidence_digest": None}, "invalid_label_manifest"),
    ({"episode_id": "two\nlines"}, "invalid_label_manifest"),
    ({"previous_anchor": "b" * 40}, "missing_anchor"),
    ({"audit_head": "not-an-audit-head"}, "invalid_audit_checkpoint"),
])
def test_prepare_refuses_invalid_labels(review, changes, reason):
    decision = scan(review)
    with pytest.raises(ManagerError, match="^" + reason + "$"):
        draft(review, manifest(review, [decision], **changes))


@pytest.mark.parametrize("case", ["other-owner", "activation", "wrong-digest", "multiline", "manifest-changed", "unsigned"])
def test_anchor_requires_pinned_owner_and_exact_statement(review, case):
    decision = scan(review)
    activation_commit = git(review["control"], "rev-parse", "HEAD")
    revision = manifest(review, [decision])
    statement = draft(review, revision)
    if case == "activation":
        trailer = git(review["control"], "log", "-1", "--format=%B", activation_commit).split("\n")[-1]
        anchor = sign(review, statement, trailer=trailer)
    elif case == "other-owner":
        wrong, _ = keygen(review["config"].parent / "other", "untrusted")
        anchor = sign(review, statement, key=wrong)
    elif case == "manifest-changed":
        manifest(review, [decision], assessment="misleading")
        anchor = sign(review, statement)
    elif case == "multiline":
        anchor = sign(review, statement, trailer=statement["required_trailer"] + "\n continuation")
    elif case == "unsigned":
        anchor = revision
    else:
        anchor = sign(review, statement, trailer="Aegis-Manager-Approve: " + "b" * 64)
    with pytest.raises(ManagerError, match="^invalid_owner_signature$"):
        project(review, anchor)


def test_changed_audit_snapshot_invalidates_signature(review):
    decision = scan(review)
    anchor = sign(review, draft(review, manifest(review, [decision])))
    audit = review["store"] / "audit.jsonl"
    rows = [json.loads(line) for line in audit.read_bytes().splitlines()]
    row = rows[-1]
    row["context"]["summary"] = "edited after serving"
    row["context_digest"] = digest(row["context"])
    del row["hash"]
    row["hash"] = digest(row)
    audit.write_bytes(b"".join(canonical(item) + b"\n" for item in rows))
    with pytest.raises(ManagerError, match="^audit_checkpoint_unavailable$"):
        project(review, anchor)


def test_unavailable_binding_refuses_and_restoring_it_allows_retry(review):
    decision = scan(review)
    anchor = sign(review, draft(review, manifest(review, [decision])))
    member = review["member"]
    unavailable = member.rename(member.with_name("offline-member"))
    try:
        with pytest.raises(ManagerError, match="^membership_unavailable$"):
            project(review, anchor)
    finally:
        unavailable.rename(member)
    assert totals(project(review, anchor))["tp"] == 1


def test_manifest_is_bounded_and_read_from_git(review):
    decision = scan(review)
    revision = manifest(review, [decision])
    path = review["control"] / "adjudication" / "label.json"
    path.write_bytes(b" " * (64 * 1024 + 1))
    assert draft(review, revision)["statement"]["manifest_digest"]
    git(review["control"], "add", "adjudication/label.json")
    git(review["control"], "commit", "-qm", "Oversized label")
    with pytest.raises(ManagerError, match="^manifest_limit$"):
        draft(review, git(review["control"], "rev-parse", "HEAD"))


def test_git_symlink_manifest_is_refused_without_reading_the_checkout(review):
    decision = scan(review)
    manifest(review, [decision])
    root = review["control"]
    path = "adjudication/label.json"
    oid = git(root, "hash-object", "-w", "--", path)
    git(root, "update-index", "--cacheinfo", "120000," + oid + "," + path)
    git(root, "commit", "-qm", "Unexpected manifest mode")
    with pytest.raises(ManagerError, match="^unsafe_label_manifest$"):
        draft(review, git(root, "rev-parse", "HEAD"))


def test_prepare_refuses_git_transport_failure_without_echo_and_can_retry(review, monkeypatch):
    revision = manifest(review, [scan(review)])
    git_boundary = adjudication.gitsafe
    failures = []

    def read(args, cwd, **options):
        if args[0] == "ls-tree" and not failures:
            failures.append(True)
            raise git_boundary.GitError("untrusted process failure detail")
        return git_boundary.run(args, cwd, **options)

    monkeypatch.setattr(adjudication, "gitsafe", SimpleNamespace(**{**vars(git_boundary), "run": read}))
    with pytest.raises(ManagerError, match="^git_unavailable$"):
        draft(review, revision)
    assert draft(review, revision)["statement"]["schema"] == "aegis.manager-adjudication/v2"


def audit_edit(review, change):
    audit = review["store"] / "audit.jsonl"
    original = audit.read_bytes()
    rows = [json.loads(line) for line in original.splitlines()]
    change(rows)
    previous = "0" * 64
    for row in rows:
        row["prev"] = previous
        del row["hash"]
        row["hash"] = previous = digest(row)
    audit.write_bytes(b"".join(canonical(row) + b"\n" for row in rows))
    return audit, original


@pytest.mark.parametrize("which", ["activation", "decision", "decision_activation", "outcome"])
def test_audit_validation_rejects_noncanonical_references(review, which):
    decision = scan(review)
    review["service"].report(decision["decision_ref"], [], "failure", [], "ref-test")

    def change(rows):
        if which == "activation":
            rows[1]["activation_ref"] = "A" * 64
        elif which == "decision":
            rows[2]["decision_ref"] = rows[2]["result"]["decision_ref"] = "invalid-ref"
        elif which == "decision_activation":
            rows[2]["activation_ref"] = rows[2]["result"]["activation_ref"] = "1" * 40
        else:
            rows[3]["request"]["decision_ref"] = "A" * 64

    audit, original = audit_edit(review, change)
    try:
        with pytest.raises(ManagerError, match="^audit_corrupt$"):
            ManagerService(review["config"])
        with pytest.raises(ManagerError, match="^audit_corrupt$"):
            review["service"].adjudication_history()
    finally:
        audit.write_bytes(original)
    assert decision["decision_ref"] in review["service"].adjudication_history()[3]


@pytest.mark.parametrize("kind", ["missing", "blob", "tag"])
def test_history_refuses_missing_or_wrong_kind_approval_and_retries(review, kind):
    root = review["control"]
    if kind == "missing":
        oid = "0" * len(review["revision"])
    elif kind == "blob":
        oid = git(root, "rev-parse", "HEAD:manager-policy/policy.json")
    else:
        git(root, "tag", "-am", "Tag over approval", "approval-tag")
        oid = git(root, "rev-parse", "approval-tag")

    def change(rows):
        rows[1]["approval"]["approval_commit"] = oid

    decision = scan(review)
    revision = manifest(review, [decision])
    audit, original = audit_edit(review, change)
    try:
        with pytest.raises(ManagerError, match="^activation_integrity$"):
            review["service"].adjudication_history()
        with pytest.raises(ManagerError, match="^activation_integrity$"):
            draft(review, revision)
    finally:
        audit.write_bytes(original)
    assert draft(review, revision)["statement"]["audit_head"]


@pytest.mark.parametrize(("oversized", "reason"), [(False, "invalid_owner_signature"), (True, "anchor_limit")])
def test_history_preserves_signature_and_commit_size_refusals(review, oversized, reason):
    oid = review["revision"]
    if oversized:
        root = review["control"]
        message = root.parent / "oversized-message"
        message.write_bytes(b"z" * (128 * 1024 + 1))
        git(root, "commit", "--allow-empty", "-q", "-F", str(message))
        oid = git(root, "rev-parse", "HEAD")

    def change(rows):
        rows[1]["approval"]["approval_commit"] = oid

    audit, original = audit_edit(review, change)
    try:
        with pytest.raises(ManagerError, match="^" + reason + "$"):
            review["service"].adjudication_history()
    finally:
        audit.write_bytes(original)
    assert review["service"].adjudication_history()[0] == review["service"].status()["audit_head"]


def test_direct_history_scrubs_ambient_git_selectors(review):
    expected = review["service"].status()["audit_head"]
    program = ("import sys\nfrom aegis_core.manager import ManagerService\n"
               "print(ManagerService(sys.argv[1]).adjudication_history()[0])")
    result = run([sys.executable, "-c", program, str(review["config"])],
                 env={**review["owner_home"], "GIT_DIR": str(review["store"] / "missing-git"),
                      "GIT_WORK_TREE": str(review["member"])}, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected


def test_direct_history_maps_operational_git_failure_and_retries(review, monkeypatch):
    git_boundary = manager.gitsafe
    failures = []

    def resolve(root, revision):
        if not failures:
            failures.append(True)
            raise git_boundary.GitError("untrusted failure text")
        return git_boundary.resolve_commit(root, revision)

    monkeypatch.setattr(manager, "gitsafe", SimpleNamespace(**{**vars(git_boundary), "resolve_commit": resolve}))
    service = review["service"]
    with pytest.raises(ManagerError, match="^git_unavailable$"):
        service.adjudication_history()
    assert service.adjudication_history()[0] == service.status()["audit_head"]


def test_owner_requests_read_once_and_scope_real_layout_objects(review, monkeypatch):
    revision = manifest(review, [scan(review)])
    reads, layouts = [], []
    real_candidate = manager.read_candidate

    class ObservedStore(ManagerStore):
        def read(self):
            reads.append(self.root)
            return super().read()

    def candidate(root, commit, **kwargs):
        layout = gitsafe.layout(root)
        result = real_candidate(root, commit, **kwargs)
        assert gitsafe.layout(root) is layout
        assert layout is not None
        layouts.append(layout)
        return result

    monkeypatch.setattr(manager, "ManagerStore", ObservedStore)
    monkeypatch.setattr(manager, "read_candidate", candidate)
    anchor = sign(review, draft(review, revision))
    assert len(reads) == len(layouts) == 1
    assert totals(project(review, anchor))["tp"] == 1
    assert len(reads) == len(layouts) == 2
    assert layouts[0] is not layouts[1]


def test_ssh_armor_preflight_allows_crlf_without_joining_trailer_text(review, monkeypatch):
    anchor = sign(review, draft(review, manifest(review, [scan(review)])))
    git_boundary = adjudication.gitsafe

    def with_crlf(raw):
        armor = b"-----BEGIN SSH SIGNATURE-----"
        assert armor + b"\n" in raw
        return raw.replace(armor + b"\n", armor + b"\r\n", 1)

    def objects(root, oids, **kwargs):
        result = git_boundary.read_blobs(root, oids, **kwargs)
        if anchor in result:
            result[anchor] = with_crlf(result[anchor])
        return result

    def sizes(root, oids, **kwargs):
        result = git_boundary.blob_sizes(root, oids, **kwargs)
        if anchor in result:
            result[anchor] += 1
        return result

    monkeypatch.setattr(adjudication, "gitsafe", SimpleNamespace(
        **{**vars(git_boundary), "read_blobs": objects, "blob_sizes": sizes}))
    assert totals(project(review, anchor))["tp"] == 1
