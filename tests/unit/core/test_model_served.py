"""Served receipts through public selection, observation and replay surfaces."""
import copy
import errno
import hashlib
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from conftest import symlink_or_skip
from aegis_core import model_select as selection
from aegis_core import model_served as core
from aegis_core.storage import confined_descriptor_supported


@pytest.fixture
def scenario():
    bindings = {"schema": "aegis.model-bindings/v1", "roles": [
        {"kind": role, "model_class": "coding",
         "band": {"floor": "deep", "default": "deep", "ceiling": "extended"}}
        for role in ("orchestrator", "decider", "implementer", "integrator", "reviewer")],
        "hosts": [{"host": host, "class": "coding", "model": model,
                   "levels": {"deep": "high", "extended": "max"},
                   "admission": {"deep": "admitted", "extended": "admitted"}}
                  for host, model in (("host-a", "model-a"), ("host-b", "model-b"))]}
    policy = {"team_id": "example-team", "manager_family": "beta", "team_family": "alpha",
              "target_shares": {"alpha": 0.7, "beta": 0.3}, "family_order": ["alpha", "beta"],
              "family_hosts": {"alpha": ["host-a"], "beta": ["host-b"]},
              "flexible_tasks": ["T9"],
              "review_families": {"T4": {"primary": "beta"}, "T5": {"primary": "alpha"},
                                  "T6": {"primary": "alpha", "whole": "beta"},
                                  "T8": {"primary": "opposite", "second": "author"}}}
    return bindings, policy


def choose(scenario, rows=(), **changes):
    bindings, policy = scenario
    return selection.select_model(bindings, policy, "T9", "implementer", rows,
                                  host_kinds=("host-a", "host-b"), subject="example",
                                  author_family="alpha", **changes)[1]


@pytest.fixture
def original(scenario):
    return choose(scenario)


def chosen(record):
    return {**{key: record["choice"][key] for key in ("host", "model", "level", "family")},
            "fallback_reason": None}


def fallback():
    return {"host": "host-b", "model": "model-b", "level": "high", "family": "beta",
            "fallback_reason": "configured_host_unavailable"}


def observation(record, served):
    return {**record, "outcome": {"served": served}}


def make_store(tmp_path, original):
    if os.name != "posix" or not confined_descriptor_supported():
        pytest.skip("descriptor-relative no-follow decision logs required")
    path = tmp_path / "receipts.jsonl"
    selection.append_decision(path, original)
    return path


def probe_report(record):
    return {"decision_id": record["decision_id"], "provenance": "runtime-receipt",
            **{key: record["choice"][key] for key in ("host", "model", "level", "family")}}


def marked_receipt(stage):
    return {**stage, "outcome": {"served": chosen(stage), "probe_readback": {
        "decision_id": stage["decision_id"], "registry_id": stage["registry_id"], "provenance": "runtime-receipt"}}}


def reidentify(record):
    immutable = {key: value for key, value in record.items() if key not in ("outcome", "decision_id")}
    record["decision_id"] = hashlib.sha256(json.dumps(
        immutable, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()


def write_history(path, rows):
    path.write_bytes(b"".join(
        (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii") for row in rows))


def audit_readback(path, bindings, stage, host_kinds=("host-a", "host-b")):
    with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
        core.admit_probe(path, bindings, stage["decision_id"], probe_report(stage), host_kinds=host_kinds)
    return marked_receipt(stage)


def stage_probe(tmp_path, scenario, original):
    if os.name != "posix" or not confined_descriptor_supported():
        pytest.skip("descriptor-relative no-follow decision logs required")
    bindings, policy = scenario
    path = tmp_path / "receipts.jsonl"
    _, attempt = selection.select_and_append(path, bindings, policy, original["task_kind"], original["role_kind"],
                                             subject=original["subject"], author_family=original["author_family"],
                                             host_kinds=("host-a", "host-b"), probe_attempt=True)
    return path, attempt


def historical_probe(tmp_path, scenario, original, *, unbound=False):
    path, stage = stage_probe(tmp_path, scenario, original)
    stage.pop("counts_scope", None)
    reidentify(stage)
    receipt = marked_receipt(stage)
    if unbound:
        receipt["outcome"]["probe_readback"].pop("decision_id")
    launch = {**stage, "outcome": {"launch_status": "launched", "registry_id": stage["registry_id"]}}
    write_history(path, (stage, receipt, launch))
    return path, stage, receipt, launch


@pytest.mark.parametrize("wrong_host", [False, True])
def test_generic_append_cannot_originate_a_probe_stage(tmp_path, scenario, original, wrong_host):
    path = make_store(tmp_path, original)
    stage = choose(scenario, [original], probe_attempt=True)
    if wrong_host:
        assert stage["choice"]["family"] != original["choice"]["family"]
        stage["choice"].update(host=original["choice"]["host"], model=original["choice"]["model"])
        reidentify(stage)
    before = path.read_bytes()
    bindings, _ = scenario
    with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
        selection.append_decision(path, stage, probe_bindings=(bindings, ("host-a", "host-b")))
    with pytest.raises(selection.ModelSelectionError, match="^unknown_decision_id$"):
        selection.append_decision(path, None, known_decision=stage["decision_id"], prepare=lambda _: stage)
    assert path.read_bytes() == before


@pytest.mark.parametrize("entry", ["admit", "direct", "prepared"])
def test_exact_probe_evidence_is_audited_once_and_never_grants(tmp_path, scenario, original, entry):
    path, stage = stage_probe(tmp_path, scenario, original)
    bindings, _ = scenario
    hosts = ("host-a", "host-b")
    identity, receipt = stage["decision_id"], marked_receipt(stage)
    for _ in range(2):
        with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
            if entry == "admit":
                core.admit_probe(path, bindings, identity, probe_report(stage), host_kinds=hosts)
            elif entry == "direct":
                selection.append_decision(path, receipt, probe_bindings=(bindings, hosts))
            else:
                selection.append_decision(path, None, known_decision=identity, prepare=lambda _: receipt,
                                          probe_bindings=(bindings, hosts))
    assert list(selection.read_decisions(path)) == [stage, receipt]
    assert core.served_of(selection.read_decisions(path), identity, probe_bindings=(bindings, hosts)) is None


@pytest.mark.parametrize("limit", ["MAX_HISTORY_RECORDS", "MAX_HISTORY_BYTES"])
def test_full_probe_audit_preserves_bytes_and_cannot_grant(tmp_path, scenario, original, monkeypatch, limit):
    path, stage = stage_probe(tmp_path, scenario, original)
    bindings, _ = scenario
    hosts = ("host-a", "host-b")
    receipt = marked_receipt(stage)
    write_history(path, (stage, receipt))
    before = path.read_bytes()
    if limit == "MAX_HISTORY_RECORDS":
        monkeypatch.setattr(selection, "MAX_HISTORY_RECORDS", 2)
    else:
        monkeypatch.setattr(selection, "MAX_HISTORY_BYTES", len(before))
    report = probe_report(stage)
    for _ in range(2):
        with pytest.raises(selection.ModelSelectionError, match="^history_limit_exceeded: archive_or_rotate"):
            core.admit_probe(path, bindings, stage["decision_id"], {**report, "model": "different"}, host_kinds=hosts)
        with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
            core.admit_probe(path, bindings, stage["decision_id"], report, host_kinds=hosts)
    assert path.read_bytes() == before
    assert core.served_of(selection.read_decisions(path), stage["decision_id"], probe_bindings=(bindings, hosts)) is None


def test_probe_stage_uses_the_ordered_host_of_its_policy_family(scenario):
    bindings, policy = scenario
    bindings["hosts"].append({**bindings["hosts"][0], "host": "host-next", "model": "model-next"})
    policy["family_hosts"]["alpha"].insert(0, "host-next")
    choice, stage = selection.select_model(bindings, policy, "T9", "implementer", [],
                                           host_kinds=("host-a", "host-b", "host-next"), subject="first",
                                           probe_attempt=True)
    assert (choice["family"], choice["host"], choice["model"]) == ("alpha", "host-next", "model-next")
    assert stage["admission"] == "unprobed"
    assert stage["outcome"] == {"launch_status": "not_launched"}


@pytest.mark.parametrize("task,role", [("T1", "orchestrator"), ("T1", "decider"), ("T2", "implementer"),
                                      ("T2", "integrator"), ("T4", "reviewer")])
def test_staged_probe_uses_changed_binding_for_all_roles(tmp_path, scenario, task, role):
    bindings, policy = scenario
    hosts = ("host-a", "host-b")
    before = selection.select_model(bindings, policy, task, role, [], subject="first-attempt",
                                    author_family="alpha", host_kinds=hosts)[1]
    make_store(tmp_path, before)
    path, before = stage_probe(tmp_path, scenario, before)
    for row in bindings["hosts"]:
        row["model"] += "-next"
        row["levels"]["deep"] = "medium"
    binding_file, profile_file = tmp_path / "bindings.json", tmp_path / "profile.json"
    binding_file.write_text(json.dumps(bindings), encoding="utf-8")
    profile_file.write_text(json.dumps(policy), encoding="utf-8")
    _, attempt = selection.select_and_append(path, binding_file, profile_file, task, role,
                                            subject="next-attempt", author_family="alpha", host_kinds=hosts,
                                            probe_attempt=True)
    prior_receipt = audit_readback(path, binding_file, before, hosts)
    report = probe_report(attempt)
    result = audit_readback(path, binding_file, attempt, hosts)
    assert result["choice"]["host"] == before["choice"]["host"] == report["host"]
    assert result["choice"]["model"] == before["choice"]["model"] + "-next" == report["model"]
    assert result["choice"]["level"] == report["level"] == "medium"
    assert attempt["admission"] == "unprobed"
    assert result["outcome"] == {"served": chosen(attempt), "probe_readback": {
        "decision_id": attempt["decision_id"], "provenance": "runtime-receipt",
        "registry_id": attempt["registry_id"]}}
    stored = list(selection.read_decisions(path))
    assert stored[0]["admission"] == "admitted"
    assert stored[-2:] == [prior_receipt, result]


@pytest.mark.parametrize("field,value,error", [
    (None, None, "probe_readback_missing"), (None, {}, "invalid_probe_readback"),
    ("decision_id", "0" * 64, "probe_readback_mismatch"),
    ("model", "different", "probe_readback_mismatch"), ("level", "max", "probe_readback_mismatch"),
    ("host", "host-b", "probe_readback_mismatch"), ("family", "beta", "probe_readback_mismatch"),
    ("provenance", "receipt\nforged", "invalid_probe_readback"),
    ("provenance", "x" * 129, "invalid_probe_readback"),
])
def test_bad_probe_readback_records_only_same_attempt_contradictions(tmp_path, scenario, original,
                                                                   field, value, error):
    path, original = stage_probe(tmp_path, scenario, original)
    bindings, _ = scenario
    report = value if field is None else {**probe_report(original), field: value}
    before = path.read_bytes()

    def refuse(_):
        with pytest.raises(selection.ModelSelectionError, match="^" + error + "$"):
            core.admit_probe(path, bindings, original["decision_id"], report, host_kinds=("host-a", "host-b"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(refuse, range(2), timeout=10))
    refuse(None)
    if field in ("model", "level", "host", "family"):
        staged, audit = list(selection.read_decisions(path))
        assert staged == original
        assert audit["outcome"]["served"][field] == value
        assert audit["outcome"]["probe_readback"]["decision_id"] == original["decision_id"]
        with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
            core.admit_probe(path, bindings, original["decision_id"], probe_report(original),
                             host_kinds=("host-a", "host-b"))
    else:
        assert path.read_bytes() == before


def test_exact_probe_audit_is_written_once_under_concurrency(tmp_path, scenario, original):
    path, original = stage_probe(tmp_path, scenario, original)
    bindings, _ = scenario
    def admit(_):
        return audit_readback(path, bindings, original)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, replay = pool.map(admit, range(2), timeout=10)
    assert first == replay
    before = path.read_bytes()
    assert admit(None) == first
    assert path.read_bytes() == before
    rows = list(selection.read_decisions(path))
    assert len(rows) == 2
    assert rows[-1] == first
    assert core.served_of(rows, original["decision_id"], probe_bindings=(bindings, ("host-a", "host-b"))) is None
    assert sum(choose(scenario, rows)["counts_before"].values()) == 0


def test_peer_publication_before_probe_lock_uses_current_snapshot(tmp_path, scenario, original, monkeypatch):
    path, stage = stage_probe(tmp_path, scenario, original)
    replacement = tmp_path / "peer-publication"
    receipt = marked_receipt(stage)
    write_history(replacement, [stage, receipt])
    same_file, file_lock = selection._same_file, selection.file_lock

    def publish_peer():
        if replacement.exists():
            replacement.replace(path)

    def compare_after_peer(name, descriptor, directory):
        if name == path.name:
            publish_peer()
        return same_file(name, descriptor, directory)

    def lock_after_peer(name, *, timeout, dir_fd):
        publish_peer()
        return file_lock(name, timeout=timeout, dir_fd=dir_fd)

    monkeypatch.setattr(selection, "_same_file", compare_after_peer)
    monkeypatch.setattr(selection, "file_lock", lock_after_peer)
    report = {**probe_report(stage), "model": "different"}
    with pytest.raises(selection.ModelSelectionError, match="^probe_readback_mismatch$"):
        core.admit_probe(path, scenario[0], stage["decision_id"], report, host_kinds=("host-a", "host-b"))
    staged, observed, conflict = selection.read_decisions(path)
    assert (staged, observed) == (stage, receipt)
    assert conflict["outcome"]["served"]["model"] == "different"


@pytest.mark.parametrize("known", [False, True])
def test_probe_receipt_cannot_be_transplanted_by_either_append_form(tmp_path, scenario, original, known):
    path, attempt = stage_probe(tmp_path, scenario, original)
    bindings, policy = scenario
    hosts = ("host-a", "host-b")
    proof = audit_readback(path, bindings, attempt, hosts)
    _, other = selection.select_and_append(path, bindings, policy, "T9", "implementer",
                                          subject="other", host_kinds=hosts, probe_attempt=True)
    pending = {**other, "outcome": proof["outcome"]}
    before = path.read_bytes()
    with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
        if known:
            selection.append_decision(path, None, known_decision=other["decision_id"],
                                      prepare=lambda _: pending, probe_bindings=(bindings, hosts))
        else:
            selection.append_decision(path, pending, probe_bindings=(bindings, hosts))
    assert path.read_bytes() == before
    assert audit_readback(path, bindings, other, hosts) == list(selection.read_decisions(path))[-1]


@pytest.mark.parametrize("entry", ["direct", "prepared", "admit"])
@pytest.mark.parametrize("launched", [False, True])
def test_probe_provenance_conflict_persists_once_and_blocks_retries(tmp_path, scenario, original, entry, launched):
    bindings, _ = scenario
    hosts = ("host-a", "host-b")
    if launched:
        path, attempt, proof, launch = historical_probe(tmp_path, scenario, original)
    else:
        path, attempt = stage_probe(tmp_path, scenario, original)
        proof = audit_readback(path, bindings, attempt, hosts)
        launch = {**attempt, "outcome": {"launch_status": "launched", "registry_id": attempt["registry_id"]}}
    identity, report = attempt["decision_id"], probe_report(attempt)
    baseline = list(selection.read_decisions(path))
    conflict = copy.deepcopy(proof)
    conflict["outcome"]["probe_readback"]["provenance"] = "different-receipt"

    def refuse(_):
        with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
            if entry == "admit":
                core.admit_probe(path, bindings, identity, {**report, "provenance": "different-receipt"},
                                 host_kinds=hosts)
            elif entry == "prepared":
                selection.append_decision(path, None, known_decision=identity, prepare=lambda _: conflict,
                                          probe_bindings=(bindings, hosts))
            else:
                selection.append_decision(path, conflict, probe_bindings=(bindings, hosts))

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(refuse, range(2), timeout=10))
    assert list(selection.read_decisions(path)) == [*baseline, conflict]
    core.observe_served(path, identity, chosen(attempt))
    with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
        core.admit_probe(path, bindings, identity, report, host_kinds=hosts)
    with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
        selection.append_decision(path, launch, probe_bindings=(bindings, hosts))
    assert sum(choose(scenario, selection.read_decisions(path))["counts_before"].values()) == 0


@pytest.mark.parametrize("entry", ["admit", "direct", "prepared"])
@pytest.mark.parametrize("field", ["model", "provenance"])
def test_drift_preserves_contradictions_across_registry_restoration(tmp_path, scenario, original, entry, field):
    path, stage, proof, launch = historical_probe(tmp_path, scenario, original)
    bindings, _ = scenario
    hosts = ("host-a", "host-b")
    identity, report = stage["decision_id"], probe_report(stage)
    before = list(selection.read_decisions(path))
    changed = copy.deepcopy(bindings)
    changed["hosts"][1]["model"] += "-next"
    pending = copy.deepcopy(proof)
    target = "served" if field == "model" else "probe_readback"
    pending["outcome"][target][field] = "different"
    refusal = "probe_readback_mismatch" if entry == "admit" and field == "model" else "decision_outcome_conflict"

    def contradict(_):
        with pytest.raises(selection.ModelSelectionError, match="^" + refusal + "$"):
            if entry == "admit":
                core.admit_probe(path, changed, identity, {**report, field: "different"}, host_kinds=hosts)
            elif entry == "direct":
                selection.append_decision(path, pending, probe_bindings=(changed, hosts))
            else:
                selection.append_decision(path, None, known_decision=identity, prepare=lambda _: pending,
                                          probe_bindings=(changed, hosts))

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(contradict, range(2), timeout=10))
    assert list(selection.read_decisions(path)) == [*before, pending]
    for current in (changed, bindings):
        with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
            core.admit_probe(path, current, identity, report, host_kinds=hosts)
        with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
            selection.append_decision(path, launch, probe_bindings=(current, hosts))
        with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
            core.served_of(selection.read_decisions(path), identity, probe_bindings=(current, hosts))
        assert sum(choose((current, scenario[1]), selection.read_decisions(path))["counts_before"].values()) == 0


@pytest.mark.parametrize("container", [list, tuple, iter])
def test_unbound_stage_metadata_cannot_project_as_ordinary(scenario, container):
    stage = choose(scenario, probe_attempt=True)
    stage.pop("probe_id")
    rows = [stage, observation(stage, chosen(stage))]
    with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
        core.served_of(container(rows), stage["decision_id"])


def foreign_readback(original, *, launched=False):
    outcome = {"probe_readback": {"decision_id": "0" * 64}, "served": chosen(original)}
    if launched:
        outcome["launch_status"] = "launched"
    return {**original, "outcome": outcome}


@pytest.mark.parametrize("entry", ["direct", "prepared"])
def test_foreign_marked_readback_cannot_count_as_ordinary_launch(tmp_path, original, entry):
    path = make_store(tmp_path, {**original, "outcome": {"launch_status": "not_launched"}})
    pending = foreign_readback(original, launched=True)
    before = path.read_bytes()
    with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
        if entry == "direct":
            selection.append_decision(path, pending)
        else:
            selection.append_decision(path, None, known_decision=original["decision_id"], prepare=lambda _: pending)
    assert path.read_bytes() == before


@pytest.mark.parametrize("container", [list, tuple, iter])
def test_foreign_marked_readback_refuses_ordinary_accounting(scenario, original, container):
    with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
        choose(scenario, container([foreign_readback(original)]))


@pytest.mark.parametrize("include_scope", [False, True])
@pytest.mark.parametrize("surface", ["append", "disk", "list", "tuple", "iterator", "projection"])
def test_stage_counts_derive_from_stage_registry(tmp_path, scenario, original, include_scope, surface):
    path, stage, _, _ = historical_probe(tmp_path, scenario, original)
    bindings, _ = scenario
    hosts = ("host-a", "host-b")
    rows = list(selection.read_decisions(path))
    changed = copy.deepcopy(bindings)
    changed["hosts"][1]["model"] += "-next"
    current = (changed, scenario[1])
    forged = choose(current, rows, probe_attempt=True)
    assert forged["choice"]["family"] == "alpha"
    if include_scope:
        forged.pop("counts_scope")
        forged["counts_registry_id"] = stage["registry_id"]
    forged["counts_before"] = {"alpha": 1, "beta": 0}
    forged["choice"].update(family="beta", host="host-b", model=changed["hosts"][1]["model"])
    reidentify(forged)
    refusal = "^decision_outcome_conflict$" if surface in ("append", "projection") else "^invalid_history:counts_before:"
    with pytest.raises(selection.ModelSelectionError, match=refusal):
        if surface == "append":
            selection.append_decision(path, forged, probe_bindings=(changed, hosts))
        elif surface == "disk":
            with path.open("ab") as stream:
                stream.write((json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
            list(selection.read_decisions(path))
        elif surface == "projection":
            receipt = {**forged, "outcome": {"served": chosen(forged), "probe_readback": {
                "decision_id": forged["decision_id"], "registry_id": forged["registry_id"],
                "provenance": "different-run"}}}
            core.served_of(iter([*rows, forged, receipt]), forged["decision_id"], probe_bindings=(changed, hosts))
        else:
            container = {"list": list, "tuple": tuple, "iterator": iter}[surface]
            choose(current, container([*rows, forged]))


@pytest.mark.parametrize("container", [list, tuple, iter])
@pytest.mark.parametrize("with_stage", [False, True])
def test_unmarked_prefix_never_establishes_or_hides_probe_staging(tmp_path, scenario, original, container, with_stage):
    path, attempt = stage_probe(tmp_path, scenario, original)
    bindings, _ = scenario
    hosts = ("host-a", "host-b")
    identity = attempt["decision_id"]
    prefix = observation({key: value for key, value in attempt.items() if key != "probe_id"}, fallback())
    proof = audit_readback(path, bindings, attempt, hosts)
    rows = [prefix, attempt, proof] if with_stage else [prefix, proof]
    with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
        core.served_of(container(rows), identity)


@pytest.mark.parametrize("replay", [False, True])
def test_registry_replacement_during_audit_write_or_retry(tmp_path, scenario, original, monkeypatch, replay):
    path, attempt = stage_probe(tmp_path, scenario, original)
    bindings, _ = scenario
    hosts = ("host-a", "host-b")
    binding_file, replacement = tmp_path / "bindings.json", tmp_path / "next.json"
    binding_file.write_text(json.dumps(bindings), encoding="utf-8")
    changed = copy.deepcopy(bindings)
    changed["hosts"][1]["model"] += "-next"
    replacement.write_text(json.dumps(changed), encoding="utf-8")
    identity = attempt["decision_id"]
    if replay:
        audit_readback(path, binding_file, attempt, hosts)
    before = path.read_bytes()
    check = selection._check_log_generation

    def replace_bindings(name, directory, generation):
        if replacement.exists():
            replacement.replace(binding_file)
        check(name, directory, generation)

    monkeypatch.setattr(selection, "_check_log_generation", replace_bindings)
    receipt = audit_readback(path, binding_file, attempt, hosts)
    assert not replacement.exists()
    assert (path.read_bytes() == before) is replay
    assert list(selection.read_decisions(path)) == [attempt, receipt]
    assert core.served_of(selection.read_decisions(path), identity) is None
    assert core.served_of(selection.read_decisions(path), identity, probe_bindings=(binding_file, hosts)) is None
    assert core.served_of(selection.read_decisions(path), identity, probe_bindings=(bindings, hosts)) is None


def test_historical_launch_keeps_audit_counts_but_never_affects_selection(tmp_path, scenario, original):
    path, stage, receipt, launch = historical_probe(tmp_path, scenario, original)
    bindings, policy = scenario
    hosts = ("host-a", "host-b")
    historical = {**original, "counts_before": {"alpha": 1, "beta": 0},
                  "previous_decision_id": stage["decision_id"], "outcome": {"launch_status": "not_launched"}}
    historical["choice"] = {**original["choice"], "host": "host-b", "model": "model-b", "family": "beta"}
    reidentify(historical)
    rows = [stage, receipt, launch, historical]
    write_history(path, rows)
    assert list(selection.read_decisions(path)) == rows
    changed = copy.deepcopy(bindings)
    changed["hosts"][1]["model"] += "-next"
    for current in (bindings, changed, bindings):
        for history in (rows, tuple(rows), iter(rows), selection.read_decisions(path)):
            next_record = choose((current, policy), history)
            assert next_record["counts_before"] == {"alpha": 0, "beta": 0}
            assert next_record["choice"]["family"] == "alpha"
    for history in (rows, tuple(rows), iter(rows), selection.read_decisions(path)):
        assert core.served_of(history, stage["decision_id"], probe_bindings=(bindings, hosts)) is None
    _, probe = selection.select_and_append(path, bindings, policy, "T9", "implementer",
                                          subject="next-a", host_kinds=hosts, probe_attempt=True)
    _, ordinary = selection.select_and_append(path, changed, policy, "T9", "implementer",
                                             subject="next-b", host_kinds=hosts)
    assert probe["counts_before"] == ordinary["counts_before"] == {"alpha": 0, "beta": 0}
    assert probe["counts_scope"] == ordinary["counts_scope"] == "ordinary"
    assert list(selection.read_decisions(path)) == [*rows, probe, ordinary]
    assert sum(choose(scenario, selection.read_decisions(path))["counts_before"].values()) == 1


@pytest.mark.parametrize("known", [False, True])
@pytest.mark.parametrize("revision", ["staged", "different", "absent"])
def test_duplicate_stage_is_idempotent_for_historical_attempts(tmp_path, scenario, original, known, revision):
    path, attempt, receipt, launch = historical_probe(tmp_path, scenario, original)
    bindings, _ = scenario
    hosts = ("host-a", "host-b")
    changed = copy.deepcopy(bindings)
    changed["hosts"][1]["model"] += "-next"
    source = {"staged": (bindings, hosts), "different": (changed, hosts), "absent": None}[revision]
    identity = attempt["decision_id"]
    before = path.read_bytes()
    for _ in range(2):
        if known:
            selection.append_decision(path, None, known_decision=identity, prepare=lambda _: attempt,
                                      probe_bindings=source)
        else:
            selection.append_decision(path, attempt, probe_bindings=source)
    assert path.read_bytes() == before
    assert list(selection.read_decisions(path)) == [attempt, receipt, launch]
    assert sum(choose(scenario, selection.read_decisions(path))["counts_before"].values()) == 0


def test_historical_stage_reset_keeps_later_audit_rows_readable(tmp_path, scenario, original):
    path, stage, receipt, launch = historical_probe(tmp_path, scenario, original)
    following = {**original, "previous_decision_id": stage["decision_id"]}
    reidentify(following)
    rows = [stage, receipt, launch, stage, following]
    write_history(path, rows)
    assert list(selection.read_decisions(path)) == rows
    assert choose(scenario, iter(rows))["counts_before"] == {"alpha": 1, "beta": 0}


def test_legacy_unbound_receipt_and_launch_stay_in_audit_without_qualification(tmp_path, scenario, original):
    path, attempt, receipt, launch = historical_probe(tmp_path, scenario, original, unbound=True)
    bindings, _ = scenario
    hosts = ("host-a", "host-b")
    identity = attempt["decision_id"]
    rows = list(selection.read_decisions(path))
    assert rows == [attempt, receipt, launch]
    assert core.served_of(iter(rows), identity, probe_bindings=(bindings, hosts)) is None
    assert sum(choose(scenario, rows)["counts_before"].values()) == 0
    with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
        core.admit_probe(path, bindings, identity, probe_report(attempt), host_kinds=hosts)
    with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
        selection.append_decision(path, launch, probe_bindings=(bindings, hosts))
    assert list(selection.read_decisions(path)) == rows


def test_probe_promotion_cannot_reuse_an_older_attempt(tmp_path, scenario, original):
    path, original = stage_probe(tmp_path, scenario, original)
    # The same request in a different log generation is still a distinct attempt.
    path.write_bytes(b"")
    _, current = stage_probe(tmp_path, scenario, original)
    bindings, _ = scenario
    hosts = ("host-a", "host-b")
    stale_report = probe_report(original)
    assert all(stale_report[key] == current["choice"][key] for key in ("host", "model", "level", "family"))
    before = path.read_bytes()
    with pytest.raises(selection.ModelSelectionError, match="^probe_readback_mismatch$"):
        core.admit_probe(path, bindings, current["decision_id"], stale_report, host_kinds=hosts)
    assert path.read_bytes() == before
    assert audit_readback(path, bindings, current, hosts) == list(selection.read_decisions(path))[-1]


def test_exact_readback_remains_audit_for_an_offered_unprobed_endpoint(tmp_path, scenario, original):
    bindings, _ = scenario
    host_row = next(row for row in bindings["hosts"] if row["host"] == original["choice"]["host"])
    host_row["admission"][original["intent"]] = "unprobed"
    path, attempt = stage_probe(tmp_path, scenario, original)
    assert attempt["admission"] == "unprobed"
    receipt = audit_readback(path, bindings, attempt)
    assert list(selection.read_decisions(path)) == [attempt, receipt]
    assert core.served_of([attempt, receipt], attempt["decision_id"], probe_bindings=(bindings, ("host-a", "host-b"))) is None


def test_probe_history_projection_requires_proof_for_the_original_revision(tmp_path, scenario, original):
    path, attempt = stage_probe(tmp_path, scenario, original)
    bindings, _ = scenario
    identity = attempt["decision_id"]
    receipt = core.observe_served(path, identity, chosen(attempt))
    assert core.served_of([attempt, receipt], identity) is None
    proof = audit_readback(path, bindings, attempt)
    changed = {**proof, "registry_id": "f" * 64}
    changed["outcome"] = {**proof["outcome"], "probe_readback": {
        **proof["outcome"]["probe_readback"], "registry_id": "f" * 64}}
    with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
        core.served_of([attempt, receipt, changed], identity)


@pytest.mark.parametrize("reported", [False, True])
def test_conflicting_observations_survive_and_block_probe_replay(tmp_path, scenario, original, reported):
    path, attempt = stage_probe(tmp_path, scenario, original)
    bindings, _ = scenario
    identity = attempt["decision_id"]
    report = probe_report(attempt)

    def promote(_):
        return core.admit_probe(path, bindings, identity, report, host_kinds=("host-a", "host-b"))

    if reported:
        audit_readback(path, bindings, attempt)
    conflict = core.observe_served(path, identity, fallback())
    before = path.read_bytes()

    def refuse(_):
        with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
            promote(None)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(refuse, range(2), timeout=10))
    refuse(None)
    rows = list(selection.read_decisions(path))
    assert rows[-1] == conflict
    with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
        core.served_of(rows, identity)
    assert sum(choose(scenario, rows)["counts_before"].values()) == 0
    assert path.read_bytes() == before


@pytest.mark.parametrize("known", [False, True])
@pytest.mark.parametrize("outcome", [{"launch_status": "launched"}, {"probe_readback": {}},
                                     {"probe_readback": {"provenance": "runner"}, "served": fallback()}])
def test_both_append_forms_refuse_unproven_transitions(tmp_path, scenario, original, known, outcome):
    path, attempt = stage_probe(tmp_path, scenario, original)
    before = path.read_bytes()
    pending = {**attempt, "outcome": outcome}
    for _ in range(2):
        with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
            if known:
                selection.append_decision(path, None, known_decision=attempt["decision_id"],
                                          prepare=lambda _: pending)
            else:
                selection.append_decision(path, pending)
    assert path.read_bytes() == before
    # A raw history row cannot bypass the same checks either.
    with path.open("ab") as stream:
        stream.write((json.dumps(pending, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
    with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
        list(selection.read_decisions(path))


def test_registry_restoration_cannot_turn_audit_replay_into_admission(tmp_path, scenario, original):
    path, attempt = stage_probe(tmp_path, scenario, original)
    bindings, _ = scenario
    identity, report = attempt["decision_id"], probe_report(attempt)
    hosts = ("host-a", "host-b")
    audit_readback(path, bindings, attempt, hosts)
    before = path.read_bytes()
    changed = copy.deepcopy(bindings)
    changed["hosts"][1]["model"] += "-other-release"
    for current in (changed, bindings):
        with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
            core.admit_probe(path, current, identity, report, host_kinds=hosts)
    assert path.read_bytes() == before


@pytest.mark.parametrize("known", [False, True])
def test_probe_launch_refuses_before_and_after_exact_readback(tmp_path, scenario, original, known):
    path, attempt = stage_probe(tmp_path, scenario, original)
    bindings, _ = scenario
    hosts = ("host-a", "host-b")
    identity = attempt["decision_id"]
    current = (bindings, hosts)
    launch = {**attempt, "outcome": {"launch_status": "launched", "registry_id": attempt["registry_id"]}}

    def append(row, registry):
        if known:
            return selection.append_decision(path, None, known_decision=identity,
                                             prepare=lambda _: row, probe_bindings=registry)
        return selection.append_decision(path, row, probe_bindings=registry)

    before = path.read_bytes()
    with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
        append(launch, current)
    assert path.read_bytes() == before
    audit_readback(path, bindings, attempt, hosts)
    changed = copy.deepcopy(bindings)
    changed["hosts"][1]["model"] += "-other-release"
    for registry in (None, (changed, hosts), current):
        before = path.read_bytes()
        with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
            append(launch, registry)
        assert path.read_bytes() == before
    assert sum(choose(scenario, list(selection.read_decisions(path)))["counts_before"].values()) == 0
    conflict = core.observe_served(path, identity, fallback())
    rows = list(selection.read_decisions(path))
    assert rows[-1] == conflict
    assert sum(choose(scenario, rows)["counts_before"].values()) == 0
    with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
        append(launch, current)
    assert list(selection.read_decisions(path)) == rows
    write_history(path, [*rows, launch])
    with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
        list(selection.read_decisions(path))


def test_concurrent_readback_and_conflicting_observation_leave_audit(tmp_path, scenario, original):
    path, attempt = stage_probe(tmp_path, scenario, original)
    bindings, _ = scenario
    identity = attempt["decision_id"]
    report = probe_report(attempt)

    def promote():
        return core.admit_probe(path, bindings, identity, report, host_kinds=("host-a", "host-b"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        readback = pool.submit(promote)
        audit = pool.submit(core.observe_served, path, identity, fallback()).result(timeout=10)
        with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
            readback.result(timeout=10)
    assert audit in list(selection.read_decisions(path))
    before = path.read_bytes()
    with pytest.raises(selection.ModelSelectionError, match="^decision_outcome_conflict$"):
        promote()
    assert path.read_bytes() == before


def test_replaced_log_refuses_before_creating_temporary_output(tmp_path, original, monkeypatch):
    path = make_store(tmp_path, original)
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"")

    def prepare(row):
        replacement.replace(path)
        return observation(row, chosen(row))

    def unexpected_allocation(_):
        pytest.fail("stale snapshot reached temporary output allocation")

    monkeypatch.setattr(selection, "secrets", SimpleNamespace(token_hex=unexpected_allocation))
    with pytest.raises(selection.ModelSelectionError, match="^stale_decision$"):
        selection.append_decision(path, None, known_decision=original["decision_id"], prepare=prepare)
    assert path.read_bytes() == b""
    assert not list(tmp_path.glob(".model-select-*"))


def test_probe_promotion_refuses_an_ordinary_launch_decision(tmp_path, scenario, original):
    path = make_store(tmp_path, original)
    bindings, _ = scenario
    before = path.read_bytes()
    with pytest.raises(selection.ModelSelectionError, match="^not_probe_attempt$"):
        core.admit_probe(path, bindings, original["decision_id"], probe_report(original),
                         host_kinds=("host-a", "host-b"))
    assert path.read_bytes() == before


@pytest.mark.parametrize("operation", ["stage", "readback", "observe", "conflict"])
def test_probe_file_sync_failure_has_stable_code_and_can_retry(tmp_path, scenario, original, monkeypatch,
                                                               operation):
    path, original = stage_probe(tmp_path, scenario, original)
    bindings, policy = scenario
    hosts = ("host-a", "host-b")
    before = path.read_bytes()

    def fail_sync(descriptor):
        raise OSError(errno.EIO, "descriptor sync failed")

    failing_os = SimpleNamespace(
        O_CREAT=os.O_CREAT, O_EXCL=os.O_EXCL, O_NOFOLLOW=os.O_NOFOLLOW,
        O_NONBLOCK=os.O_NONBLOCK, O_RDONLY=os.O_RDONLY, O_WRONLY=os.O_WRONLY,
        O_CLOEXEC=getattr(os, "O_CLOEXEC", 0), PathLike=os.PathLike, sep=os.sep, altsep=os.altsep,
        close=os.close, fchmod=os.fchmod, fdopen=os.fdopen, fstat=os.fstat, fsync=fail_sync,
        getuid=os.getuid, open=os.open, rename=os.rename, stat=os.stat, unlink=os.unlink, write=os.write,
    )

    def attempt():
        if operation == "readback":
            return core.admit_probe(path, bindings, original["decision_id"], probe_report(original),
                                    host_kinds=hosts)
        if operation == "conflict":
            changed = copy.deepcopy(bindings)
            changed["hosts"][1]["model"] += "-next"
            return core.admit_probe(path, changed, original["decision_id"],
                                    {**probe_report(original), "model": "different"}, host_kinds=hosts)
        if operation == "observe":
            return core.observe_served(path, original["decision_id"], chosen(original))
        return selection.select_and_append(path, bindings, policy, "T2", "implementer", subject="new-probe",
                                           host_kinds=hosts, probe_attempt=True)

    monkeypatch.setattr(selection, "os", failing_os)
    with pytest.raises(selection.ModelSelectionError, match="^probe_decision_io_failed$"):
        attempt()
    assert path.read_bytes() == before
    assert not list(tmp_path.glob(".model-select-*"))
    monkeypatch.setattr(selection, "os", os)
    if operation in ("readback", "conflict"):
        refusal = "probe_readback_mismatch" if operation == "conflict" else "decision_outcome_conflict"
        with pytest.raises(selection.ModelSelectionError, match="^" + refusal + "$"):
            attempt()
    else:
        attempt()
    assert len(list(selection.read_decisions(path))) == 2


def test_probe_promotion_refuses_without_descriptor_support(tmp_path, scenario, original, monkeypatch):
    monkeypatch.setattr(core, "os", SimpleNamespace(name="nt", supports_dir_fd=set()))
    bindings, _ = scenario
    with pytest.raises(selection.ModelSelectionError, match="^anchored_io_unavailable$"):
        core.admit_probe(tmp_path / "unused.jsonl", bindings, original["decision_id"], probe_report(original),
                         host_kinds=("host-a", "host-b"))
    assert list(tmp_path.iterdir()) == []


def malformed_blocks():
    return [None, [], "beta", {}, {**fallback(), "extra": True},
            {**fallback(), "cross_family": True}, {**fallback(), "family": []},
            {**fallback(), "host": "x" * 129}, {**fallback(), "model": "x" * 129},
            {**fallback(), "level": "high\nforged"}, {**fallback(), "family": "beta\x00"},
            {**fallback(), "fallback_reason": "unavailable\rforged"},
            {**fallback(), "fallback_reason": "x" * 129},
            {**fallback(), "fallback_reason": ""},
            {**fallback(), "host": "é"}, {**fallback(), "model": "\ud800"}]


@pytest.mark.parametrize("served", malformed_blocks())
def test_malformed_receipt_refuses_before_io_and_reads_as_absent(tmp_path, original, served):
    path = tmp_path / "never-created"
    for _ in range(2):
        with pytest.raises(selection.ModelSelectionError) as refused:
            core.observe_served(path, original["decision_id"], served)
        assert str(refused.value) == "invalid_served"
    assert list(tmp_path.iterdir()) == []
    rows = [original, observation(original, served)]
    assert core.served_of(rows, original["decision_id"]) is None


@pytest.mark.parametrize("identity", [None, [], {}, 1, "", "x" * 64, "a" * 65, "a\n" * 32])
def test_invalid_decision_id_refuses_without_echo_or_io(tmp_path, identity):
    with pytest.raises(selection.ModelSelectionError) as refused:
        core.observe_served(tmp_path / "never-created", identity, fallback())
    assert str(refused.value) == "invalid_decision_id"
    with pytest.raises(selection.ModelSelectionError, match="^invalid_decision_id$"):
        core.served_of([], identity)
    assert list(tmp_path.iterdir()) == []


def test_absent_malformed_rows_and_unknown_decision_never_infer_chosen(original):
    identity = original["decision_id"]
    assert core.served_of([original], identity) is None
    assert core.served_of([original, observation(original, fallback())], "f" * 64) is None
    rows = [None, [], {}, {"decision_id": identity, "outcome": []}]
    assert core.served_of(rows, identity) is None


@pytest.mark.parametrize("rows", [None, 3, {}])
def test_unreadable_history_is_a_refusal_not_absence(original, rows):
    for _ in range(2):
        with pytest.raises(selection.ModelSelectionError, match="^invalid_history$"):
            core.served_of(rows, original["decision_id"])


def test_reader_refuses_sequence_protocol_history_before_reading(original):
    class History:
        def __getitem__(self, index):
            pytest.fail("unsupported history was read")

    history = History()
    identity = original["decision_id"]

    def refuse(_):
        with pytest.raises(selection.ModelSelectionError, match="^invalid_history$"):
            core.served_of(history, identity)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(refuse, range(2)))
    refuse(None)


def test_reader_refuses_a_broken_iter_without_echo(original):
    class History:
        def __iter__(self):
            pytest.fail("unsupported __iter__ was called")

    history = History()
    for _ in range(2):
        with pytest.raises(selection.ModelSelectionError, match="^invalid_history$"):
            core.served_of(history, original["decision_id"])


@pytest.mark.parametrize("failure", [TypeError("row read failed"),
                                    selection.ModelSelectionError("unsafe_decision_path")])
def test_reader_propagates_row_read_failure_after_valid_receipt(original, failure):
    def history():
        yield original
        yield observation(original, fallback())
        raise failure

    with pytest.raises(type(failure)) as caught:
        core.served_of(history(), original["decision_id"])
    assert caught.value is failure


def test_reader_consumes_iterator_without_calling_its_broken_iter(original):
    served = fallback()

    class History:
        def __init__(self):
            self.records = iter((original, observation(original, served)))

        def __iter__(self):
            return None

        def __next__(self):
            return next(self.records)

    for _ in range(2):
        assert core.served_of(History(), original["decision_id"]) == {**served, "cross_family": True}


@pytest.mark.parametrize("container", [list, tuple])
def test_reader_walks_list_and_tuple_storage_directly(original, container):
    class History(container):
        def __iter__(self):
            pytest.fail("container override was called")

    served = fallback()
    records = (original, observation(original, served))
    for history in (container(records), History(records)):
        assert core.served_of(history, original["decision_id"]) == {**served, "cross_family": True}


@pytest.mark.parametrize("extra", [0, 1])
@pytest.mark.parametrize("has_observation", [False, True])
@pytest.mark.parametrize("known_id", [False, True])
def test_reader_limit_distinguishes_complete_history_from_absence(original, extra, has_observation, known_id):
    rows = [original]
    if has_observation:
        rows.append(observation(original, fallback()))
    rows.extend({} for _ in range(selection.MAX_HISTORY_RECORDS - len(rows) + extra))
    identity = original["decision_id"] if known_id else "f" * 64
    assert len(rows) == selection.MAX_HISTORY_RECORDS + extra
    for _ in range(2):
        if extra:
            with pytest.raises(selection.ModelSelectionError) as refused:
                core.served_of(rows, identity)
            assert str(refused.value) == "history_limit_exceeded: archive_or_rotate_decision_log"
        else:
            expected = {**fallback(), "cross_family": True} if has_observation and known_id else None
            assert core.served_of(rows, identity) == expected


@pytest.mark.parametrize("has_observation", [False, True])
def test_over_limit_generator_reads_only_one_extra_row_on_concurrent_retry(original, has_observation):
    def refuse(_):
        consumed = SimpleNamespace(count=0)

        def rows():
            for index in range(selection.MAX_HISTORY_RECORDS + 2):
                consumed.count += 1
                if index == 0:
                    yield original
                elif index == 1 and has_observation:
                    yield observation(original, fallback())
                else:
                    yield {}

        with pytest.raises(selection.ModelSelectionError) as refused:
            core.served_of(rows(), original["decision_id"])
        assert str(refused.value) == "history_limit_exceeded: archive_or_rotate_decision_log"
        assert consumed.count == selection.MAX_HISTORY_RECORDS + 1

    refuse(None)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(refuse, range(2)))


def test_unknown_decision_refuses_without_publication(tmp_path, original):
    path = make_store(tmp_path, original)
    before = path.read_bytes()
    def refuse(_):
        with pytest.raises(selection.ModelSelectionError) as refused:
            core.observe_served(path, "f" * 64, fallback())
        assert str(refused.value) == "unknown_decision_id"

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(refuse, range(2)))
    refuse(None)
    assert path.read_bytes() == before
    missing = tmp_path / "missing.jsonl"
    with pytest.raises(selection.ModelSelectionError, match="^unknown_decision_id$"):
        core.observe_served(missing, "f" * 64, fallback())
    assert not missing.exists()
    assert not missing.with_name(missing.name + ".lock").exists()


@pytest.mark.parametrize("field", ["host", "model", "level", "family"])
def test_any_changed_identity_requires_a_reason(original, field):
    served = chosen(original)
    served[field] = "different"
    assert core.served_of([original, observation(original, served)], original["decision_id"]) is None
    served["fallback_reason"] = "runtime_fallback"
    assert core.served_of([original, observation(original, served)], original["decision_id"]) == {
        **served, "cross_family": field == "family"}


def test_chosen_receipt_requires_null_reason(original):
    served = {**chosen(original), "fallback_reason": "invented_fallback"}
    assert core.served_of([original, observation(original, served)], original["decision_id"]) is None


@pytest.mark.parametrize("receipt", ["unchanged_with_reason", "fallback_without_reason"])
def test_inconsistent_fallback_reason_refuses_on_retry_without_mutation(tmp_path, original, receipt):
    path = make_store(tmp_path, original)
    served = ({**chosen(original), "fallback_reason": "invented_fallback"}
              if receipt == "unchanged_with_reason" else {**fallback(), "fallback_reason": None})
    before = path.read_bytes()
    for _ in range(2):
        with pytest.raises(selection.ModelSelectionError, match="^invalid_served$"):
            core.observe_served(path, original["decision_id"], served)
    assert path.read_bytes() == before
    assert core.served_of([original, observation(original, served)], original["decision_id"]) is None


@pytest.mark.parametrize("receipt", ["chosen", "fallback"])
@pytest.mark.parametrize("status", [None, "not_launched"])
def test_observation_preserves_launch_state_and_split_counts(tmp_path, original, scenario, receipt, status):
    path = make_store(tmp_path, original)
    if status:
        selection.append_decision(path, {**original, "outcome": {"launch_status": status}})
    before_rows = list(selection.read_decisions(path))
    before_counts = choose(scenario, before_rows)["counts_before"]
    served = chosen(original) if receipt == "chosen" else fallback()
    for _ in range(2):
        result = core.observe_served(path, original["decision_id"], served)
        assert result == observation(original, served)
    rows = list(selection.read_decisions(path))
    assert rows == before_rows + [observation(original, served)] * 2
    assert core.served_of(rows, original["decision_id"]) == {**served, "cross_family": receipt == "fallback"}
    assert choose(scenario, rows)["counts_before"] == before_counts
    assert sum(before_counts.values()) == (0 if status else 1)


def test_newest_valid_receipt_wins_and_invalid_later_receipts_do_not_hide_it(original):
    identity = original["decision_id"]
    rows = [original, observation(original, chosen(original)), observation(original, fallback())]
    for bad in malformed_blocks():
        rows.append(observation(original, bad))
    before = copy.deepcopy(rows)
    result = core.served_of(iter(rows), identity)
    assert result == {**fallback(), "cross_family": True}
    result["family"] = "mutated"
    assert rows == before
    rows.append(observation(original, chosen(original)))
    assert core.served_of(rows, identity) == {**chosen(original), "cross_family": False}


@pytest.mark.parametrize("author", ["beta", None])
def test_coverage_uses_author_and_missing_author_cannot_claim_coverage(scenario, author):
    bindings, policy = scenario
    _, original = selection.select_model(bindings, policy, "T9", "implementer", [],
                                         host_kinds=("host-a", "host-b"), subject="example", author_family=author)
    assert core.served_of([original, observation(original, fallback())], original["decision_id"]) == {
        **fallback(), "cross_family": False}


@pytest.mark.parametrize("status", [None, "not_launched"])
def test_concurrent_appenders_preserve_both_receipts_and_launch_state(tmp_path, original, scenario, status):
    path = make_store(tmp_path, original)
    if status:
        selection.append_decision(path, {**original, "outcome": {"launch_status": status}})
    before_rows = list(selection.read_decisions(path))
    counts = choose(scenario, before_rows)["counts_before"]
    receipts = [chosen(original), fallback()]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda served: core.observe_served(path, original["decision_id"], served), receipts))
    rows = list(selection.read_decisions(path))
    assert len(rows) == len(before_rows) + 2
    assert all(result in rows[len(before_rows):] for result in results)
    last = rows[-1]["outcome"]["served"]
    assert core.served_of(rows, original["decision_id"]) == {**last, "cross_family": last["family"] != "alpha"}
    assert choose(scenario, rows)["counts_before"] == counts


def test_concurrent_malformed_receipts_leave_history_unchanged_then_valid_retry_works(tmp_path, original):
    path = make_store(tmp_path, original)
    before = path.read_bytes()

    def refuse(served):
        with pytest.raises(selection.ModelSelectionError, match="^invalid_served$"):
            core.observe_served(path, original["decision_id"], served)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(refuse, malformed_blocks()))
    assert path.read_bytes() == before
    core.observe_served(path, original["decision_id"], fallback())
    assert core.served_of(selection.read_decisions(path), original["decision_id"]) == {
        **fallback(), "cross_family": True}


@pytest.mark.parametrize("limit", ["records", "bytes"])
def test_history_limit_refuses_concurrent_retries_without_changes(tmp_path, original, limit):
    path = make_store(tmp_path, original)
    encode = lambda row: (json.dumps(row, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode("ascii")
    line = encode(original)
    if limit == "records":
        payload = line * selection.MAX_HISTORY_RECORDS
        assert len(payload) <= selection.MAX_HISTORY_BYTES
    else:
        padded = encode({**original, "outcome": {"padding": "x" * 2000}})
        count, remainder = divmod(selection.MAX_HISTORY_BYTES - len(line), len(padded))
        tail = encode({**original, "outcome": {"padding": ""}})
        if remainder < len(tail):
            count -= 1
            remainder += len(padded)
        tail = encode({**original, "outcome": {"padding": "x" * (remainder - len(tail))}})
        payload = line + padded * count + tail
        assert len(payload) == selection.MAX_HISTORY_BYTES
        assert count + 2 < selection.MAX_HISTORY_RECORDS
        assert len(tail) <= selection.MAX_LINE_BYTES
    path.write_bytes(payload)

    def refuse(_):
        with pytest.raises(selection.ModelSelectionError) as refused:
            core.observe_served(path, original["decision_id"], fallback())
        assert str(refused.value) == "history_limit_exceeded: archive_or_rotate_decision_log"

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(refuse, range(2)))
    refuse(None)
    assert path.read_bytes() == payload
    assert sorted(p.name for p in tmp_path.iterdir()) == [path.name, path.name + ".lock"]


def test_malformed_block_on_disk_reads_as_absent(tmp_path, original):
    path = make_store(tmp_path, original)
    selection.append_decision(path, observation(original, {**fallback(), "extra": True}))
    assert core.served_of(selection.read_decisions(path), original["decision_id"]) is None
    core.observe_served(path, original["decision_id"], fallback())
    selection.append_decision(path, observation(original, {**fallback(), "family": "beta\n"}))
    assert core.served_of(selection.read_decisions(path), original["decision_id"]) == {
        **fallback(), "cross_family": True}


def test_symlink_component_refuses_without_touching_target(tmp_path, original):
    directory = tmp_path / "real"
    directory.mkdir()
    path = make_store(directory, original)
    link = tmp_path / "alias"
    symlink_or_skip(directory, link, target_is_directory=True)
    before = path.read_bytes()
    with pytest.raises(selection.ModelSelectionError, match="^unsafe_decision_path$"):
        core.observe_served(link / path.name, original["decision_id"], fallback())
    assert path.read_bytes() == before


def test_unsupported_platform_refusal_is_preserved_with_probe_disabled(tmp_path, original, monkeypatch):
    monkeypatch.setattr(core, "os", SimpleNamespace(name="nt", supports_dir_fd=set()))
    with pytest.raises(selection.ModelSelectionError, match="^anchored_io_unavailable$"):
        core.observe_served(tmp_path / "receipts.jsonl", original["decision_id"], fallback())
    assert list(tmp_path.iterdir()) == []


def test_rotation_cannot_republish_a_suppressed_first_launch(tmp_path, original, scenario, monkeypatch):
    """A receipt must name a decision in the generation that receives it.

    Wiping the log after lookup is the cooperating rotation. An empty generation
    would otherwise admit this not_launched first row as a fresh launch.
    """
    path = make_store(tmp_path, original)
    selection.append_decision(path, {**original, "outcome": {"launch_status": "not_launched"}})
    preserved = path.read_bytes()
    real_append = selection.append_decision
    state = {"rotate": True}

    def rotate_then_append(log_path, record=None, **kwargs):
        if state["rotate"]:
            log_path.write_bytes(b"")
            log_path.chmod(0o600)
        return real_append(log_path, record, **kwargs)

    monkeypatch.setattr(selection, "append_decision", rotate_then_append)
    for _ in range(2):
        with pytest.raises(selection.ModelSelectionError, match="^unknown_decision_id$"):
            core.observe_served(path, original["decision_id"], fallback())
    assert path.read_bytes() == b""
    assert not list(tmp_path.glob(".model-select-*"))
    state["rotate"] = False
    path.write_bytes(preserved)
    path.chmod(0o600)
    result = core.observe_served(path, original["decision_id"], fallback())
    rows = list(selection.read_decisions(path))
    assert result == observation(original, fallback())
    assert rows[-1] == result
    assert sum(choose(scenario, rows)["counts_before"].values()) == 0


def test_changed_generation_refuses_receipt_before_rename(tmp_path, original, monkeypatch):
    path = make_store(tmp_path, original)
    selection.append_decision(path, {**original, "outcome": {"launch_status": "not_launched"}})
    state = {"swapped": False}

    def swap_on_sync(descriptor):
        # The file fsync runs after the snapshot is taken and before the generation check.
        os.fsync(descriptor)
        if state["swapped"]:
            return
        replacement = tmp_path / "replacement"
        replacement.write_bytes(b"")
        replacement.chmod(0o600)
        replacement.replace(path)
        state["swapped"] = True

    monkeypatch.setattr(selection, "os", SimpleNamespace(**{**vars(os), "fsync": swap_on_sync}))
    with pytest.raises(selection.ModelSelectionError, match="^stale_decision$"):
        core.observe_served(path, original["decision_id"], fallback())
    monkeypatch.setattr(selection, "os", os)
    assert state["swapped"]
    assert path.read_bytes() == b""
    assert not list(tmp_path.glob(".model-select-*"))
    assert not (tmp_path / "replacement").exists()

    def refuse(_):
        with pytest.raises(selection.ModelSelectionError, match="^unknown_decision_id$"):
            core.observe_served(path, original["decision_id"], fallback())

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(refuse, range(2)))
    refuse(None)
    assert path.read_bytes() == b""


def test_directory_flush_failure_leaves_visible_receipt_and_closed_descriptors(
        tmp_path, original, scenario, monkeypatch):
    path = make_store(tmp_path, original)
    selection.append_decision(path, {**original, "outcome": {"launch_status": "not_launched"}})
    opened = []

    def fail_directory_fsync(descriptor):
        os.fsync(descriptor)
        opened.append(descriptor)
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError(errno.EIO, "directory flush failed")

    monkeypatch.setattr(selection, "os", SimpleNamespace(**{**vars(os), "fsync": fail_directory_fsync}))
    with pytest.raises(OSError, match="directory flush failed") as raised:
        core.observe_served(path, original["decision_id"], fallback())
    monkeypatch.setattr(selection, "os", os)
    assert raised.value.errno == errno.EIO
    assert opened
    for descriptor in opened:
        with pytest.raises(OSError) as closed:
            os.fstat(descriptor)
        assert closed.value.errno == errno.EBADF
    assert not list(tmp_path.glob(".model-select-*"))
    rows = list(selection.read_decisions(path))
    assert rows[-1] == observation(original, fallback())
    again = core.observe_served(path, original["decision_id"], fallback())
    rows = list(selection.read_decisions(path))
    assert again == rows[-1] == observation(original, fallback())
    assert sum(choose(scenario, rows)["counts_before"].values()) == 0


def test_receipt_fdopen_failure_closes_descriptor_and_retries(tmp_path, original, scenario, monkeypatch):
    path = make_store(tmp_path, original)
    selection.append_decision(path, {**original, "outcome": {"launch_status": "not_launched"}})
    before = path.read_bytes()
    fdopen, fsync, synced, failed = os.fdopen, os.fsync, [], []

    def track_sync(descriptor):
        fsync(descriptor)
        synced.append(descriptor)

    def fail_probe(descriptor, *args, **kwargs):
        if synced:
            failed.append(descriptor)
            raise OSError(errno.EIO, "probe stream unavailable")
        return fdopen(descriptor, *args, **kwargs)

    monkeypatch.setattr(selection, "os", SimpleNamespace(
        **{**vars(os), "fdopen": fail_probe, "fsync": track_sync}))
    with pytest.raises(OSError, match="probe stream unavailable") as raised:
        core.observe_served(path, original["decision_id"], fallback())
    monkeypatch.setattr(selection, "os", os)
    assert raised.value.errno == errno.EIO
    assert len(failed) == 1
    with pytest.raises(OSError) as closed:
        os.fstat(failed[0])
    assert closed.value.errno == errno.EBADF
    assert path.read_bytes() == before
    assert not list(tmp_path.glob(".model-select-*"))
    result = core.observe_served(path, original["decision_id"], fallback())
    rows = list(selection.read_decisions(path))
    assert result == rows[-1] == observation(original, fallback())
    assert sum(choose(scenario, rows)["counts_before"].values()) == 0


def test_corrupt_snapshot_refuses_receipt_without_publication(tmp_path, original):
    path = make_store(tmp_path, original)
    raw = path.read_bytes() + b"{broken}\n"
    path.write_bytes(raw)

    def refuse(_):
        with pytest.raises(selection.ModelSelectionError, match="^invalid_history$"):
            core.observe_served(path, original["decision_id"], fallback())

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(refuse, range(2)))
    refuse(None)
    assert path.read_bytes() == raw
    assert not list(tmp_path.glob(".model-select-*"))
