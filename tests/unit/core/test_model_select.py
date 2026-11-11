"""Public selector contract: refusals first, then deterministic choices and audit I/O."""
import copy
import errno
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from aegis_core import model_select as core
from aegis_core.model_select import (
    MAX_LINE_BYTES,
    ModelSelectionError,
    append_decision,
    read_decisions as core_read_decisions,
    select_model as core_select_model,
)

requires_anchored_io = pytest.mark.skipif(
    os.name != "posix", reason="POSIX anchored-log behavior; unsupported-platform refusal has its own test")


@pytest.fixture
def bindings():
    return json.loads((Path(__file__).resolve().parents[3] /
                       "tools/hierarchy_templates/model-bindings.json").read_text())


@pytest.fixture
def policy():
    # Host and family names have no built-in meaning to the core.
    return {"team_id": "team-one", "manager_family": "second", "team_family": "first",
            "target_shares": {"first": 0.7, "second": 0.3},
            "family_order": ["first", "second"], "flexible_tasks": ["T9", "T10", "T14"],
            "family_hosts": {"first": ["codex-cli"], "second": ["claude-code"]},
            "review_families": {"T4": {"primary": "second"}, "T5": {"primary": "first"},
                                "T6": {"primary": "first", "whole": "second"},
                                "T8": {"primary": "opposite", "second": "author"}},
            "task_intents": {"T5": {"first": "extended", "second": "deep"},
                             "T8": {"first": "extended", "second": "extended"}}}


def select_model(*args, **kwargs):
    kwargs.setdefault("subject", "lane-one")
    kwargs.setdefault("host_kinds", ("codex-cli", "claude-code"))
    return core_select_model(*args, **kwargs)


def read_decisions(path):
    """Consume the public stream for snapshot assertions in these tests."""
    return list(core_read_decisions(path))


def choose(bindings, policy, **kwargs):
    return select_model(bindings, policy, "T9", "implementer", [], **kwargs)


def test_model_selection_document_names_every_public_function():
    document = (Path(__file__).resolve().parents[3] / "docs/model-selection.md").read_text(encoding="utf-8")
    for name in core.__all__:
        if callable(getattr(core, name)) and not isinstance(getattr(core, name), type):
            assert name in document


@pytest.mark.parametrize("task,role,error", [
    ("unknown", "implementer", "unknown_task_kind"),
    ("T2", "router", "unknown_role_kind"),
    ("T2", "orchestrator", "task_role_mismatch"),
])
def test_unknown_kinds_and_incompatible_seats(bindings, policy, task, role, error):
    with pytest.raises(ModelSelectionError, match="^" + error + "$"):
        select_model(bindings, policy, task, role, [])


@pytest.mark.parametrize("intent,error", [("ultra", "unknown_intent"),
                                          ("bogus", "unknown_intent"),
                                          ("light", "intent_outside_role_band")])
def test_invalid_intents(bindings, policy, intent, error):
    with pytest.raises(ModelSelectionError, match="^" + error + "$"):
        choose(bindings, policy, intent=intent)


@pytest.mark.parametrize("case", ["schema", "roles", "hosts", "duplicate-role", "duplicate-host",
                                  "band", "ultra", "model", "levels", "admission", "class"])
def test_malformed_bindings(bindings, policy, case):
    if case in ("schema", "roles", "hosts"):
        bindings[case] = None
    elif case == "duplicate-role":
        bindings["roles"].append(bindings["roles"][0])
    elif case == "duplicate-host":
        bindings["hosts"].append(bindings["hosts"][0])
    elif case == "band":
        bindings["roles"][0]["band"]["floor"] = "max"
    elif case == "ultra":
        bindings["roles"][0]["band"]["default"] = "ultra"
    elif case == "model":
        bindings["hosts"][0]["model"] = ""
    elif case == "levels":
        bindings["hosts"][0]["levels"]["ultra"] = "ultra"
    elif case == "admission":
        bindings["hosts"][0]["admission"]["deep"] = "bogus"
    else:
        bindings["roles"][0]["model_class"] = "frontier"
    with pytest.raises(ModelSelectionError, match="^invalid_bindings$"):
        choose(bindings, policy)


@pytest.mark.parametrize("shares,code", [({}, "target_shares_shape"),
    ({"first": -1, "second": 2}, "target_shares_values"),
    ({"first": True, "second": 0}, "target_shares_values"),
    ({"first": float("nan"), "second": 0.3}, None),
    ({"first": 0.8, "second": 0.3}, "target_shares_sum")])
def test_bad_policy_shares(bindings, policy, shares, code):
    policy["target_shares"] = shares
    with pytest.raises(ModelSelectionError, match="^invalid_policy" + (":" + code if code else "") + "$"):
        choose(bindings, policy)


def test_review_requires_known_author(bindings, policy):
    for author in (None, "unknown"):
        with pytest.raises(ModelSelectionError, match="^invalid_author_family$"):
            select_model(bindings, policy, "T8", "reviewer", [], author_family=author)


def test_rejected_or_missing_binding_never_falls_back(bindings, policy):
    row = next(r for r in bindings["hosts"] if r["host"] == "codex-cli" and r["class"] == "coding")
    row["admission"]["deep"] = "rejected"
    with pytest.raises(ModelSelectionError, match="^invalid_bindings$"):
        choose(bindings, policy)
    row["admission"]["deep"] = "unprobed"
    del row["levels"]["deep"]
    del row["admission"]["deep"]
    with pytest.raises(ModelSelectionError, match="^invalid_bindings$"):
        choose(bindings, policy)


def test_family_split_and_replay(bindings, policy):
    before = copy.deepcopy((bindings, policy))
    history = []
    for _ in range(10):
        choice, record = select_model(bindings, policy, "T9", "implementer", history)
        assert (choice, record) == select_model(bindings, policy, "T9", "implementer", history)
        assert record["choice"] == choice
        history.append(record)
    assert [r["choice"]["family"] for r in history] == [
        "first", "second", "first", "first", "second", "first", "first", "second", "first", "first"]
    assert choice == {"host": "codex-cli", "class": "coding", "model": "gpt-6.1-sol",
                      "level": "high", "family": "first", "reason": "family_split", "admission": "unprobed"}
    assert (bindings, policy) == before


@requires_anchored_io
def test_policy_path_and_bindings_path(bindings, policy, tmp_path):
    bp, pp = tmp_path / "bindings.json", tmp_path / "policy.json"
    bp.write_text(json.dumps(bindings))
    pp.write_text(json.dumps(policy))
    assert choose(bp, pp) == choose(bindings, policy)
    pp.write_text('{"team_id":"a","team_id":"b"}')
    with pytest.raises(ModelSelectionError, match="^invalid_policy$"):
        choose(bp, pp)
    with pytest.raises(ModelSelectionError, match="^invalid_bindings$"):
        choose(tmp_path / "missing", policy)


def test_configurable_target_and_explicit_order(bindings, policy):
    policy["target_shares"] = {"second": 0.5, "first": 0.5}
    assert choose(bindings, policy)[0]["family"] == "first"
    policy["target_shares"] = {"first": 0, "second": 1}
    assert choose(bindings, policy)[0]["family"] == "second"


@pytest.mark.parametrize("role", ["orchestrator", "decider"])
def test_managers_use_configured_family(bindings, policy, role):
    choice, record = select_model(bindings, policy, "T1", role, [])
    assert choice["family"] == "second"
    assert choice["level"] == "medium"
    assert choice["reason"] == "manager_family"
    assert not record["split_eligible"]
    with pytest.raises(ModelSelectionError, match="^intent_outside_role_band$"):
        select_model(bindings, policy, "T1", role, [], intent="deep")


@pytest.mark.parametrize("task,family", [("T4", "second"), ("T5", "first"), ("T6", "first"), ("T8", "second")])
def test_configured_reviews_and_amended_efforts(bindings, policy, task, family):
    choice, record = select_model(bindings, policy, task, "reviewer", [], author_family="first")
    assert choice["family"] == family
    assert choice["reason"] == "review_policy"
    assert choice["level"] == ("xhigh" if task in ("T5", "T8") else "high")
    assert not record["split_eligible"]


def test_renamed_hosts_and_models_are_data(bindings, policy):
    for row in bindings["hosts"]:
        row["host"] = {"codex-cli": "local-a", "claude-code": "local-b"}[row["host"]]
        row["model"] = "new-" + row["model"]
    policy["family_hosts"] = {"first": ["local-a"], "second": ["local-b"]}
    assert choose(bindings, policy, host_kinds=("local-a", "local-b"))[0]["host"] == "local-a"


def test_team_history_and_fixed_decisions_do_not_skew_split(bindings, policy):
    _, fixed = select_model(bindings, policy, "T1", "orchestrator", [])
    _, other = choose(bindings, dict(policy, team_id="other-team"))
    choice, record = select_model(bindings, policy, "T9", "implementer", [fixed, other])
    expected_choice, expected_record = choose(bindings, policy)
    assert choice == expected_choice and record["counts_before"] == expected_record["counts_before"]
    assert record["previous_decision_id"] == fixed["decision_id"]
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        select_model(bindings, policy, "T9", "implementer", [{"family": "unknown"}])


@requires_anchored_io
def test_jsonl_append_preserves_bytes_and_outcomes(bindings, policy, tmp_path):
    path = tmp_path / "decisions.jsonl"
    _, record = choose(bindings, policy)
    append_decision(path, record)
    first = path.read_bytes()
    record["outcome"] = {"tests_passed": False, "finding": "P1"}
    append_decision(path, record)
    assert path.read_bytes().startswith(first)
    assert read_decisions(path) == [dict(record, outcome=None), record]
    assert all(len(line) + 1 <= MAX_LINE_BYTES for line in path.read_bytes().splitlines())


@requires_anchored_io
def test_jsonl_rejects_oversized_record_before_append(bindings, policy, tmp_path):
    path = tmp_path / "decisions.jsonl"
    _, record = choose(bindings, policy)
    append_decision(path, record)
    before = path.read_bytes()
    record["outcome"] = "x" * MAX_LINE_BYTES
    with pytest.raises(ModelSelectionError, match="^decision_line_too_large$"):
        append_decision(path, record)
    assert path.read_bytes() == before


@pytest.mark.parametrize("raw", [b'{bad}\n', b'{}\n', b'{"x":1}', b'\xff\n', b'\n'])
@requires_anchored_io
def test_corrupt_history_is_never_reset(tmp_path, raw):
    path = tmp_path / "decisions.jsonl"
    path.write_bytes(raw)
    path.chmod(0o600)
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        read_decisions(path)


@requires_anchored_io
def test_concurrent_appends_are_complete(bindings, policy, tmp_path):
    path = tmp_path / "decisions.jsonl"
    _, record = choose(bindings, policy)
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(lambda _: append_decision(path, record), range(18)))
    assert read_decisions(path) == [record] * 18


@requires_anchored_io
def test_missing_log_and_nonregular_target(bindings, policy, tmp_path):
    assert read_decisions(tmp_path / "missing") == []
    with pytest.raises(ModelSelectionError, match="^unsafe_decision_path$"):
        read_decisions(tmp_path)
    _, record = choose(bindings, policy)
    with pytest.raises(ModelSelectionError, match="^unsafe_decision_path$"):
        append_decision(tmp_path, record)


def test_outcome_observations_do_not_count_a_second_launch(bindings, policy):
    _, original = choose(bindings, policy)
    observation = dict(original, outcome={"review": "REQUEST_CHANGES"})
    assert select_model(bindings, policy, "T9", "implementer", [original, observation]) == (
        select_model(bindings, policy, "T9", "implementer", [original]))


def test_conflicting_or_forged_decision_identity_is_rejected(bindings, policy):
    _, original = choose(bindings, policy)
    forged = copy.deepcopy(original)
    forged["choice"]["family"] = "second"
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        select_model(bindings, policy, "T9", "implementer", [forged])


@requires_anchored_io
def test_corrupt_log_is_not_extended(bindings, policy, tmp_path):
    path = tmp_path / "decisions.jsonl"
    path.write_bytes(b'{bad}\n')
    path.chmod(0o600)
    _, record = choose(bindings, policy)
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        append_decision(path, record)
    assert path.read_bytes() == b'{bad}\n'


@requires_anchored_io
def test_oversized_existing_line_is_rejected(tmp_path):
    path = tmp_path / "decisions.jsonl"
    path.write_bytes(b' ' * MAX_LINE_BYTES + b'\n')
    path.chmod(0o600)
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        read_decisions(path)


@requires_anchored_io
def test_symlink_log_is_neither_read_nor_written(bindings, policy, tmp_path):
    target, link = tmp_path / "target", tmp_path / "link"
    _, record = choose(bindings, policy)
    append_decision(target, record)
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    for operation in (lambda: read_decisions(link), lambda: append_decision(link, record)):
        with pytest.raises(ModelSelectionError, match="^unsafe_decision_path$"):
            operation()
    assert read_decisions(target) == [record]


@requires_anchored_io
def test_lock_timeout_is_explicit(bindings, policy, tmp_path):
    import subprocess
    import sys
    from aegis_core.storage import file_lock

    path = tmp_path / "decisions.jsonl"
    _, record = choose(bindings, policy)
    append_decision(path, record)
    code = ("from aegis_core import model_select as core; core._LOCK_TIMEOUT_SECONDS = 0.05; "
            "list(core.read_decisions(" + repr(str(path)) + "))")
    with file_lock(path.with_name(path.name + ".lock")):
        proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=15)
    assert proc.returncode != 0
    assert "LockTimeoutError" in proc.stderr


@pytest.mark.parametrize("value", [None, [], True, {"bad": []}])
def test_untyped_binding_input_has_exact_error(policy, value):
    with pytest.raises(ModelSelectionError, match="^invalid_bindings$"):
        choose(value, policy)


@pytest.mark.parametrize("task,role", [("T3", "implementer"), ("T7", "integrator"),
                                      ("T9", "implementer"), ("T10", "implementer"),
                                      ("T11", "implementer"), ("T12", "implementer"),
                                      ("T13", "implementer"), ("T14", "implementer")])
def test_remaining_task_defaults_are_role_data(bindings, policy, task, role):
    choice, _ = select_model(bindings, policy, task, role, [], lane_family="first" if task == "T3" else None)
    assert choice["class"] == "coding" and choice["level"] == "high"


def test_primary_fact_check_requires_another_family(bindings, policy):
    choice, _ = select_model(bindings, policy, "T8", "reviewer", [], author_family="second")
    assert choice["family"] == "first"


def test_binding_band_default_is_used_without_override(bindings, policy):
    next(r for r in bindings["roles"] if r["kind"] == "implementer")["band"]["default"] = "extended"
    assert choose(bindings, policy)[0]["level"] == "xhigh"


@requires_anchored_io
def test_policy_and_bindings_duplicate_json_keys_are_rejected(bindings, policy, tmp_path):
    path = tmp_path / "bindings.json"
    path.write_text('{"schema":"a","schema":"b"}')
    with pytest.raises(ModelSelectionError, match="^invalid_bindings$"):
        choose(path, policy)


def test_nonfinite_outcome_is_not_written(bindings, policy, tmp_path):
    path = tmp_path / "decisions.jsonl"
    _, record = choose(bindings, policy)
    record["outcome"] = float("nan")
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        append_decision(path, record)
    assert not path.exists()


@pytest.mark.parametrize("outcome", [object(), {"nested": [object()]}, {"set"},
                                     ("tuple",), {1: "non-string-key"}, float("inf")],
                         ids=["object", "nested-object", "set", "tuple", "key-type", "infinite"])
def test_non_json_outcomes_are_refused_by_history_validation(bindings, policy, tmp_path, outcome):
    _, record = choose(bindings, policy)
    record["outcome"] = outcome
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        select_model(bindings, policy, "T2", "implementer", [record])
    path = tmp_path / "decisions.jsonl"
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        append_decision(path, record)
    assert not path.exists()


def test_cyclic_outcome_is_refused_by_history_validation(bindings, policy):
    _, record = choose(bindings, policy)
    cycle = []
    cycle.append(cycle)
    record["outcome"] = cycle
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        select_model(bindings, policy, "T2", "implementer", [record])


@requires_anchored_io
def test_nested_json_outcome_round_trips(bindings, policy, tmp_path):
    _, record = choose(bindings, policy)
    record["outcome"] = {"values": [None, True, "passed", 3, 0.25, {"retry": False}]}
    path = tmp_path / "decisions.jsonl"
    append_decision(path, record)
    assert read_decisions(path) == [record]


@pytest.mark.parametrize("target,sequence", [(0.5, "XLLXLXLXLX"), (0.6, "XLXLXLXXLX"),
    (0.7, "XLXXLXXLXX"), (0.75, "XLXXLXXXLX"), (0.8, "XLXXXLXXXX"), (0.9, "XLXXXXXXXX")])
def test_build_family_split_sequences_and_renaming(bindings, policy, target, sequence):
    check_split_sequence(bindings, policy, target, sequence)


@pytest.mark.parametrize("target,sequence", [(0.0, "LLLLLLLLLL"), (1.0, "XXXXXXXXXX")])
def test_zero_share_endpoint_override_intentionally_diverges_from_build_tool(bindings, policy, target, sequence):
    check_split_sequence(bindings, policy, target, sequence)


def check_split_sequence(bindings, policy, target, sequence):
    from fractions import Fraction

    policy["target_shares"] = {"first": target, "second": float(1 - Fraction(str(target)))}
    for names in (("first", "second"), ("zulu", "alpha")):
        rename = dict(zip(("first", "second"), names))
        changed = copy.deepcopy(policy)
        for key in ("target_shares", "family_hosts"):
            changed[key] = {rename[k]: v for k, v in changed[key].items()}
        for key in ("manager_family", "team_family"):
            changed[key] = rename[changed[key]]
        changed["family_order"] = list(names)
        changed["review_families"] = {t: {s: rename.get(f, f) for s, f in row.items()}
                                      for t, row in changed["review_families"].items()}
        changed["task_intents"] = {t: {rename[f]: v for f, v in row.items()}
                                   for t, row in changed["task_intents"].items()}
        history, actual = [], ""
        for i in range(10):
            choice, record = select_model(bindings, changed, "T9", "implementer", history, subject="scan-%d" % i)
            history.append(record)
            actual += "X" if choice["family"] == names[0] else "L"
        assert actual == sequence


@pytest.mark.parametrize("role", ["implementer", "integrator"])
def test_writers_and_router_helpers_stay_on_team_family(bindings, policy, role):
    for task in ("T2", "T13"):
        choice, record = select_model(bindings, policy, task, role, [])
        assert choice["family"] == policy["team_family"]
        assert choice["reason"] == "team_family" and not record["split_eligible"]
    choice, record = select_model(bindings, policy, "T3", role, [], lane_family="first")
    assert choice["family"] == "first" and choice["reason"] == "lane_family"
    with pytest.raises(ModelSelectionError, match="^invalid_lane_family$"):
        select_model(bindings, policy, "T3", role, [])


def test_undeclared_flexible_task_stays_on_team(bindings, policy):
    policy["flexible_tasks"] = []
    choice, record = choose(bindings, policy)
    assert choice["family"] == "first" and not record["split_eligible"]


def test_same_family_security_and_explicit_second_fact_check(bindings, policy):
    security, _ = select_model(bindings, policy, "T5", "reviewer", [], author_family="first")
    assert security["family"] == "first" and security["level"] == "xhigh"
    primary, _ = select_model(bindings, policy, "T8", "reviewer", [], author_family="first")
    second, _ = select_model(bindings, policy, "T8", "reviewer", [], author_family="first", review_stage="second")
    assert primary["family"] == "second" and second["family"] == "first"
    assert primary["level"] == second["level"] == "xhigh"
    with pytest.raises(ModelSelectionError, match="^invalid_review_stage$"):
        select_model(bindings, policy, "T5", "reviewer", [], author_family="first", review_stage="unknown")


def test_required_subject_distinguishes_reviews(bindings, policy):
    a = select_model(bindings, policy, "T4", "reviewer", [], subject="lane-a/endpoint/1", author_family="first")[1]
    b = select_model(bindings, policy, "T4", "reviewer", [], subject="lane-b/endpoint/1", author_family="first")[1]
    assert a["subject"] != b["subject"] and a["decision_id"] != b["decision_id"]
    with pytest.raises(ModelSelectionError, match="^invalid_subject$"):
        core_select_model(bindings, policy, "T2", "implementer", [], host_kinds=("codex-cli", "claude-code"))


def test_admission_provenance_is_explicit(bindings, policy):
    for status in ("unprobed", "admitted"):
        for row in bindings["hosts"]:
            row["admission"] = dict.fromkeys(row["levels"], status)
        choice, record = choose(bindings, policy)
        assert choice["admission"] == record["admission"] == status


@pytest.mark.parametrize("field", ["bindings", "policy"])
@pytest.mark.parametrize("shape", ["huge", "symlink", "directory", "device", "fifo"])
def test_config_paths_are_bounded_regular_files(bindings, policy, tmp_path, field, shape):
    path = tmp_path / "input.json"
    if shape == "huge":
        path.write_bytes(b" " * (core.MAX_INPUT_BYTES + 1))
    elif shape == "symlink":
        target = tmp_path / "target.json"
        target.write_text(json.dumps(bindings if field == "bindings" else policy))
        try:
            path.symlink_to(target)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable")
    elif shape == "directory":
        path.mkdir()
    elif shape == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFOs unavailable")
        os.mkfifo(path)
    else:
        if os.name != "posix":
            pytest.skip("POSIX device only")
        path = Path("/dev/zero")
    error = "anchored_io_unavailable" if os.name != "posix" else "invalid_" + field
    with pytest.raises(ModelSelectionError, match="^" + error + "$"):
        choose(path if field == "bindings" else bindings, path if field == "policy" else policy)


@pytest.mark.parametrize("cap", ["records", "bytes"])
@requires_anchored_io
def test_history_limits_refuse_and_preserve_existing_bytes(bindings, policy, tmp_path, monkeypatch, cap):
    path = tmp_path / "decisions.jsonl"
    _, record = choose(bindings, policy)
    append_decision(path, record)
    line = path.read_bytes()
    if cap == "records":
        monkeypatch.setattr(core, "MAX_HISTORY_RECORDS", 1)
    else:
        monkeypatch.setattr(core, "MAX_HISTORY_BYTES", len(line))
    assert read_decisions(path) == [record]
    error = "^history_limit_exceeded: archive_or_rotate_decision_log$"
    with pytest.raises(ModelSelectionError, match=error):
        append_decision(path, record)
    assert path.read_bytes() == line
    path.write_bytes(line * 2)
    with pytest.raises(ModelSelectionError, match=error):
        read_decisions(path)


@pytest.mark.parametrize("surface", ["append", "transaction"])
@pytest.mark.parametrize("existing", [False, True])
@requires_anchored_io
def test_partial_write_then_enospc_does_not_change_history(bindings, policy, tmp_path, monkeypatch,
                                                         existing, surface):
    path = tmp_path / "decisions.jsonl"
    _, record = choose(bindings, policy)
    if existing:
        append_decision(path, record)
    before = path.read_bytes() if existing else b""
    write, calls = os.write, []

    def fail_after_prefix(fd, data):
        calls.append(fd)
        if existing and len(calls) == 1:
            return write(fd, data)  # copy the original line successfully
        if len(calls) == (2 if existing else 1):
            return write(fd, data[:7])
        raise OSError(errno.ENOSPC, "injected disk full")

    with monkeypatch.context() as patch:
        patch.setattr(os, "write", fail_after_prefix)
        with pytest.raises(OSError) as caught:
            if surface == "append":
                append_decision(path, record)
            else:
                core.select_and_append(path, bindings, policy, "T9", "implementer",
                                       host_kinds=("codex-cli", "claude-code"), subject="lane-one")
        assert caught.value.errno == errno.ENOSPC
    assert len(calls) == (3 if existing else 2)
    assert (path.read_bytes() if path.exists() else b"") == before
    assert read_decisions(path) == ([record] if existing else [])
    assert path.exists() == existing
    assert sorted(p.name for p in tmp_path.iterdir()) == (
        ["decisions.jsonl", "decisions.jsonl.lock"] if existing else ["decisions.jsonl.lock"])


@requires_anchored_io
def test_fifo_decision_path_is_refused(bindings, policy, tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFOs unavailable")
    path = tmp_path / "pipe"
    os.mkfifo(path)
    _, record = choose(bindings, policy)
    for operation in (lambda: read_decisions(path), lambda: append_decision(path, record)):
        with pytest.raises(ModelSelectionError, match="^unsafe_decision_path$"):
            operation()


@pytest.mark.parametrize("case", ["shape", "missing", "extra", "team-id", "share-key", "share-type",
    "share-total", "families-shape", "families-keys", "manager", "team", "order-type", "order-size",
    "order-unknown", "order-duplicate", "flexible-type", "flexible-protected", "flexible-duplicate",
    "review-keys", "review-shape", "review-primary", "review-stage-token", "review-family", "host-type",
    "host-empty", "host-token", "host-duplicate", "host-overlap", "host-unknown", "task-type", "task-unknown",
    "task-shape", "task-empty", "task-family", "task-intent"])
def test_all_policy_refusals_have_exact_error(bindings, policy, case):
    replacements = {
        "missing": ("team_family", None), "extra": ("unknown", True), "team-id": ("team_id", "bad id"),
        "share-key": ("target_shares", {"bad family": 1}),
        "share-type": ("target_shares", {"first": "0.7", "second": 0.3}),
        "share-total": ("target_shares", {"first": 0.7, "second": 0.3000000000001}),
        "families-shape": ("family_hosts", []), "families-keys": ("family_hosts", {}),
        "manager": ("manager_family", "other"), "team": ("team_family", "other"),
        "order-type": ("family_order", "first"), "order-size": ("family_order", ["first"]),
        "order-unknown": ("family_order", ["first", "other"]),
        "order-duplicate": ("family_order", ["first", "first"]),
        "flexible-type": ("flexible_tasks", "T9"), "flexible-protected": ("flexible_tasks", ["T2"]),
        "flexible-duplicate": ("flexible_tasks", ["T9", "T9"]),
        "review-keys": ("review_families", {}), "task-type": ("task_intents", []),
        "task-unknown": ("task_intents", {"unknown": {"first": "deep"}}),
        "task-shape": ("task_intents", {"T9": []}), "task-empty": ("task_intents", {"T9": {}}),
        "task-family": ("task_intents", {"T9": {"other": "deep"}}),
        "task-intent": ("task_intents", {"T9": {"first": "ultra"}}),
    }
    if case == "shape":
        policy = []
    elif case in replacements:
        key, value = replacements[case]
        if case == "missing":
            del policy[key]
        else:
            policy[key] = value
    elif case.startswith("review-"):
        policy["review_families"]["T4"] = {
            "review-shape": [], "review-primary": {"second": "first"},
            "review-stage-token": {"primary": "first", "bad stage": "second"},
            "review-family": {"primary": "other"}}[case]
    else:
        policy["family_hosts"]["first"] = {
            "host-type": "codex-cli", "host-empty": [], "host-token": ["bad host"],
            "host-duplicate": ["codex-cli", "codex-cli"], "host-overlap": ["claude-code"],
            "host-unknown": ["missing-host"]}[case]
    codes = {
        "shape": "shape", "missing": "shape", "extra": "shape", "team-id": "team_id",
        "share-key": "target_shares_shape", "share-type": "target_shares_values",
        "share-total": "target_shares_sum", "families-shape": "family_hosts_keys",
        "families-keys": "family_hosts_keys", "manager": "manager_family", "team": "team_family",
        "order-type": "family_order", "order-size": "family_order", "order-unknown": "family_order",
        "order-duplicate": "family_order", "flexible-type": "flexible_tasks",
        "flexible-protected": "flexible_tasks", "flexible-duplicate": "flexible_tasks",
        "review-keys": "review_families_keys", "review-shape": "review_families:T4:stages",
        "review-primary": "review_families:T4:stages", "review-stage-token": "review_families:T4:stages",
        "review-family": "review_families:T4:families", "host-type": "family_hosts_values",
        "host-empty": "family_hosts_values", "host-token": "family_hosts_values",
        "host-duplicate": "family_hosts_unique", "host-overlap": "family_hosts_unique",
        "host-unknown": "family_hosts_registry", "task-type": "task_intents_shape",
        "task-unknown": "task_intents_task", "task-shape": "task_intents_task",
        "task-empty": "task_intents_task", "task-family": "task_intents_values",
        "task-intent": "task_intents_values",
    }
    with pytest.raises(ModelSelectionError, match="^invalid_policy:" + codes[case] + "$"):
        choose(bindings, policy)


@pytest.mark.parametrize("band", [{"floor": "light", "default": "deep", "ceiling": "standard"},
    {"floor": "max", "default": "deep", "ceiling": "max"},
    {"floor": "standard", "default": "deep"}, {"floor": "light", "default": "ultra", "ceiling": "max"}])
def test_role_band_invariants(bindings, policy, band):
    bindings["roles"][0]["band"] = band
    with pytest.raises(ModelSelectionError, match="^invalid_bindings$"):
        choose(bindings, policy)


def test_chosen_host_lacks_coding_row(bindings, policy):
    bindings["hosts"] = [r for r in bindings["hosts"] if (r["host"], r["class"]) != ("codex-cli", "coding")]
    with pytest.raises(ModelSelectionError, match="^invalid_bindings$"):
        select_model(bindings, policy, "T2", "implementer", [])


@pytest.mark.parametrize("missing", [False, True])
def test_selected_optional_level_refuses_without_fallback(bindings, policy, missing):
    row = next(r for r in bindings["hosts"] if (r["host"], r["class"]) == ("codex-cli", "coding"))
    if missing:
        del row["levels"]["extended"]
        del row["admission"]["extended"]
    else:
        row["admission"]["extended"] = "rejected"
    with pytest.raises(ModelSelectionError, match="^binding_unavailable:codex-cli:extended$"):
        choose(bindings, policy, intent="extended")


def test_invalid_author_on_non_review_task_is_attributed(bindings, policy):
    with pytest.raises(ModelSelectionError, match="^invalid_author_family$"):
        choose(bindings, policy, author_family="unknown")


def test_configured_host_order_is_preserved(bindings, policy):
    extra = [dict(copy.deepcopy(r), host="a-host") for r in bindings["hosts"] if r["host"] == "codex-cli"]
    bindings["hosts"].extend(extra)
    policy["family_hosts"]["first"] = ["codex-cli", "a-host"]
    assert choose(bindings, policy, host_kinds=("codex-cli", "claude-code", "a-host"))[0]["host"] == "codex-cli"
    policy["family_hosts"]["first"].reverse()
    assert choose(bindings, policy, host_kinds=("codex-cli", "claude-code", "a-host"))[0]["host"] == "a-host"


@requires_anchored_io
def test_public_reader_streams_into_selection(bindings, policy, tmp_path):
    path = tmp_path / "decisions.jsonl"
    _, record = choose(bindings, policy)
    append_decision(path, record)
    stream = core_read_decisions(path)
    assert iter(stream) is stream
    assert select_model(bindings, policy, "T9", "implementer", stream) == (
        select_model(bindings, policy, "T9", "implementer", [record]))


@pytest.mark.parametrize("task", ["T4", "T5", "T6", "T8"])
def test_all_review_tasks_require_author_attribution(bindings, policy, task):
    with pytest.raises(ModelSelectionError, match="^invalid_author_family$"):
        select_model(bindings, policy, task, "reviewer", [])


def test_t7_drafts_from_both_families_get_valid_primary_checkers(bindings, policy):
    policy["flexible_tasks"].append("T7")
    history, authors = [], []
    for i in range(2):
        draft, record = select_model(bindings, policy, "T7", "implementer", history, subject="draft-%d" % i)
        history.append(record)
        authors.append(draft["family"])
        checker, _ = select_model(bindings, policy, "T8", "reviewer", history,
                                  author_family=draft["family"])
        assert checker["family"] != draft["family"]
    assert set(authors) == {"first", "second"}


def test_arbitrary_t8_stage_cannot_bypass_independence(bindings, policy):
    policy["review_families"]["T8"]["arbitrary"] = "first"
    with pytest.raises(ModelSelectionError, match="^invalid_policy:review_families:T8:stages$"):
        select_model(bindings, policy, "T8", "reviewer", [], author_family="first", review_stage="arbitrary")


def test_policy_identity_is_stable_and_covers_all_policy_fields(bindings, policy):
    _, original = choose(bindings, policy)
    reordered = dict(reversed(list(policy.items())))
    assert choose(bindings, reordered)[1]["policy_id"] == original["policy_id"]
    changed = copy.deepcopy(policy)
    changed["manager_family"] = "first"  # flexible selection stays identical
    choice, record = choose(bindings, changed)
    assert choice == original["choice"]
    assert record["policy_id"] != original["policy_id"]
    assert record["decision_id"] != original["decision_id"]


@pytest.mark.parametrize("nested", [False, True])
@requires_anchored_io
def test_missing_log_has_no_side_effects(tmp_path, nested):
    path = tmp_path / "missing" / "log.jsonl" if nested else tmp_path / "missing.jsonl"
    before = sorted(p.name for p in tmp_path.iterdir())
    if nested:
        with pytest.raises(ModelSelectionError, match="^unsafe_decision_path$"):
            read_decisions(path)
    else:
        assert read_decisions(path) == []
    assert sorted(p.name for p in tmp_path.iterdir()) == before


@pytest.mark.parametrize("kind", ["string", "collection", "integer", "aggregate", "nodes"])
@pytest.mark.parametrize("surface", ["append", "history"])
def test_record_budgets_apply_before_large_allocations(bindings, policy, tmp_path, kind, surface):
    import tracemalloc

    _, record = choose(bindings, policy)
    record["outcome"] = {"string": "x" * 8_000_000, "collection": [None] * 200_000,
                         "integer": 1 << 1_000_000, "aggregate": ["x" * 128] * 128,
                         "nodes": [[""] * 128] * 8}[kind]
    tracemalloc.start()
    try:
        with pytest.raises(ModelSelectionError, match="^decision_line_too_large$"):
            if surface == "append":
                append_decision(tmp_path / "decisions.jsonl", record)
            else:
                select_model(bindings, policy, "T9", "implementer", [record])
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 512 * 1024
    assert list(tmp_path.iterdir()) == []


@requires_anchored_io
def test_group_writable_log_directory_refuses(bindings, policy, tmp_path):
    path = tmp_path / "decisions.jsonl"
    _, record = choose(bindings, policy)
    original = tmp_path.stat().st_mode
    tmp_path.chmod(0o770)
    try:
        with pytest.raises(ModelSelectionError, match="^unsafe_decision_directory$"):
            append_decision(path, record)
    finally:
        tmp_path.chmod(original)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("hook", ["created", "mode-set"])
@requires_anchored_io
def test_temp_symlink_substitution_cannot_change_victim_or_history(bindings, policy, tmp_path, monkeypatch, hook):
    path, victim = tmp_path / "decisions.jsonl", tmp_path / "victim"
    _, record = choose(bindings, policy)
    append_decision(path, record)
    victim.write_bytes(b"do not change")
    victim.chmod(0o640)
    before = path.read_bytes()
    opened, changed, renamed = [], [], []
    real_open, real_fchmod, real_rename = os.open, os.fchmod, os.rename

    def swap(name, directory):
        os.unlink(name, dir_fd=directory)
        os.symlink(victim, name, dir_fd=directory)
        changed.append(name)

    def open_hook(name, flags, mode=0o777, *, dir_fd=None):
        fd = real_open(name, flags, mode, dir_fd=dir_fd)
        if dir_fd is not None and str(name).startswith(".model-select-"):
            opened.append((fd, name, dir_fd))
            if hook == "created":
                swap(name, dir_fd)
        return fd

    def mode_hook(fd, mode):
        real_fchmod(fd, mode)
        if opened and fd == opened[0][0] and hook == "mode-set":
            swap(opened[0][1], opened[0][2])

    def rename_hook(*args, **kwargs):
        renamed.append(args)
        return real_rename(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", open_hook)
        patch.setattr(os, "fchmod", mode_hook)
        patch.setattr(os, "rename", rename_hook)
        with pytest.raises(ModelSelectionError, match="^unsafe_decision_path$"):
            append_decision(path, record)
    assert changed and not renamed
    assert victim.read_bytes() == b"do not change" and victim.stat().st_mode & 0o777 == 0o640
    assert path.read_bytes() == before and read_decisions(path) == [record]


def test_unsupported_directory_io_refuses_without_side_effects(bindings, policy, tmp_path, monkeypatch):
    _, record = choose(bindings, policy)
    monkeypatch.setattr(core, "_DIR_FD_SUPPORTED", False)
    for operation in (lambda: append_decision(tmp_path / "log", record), lambda: read_decisions(tmp_path / "log"),
                      lambda: core.select_and_append(tmp_path / "log", bindings, policy, "T9", "implementer",
                                                     host_kinds=("codex-cli", "claude-code"), subject="lane")):
        with pytest.raises(ModelSelectionError, match="^anchored_io_unavailable$"):
            operation()
    assert list(tmp_path.iterdir()) == []


@requires_anchored_io
def test_missing_log_in_read_only_directory_has_no_side_effects(tmp_path):
    before = tmp_path.stat().st_mode
    tmp_path.chmod(0o555)
    try:
        assert read_decisions(tmp_path / "missing.jsonl") == []
        assert list(tmp_path.iterdir()) == []
    finally:
        tmp_path.chmod(before)


@requires_anchored_io
def test_log_directory_must_belong_to_current_uid(bindings, policy, tmp_path, monkeypatch):
    _, record = choose(bindings, policy)
    actual = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: actual + 1)
    with pytest.raises(ModelSelectionError, match="^unsafe_decision_directory$"):
        append_decision(tmp_path / "log", record)
    assert list(tmp_path.iterdir()) == []


def test_host_registry_is_required(bindings, policy):
    with pytest.raises(TypeError, match="missing 1 required keyword-only argument: 'host_kinds'"):
        core_select_model(bindings, policy, "T2", "implementer", [], subject="lane")


@pytest.mark.parametrize("history", [None, 1, True])
def test_history_must_be_iterable(bindings, policy, history):
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        select_model(bindings, policy, "T9", "implementer", history)


def test_non_reviewer_cannot_select_review_stage(bindings, policy):
    with pytest.raises(ModelSelectionError, match="^invalid_review_stage$"):
        choose(bindings, policy, review_stage="second")


def test_same_team_history_rejects_changed_family_set_even_when_choice_remains(bindings, policy):
    _, record = choose(bindings, policy)
    changed = copy.deepcopy(policy)
    for key in ("family_hosts", "target_shares"):
        changed[key]["third"] = changed[key].pop("second")
    changed["family_order"] = ["first", "third"]
    changed["manager_family"] = "third"
    for stages in changed["review_families"].values():
        for stage, family in stages.items():
            stages[stage] = "third" if family == "second" else family
    for intents in changed["task_intents"].values():
        if "second" in intents:
            intents["third"] = intents.pop("second")
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        select_model(bindings, changed, "T9", "implementer", [record])


@requires_anchored_io
def test_publication_uses_descriptor_mode_and_anchored_rename(bindings, policy, tmp_path, monkeypatch):
    _, record = choose(bindings, policy)
    real_rename, renamed = os.rename, []

    def rename_hook(source, destination, **kwargs):
        assert kwargs["src_dir_fd"] == kwargs["dst_dir_fd"]
        assert "/" not in source and "/" not in destination
        renamed.append((source, destination))
        return real_rename(source, destination, **kwargs)

    def forbidden_path_chmod(*args, **kwargs):
        pytest.fail("publication must use fchmod")

    monkeypatch.setattr(os, "rename", rename_hook)
    monkeypatch.setattr(os, "chmod", forbidden_path_chmod)
    path = tmp_path / "log"
    append_decision(path, record)
    assert renamed and path.stat().st_mode & 0o777 == 0o600
    assert read_decisions(path) == [record]


@pytest.mark.parametrize("entry,error", [("validate", "invalid_bindings"), ("bindings", "invalid_bindings"),
    ("policy", "invalid_policy"), ("read", "unsafe_decision_path"), ("append", "unsafe_decision_path"),
    ("transaction", "unsafe_decision_path")])
@pytest.mark.parametrize("bad", ["nul", "long-component"])
def test_rejected_paths_have_stable_codes(bindings, policy, tmp_path, entry, error, bad):
    _, record = choose(bindings, policy)
    path = str(tmp_path / ("bad\x00path" if bad == "nul" else "x" * 5000))
    operations = {"validate": lambda: core.validate_bindings(path),
                  "bindings": lambda: choose(path, policy), "policy": lambda: choose(bindings, path),
                  "read": lambda: read_decisions(path), "append": lambda: append_decision(path, record),
                  "transaction": lambda: core.select_and_append(path, bindings, policy, "T9", "implementer",
                                                                 host_kinds=("codex-cli", "claude-code"), subject="lane")}
    if entry in ("read", "append", "transaction") and bad == "long-component" and os.name != "posix":
        error = "anchored_io_unavailable"  # unsupported log APIs refuse before asking the OS
    if entry in ("validate", "bindings", "policy") and os.name != "posix":
        error = "anchored_io_unavailable"
    with pytest.raises(ModelSelectionError, match="^" + error + "$"):
        operations[entry]()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("offset", [-1, 0, 1])
@pytest.mark.parametrize("prefix", ["", '\"\\\t\u00e9\U0001f642'])
@requires_anchored_io
def test_canonical_row_byte_limit_applies_to_write_read_and_replay(bindings, policy, tmp_path, monkeypatch,
                                                                  offset, prefix):
    path = tmp_path / "decisions.jsonl"
    _, record = choose(bindings, policy)
    record["outcome"] = prefix
    base = len(json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")) + 1
    padding = MAX_LINE_BYTES + offset - base
    assert padding > 0
    record["outcome"] += "x" * padding
    expected = (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    assert len(expected) == MAX_LINE_BYTES + offset
    if offset > 0:
        with pytest.raises(ModelSelectionError, match="^decision_line_too_large$"):
            append_decision(path, record)
        assert list(tmp_path.iterdir()) == []
    else:
        append_decision(path, record)
        assert path.read_bytes() == expected
        assert read_decisions(path) == [record]
        monkeypatch.setattr(core, "MAX_HISTORY_BYTES", len(expected))
        assert select_model(bindings, policy, "T9", "implementer", core_read_decisions(path)) == (
            select_model(bindings, policy, "T9", "implementer", [record]))


@requires_anchored_io
def test_disk_history_requires_the_writer_canonical_encoding(bindings, policy, tmp_path):
    _, record = choose(bindings, policy)
    path = tmp_path / "decisions.jsonl"
    path.write_text(json.dumps(record, sort_keys=True) + "\n")  # extra whitespace
    path.chmod(0o600)
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        read_decisions(path)


@pytest.mark.parametrize("path_errno", [errno.EACCES, errno.EPERM, errno.EINVAL, errno.ENAMETOOLONG, errno.EROFS,
                                       errno.EIO, None])
@pytest.mark.parametrize("entry", ["read", "append"])
@requires_anchored_io
def test_os_log_path_rejections_keep_stable_codes(bindings, policy, tmp_path, monkeypatch, path_errno, entry):
    path = tmp_path / "log"
    _, record = choose(bindings, policy)
    append_decision(path, record)
    before, real_open = path.read_bytes(), os.open

    def rejected_open(name, flags, mode=0o777, *, dir_fd=None):
        if name == "log" and dir_fd is not None:
            raise OSError(path_errno, "injected path rejection")
        return real_open(name, flags, mode, dir_fd=dir_fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", rejected_open)
        with pytest.raises(ModelSelectionError, match="^unsafe_decision_path$"):
            if entry == "read":
                read_decisions(path)
            else:
                append_decision(path, record)
    assert path.read_bytes() == before and read_decisions(path) == [record]


@requires_anchored_io
def test_log_disappearing_before_locked_open_has_stable_code(bindings, policy, tmp_path, monkeypatch):
    path = tmp_path / "log"
    _, record = choose(bindings, policy)
    append_decision(path, record)
    real_open = os.open

    def remove_before_lock(name, flags, mode=0o777, *, dir_fd=None):
        if name == "log.lock" and dir_fd is not None:
            os.unlink("log", dir_fd=dir_fd)
        return real_open(name, flags, mode, dir_fd=dir_fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", remove_before_lock)
        with pytest.raises(ModelSelectionError, match="^unsafe_decision_path$"):
            read_decisions(path)


@requires_anchored_io
def test_ancestor_symlink_substitution_during_acquisition_refuses(bindings, policy, tmp_path, monkeypatch):
    untrusted = tmp_path / "untrusted"
    private = untrusted / "a" / "private"
    private.mkdir(parents=True, mode=0o700)
    redirected = tmp_path / "redirected" / "private"
    redirected.mkdir(parents=True, mode=0o700)
    untrusted.chmod(0o777)
    _, record = choose(bindings, policy)
    changed, real_open = [], os.open

    def substitute(name, flags, mode=0o777, *, dir_fd=None):
        if not changed and (str(name) == str(private) or (name == "a" and dir_fd is not None)):
            (untrusted / "a").rename(untrusted / "original-a")
            (untrusted / "a").symlink_to(redirected.parent, target_is_directory=True)
            changed.append(True)
        return real_open(name, flags, mode, dir_fd=dir_fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", substitute)
        with pytest.raises(ModelSelectionError, match="^unsafe_decision_path$"):
            append_decision(private / "log", record)
    assert changed
    assert list(redirected.iterdir()) == []
    assert list((untrusted / "original-a" / "private").iterdir()) == []


@requires_anchored_io
def test_stale_new_decision_refuses_without_changing_log(bindings, policy, tmp_path):
    path = tmp_path / "log"
    _, first = choose(bindings, policy, subject="lane-a")
    _, stale = choose(bindings, policy, subject="lane-b")
    append_decision(path, first)
    before = path.read_bytes()
    with pytest.raises(ModelSelectionError, match="^stale_decision$"):
        append_decision(path, stale)
    assert path.read_bytes() == before and read_decisions(path) == [first]


@requires_anchored_io
def test_atomic_concurrent_launches_follow_split_sequence(bindings, policy, tmp_path):
    from threading import Barrier

    path, start = tmp_path / "log", Barrier(2)

    def launch(subject):
        start.wait(timeout=5)
        return core.select_and_append(path, bindings, policy, "T9", "implementer",
                                      host_kinds=("codex-cli", "claude-code"), subject=subject)

    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = pool.submit(launch, "lane-a"), pool.submit(launch, "lane-b")
        results = [a.result(timeout=15), b.result(timeout=15)]
    records = read_decisions(path)
    assert [r["choice"]["family"] for r in records] == ["first", "second"]
    assert [r["counts_before"] for r in records] == [{"first": 0, "second": 0}, {"first": 1, "second": 0}]
    assert {r["subject"] for r in records} == {"lane-a", "lane-b"}
    assert {record["decision_id"] for _, record in results} == {r["decision_id"] for r in records}


@pytest.mark.parametrize("author", ["first", "second"])
def test_both_t8_stages_cover_both_families(bindings, policy, author):
    first, _ = select_model(bindings, policy, "T8", "reviewer", [], author_family=author)
    second, _ = select_model(bindings, policy, "T8", "reviewer", [], author_family=author, review_stage="second")
    assert first["family"] != second["family"]
    assert {first["family"], second["family"]} == {"first", "second"}
    assert second["family"] == author


@requires_anchored_io
def test_internal_reader_does_not_hash_history_again_during_selection(bindings, policy, tmp_path):
    import hashlib
    import sys

    path = tmp_path / "log"
    _, record = choose(bindings, policy)
    append_decision(path, record)

    def count_hashes(history):
        calls = []
        previous = sys.getprofile()

        def profile(frame, event, function):
            if event == "c_call" and function is hashlib.sha256:
                calls.append(True)

        sys.setprofile(profile)
        try:
            select_model(bindings, policy, "T9", "implementer", history)
        finally:
            sys.setprofile(previous)
        return len(calls)

    # The row identity and its shared split snapshot each need one hash.
    assert count_hashes(core_read_decisions(path)) == count_hashes([]) + 2


@requires_anchored_io
def test_historical_outcome_observation_remains_appendable_after_new_launch(bindings, policy, tmp_path):
    path = tmp_path / "log"
    _, original = core.select_and_append(path, bindings, policy, "T9", "implementer",
                                         host_kinds=("codex-cli", "claude-code"), subject="lane-a")
    _, later = core.select_and_append(path, bindings, policy, "T9", "implementer",
                                      host_kinds=("codex-cli", "claude-code"), subject="lane-b")
    observation = dict(original, outcome={"review": "ACCEPT"})
    append_decision(path, observation)
    assert read_decisions(path) == [original, later, observation]
    assert select_model(bindings, policy, "T9", "implementer", core_read_decisions(path)) == (
        select_model(bindings, policy, "T9", "implementer", [original, later]))


@requires_anchored_io
def test_other_teams_do_not_make_a_decision_stale(bindings, policy, tmp_path):
    path = tmp_path / "log"
    _, unrelated = choose(bindings, dict(policy, team_id="other-team"))
    append_decision(path, unrelated)
    choice, record = core.select_and_append(path, bindings, policy, "T9", "implementer",
                                           host_kinds=("codex-cli", "claude-code"), subject="lane")
    assert choice["family"] == "first" and record["counts_before"] == {"first": 0, "second": 0}
    assert read_decisions(path) == [unrelated, record]


@requires_anchored_io
def test_round6_lock_names_are_reserved_during_an_append(bindings, policy, tmp_path):
    from aegis_core.storage import file_lock

    path = tmp_path / "log"
    _, record = choose(bindings, policy)
    append_decision(path, record)
    lock = path.with_name(path.name + ".lock")
    before, lock_before = path.read_bytes(), lock.stat()
    with file_lock(lock):
        for operation in (lambda: append_decision(lock, record), lambda: read_decisions(lock),
                          lambda: core.select_and_append(lock, bindings, policy, "T9", "implementer",
                              host_kinds=("codex-cli", "claude-code"), subject="lane")):
            with pytest.raises(ModelSelectionError, match="^invalid_log_path$"):
                operation()
        assert lock.stat().st_ino == lock_before.st_ino
    assert path.read_bytes() == before and lock.read_bytes() == b""
    assert not lock.with_name(lock.name + ".lock").exists()


@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666])
@pytest.mark.parametrize("empty", [False, True])
@requires_anchored_io
def test_round6_writable_logs_are_never_empty_history(bindings, policy, tmp_path, mode, empty):
    path = tmp_path / "log"
    _, record = choose(bindings, policy)
    append_decision(path, record)
    if empty:
        path.write_bytes(b"")  # another UID could truncate a writable inode
    path.chmod(mode)
    before = path.read_bytes()
    for operation in (lambda: read_decisions(path), lambda: append_decision(path, record),
                      lambda: core.select_and_append(path, bindings, policy, "T9", "implementer",
                          host_kinds=("codex-cli", "claude-code"), subject="lane")):
        with pytest.raises(ModelSelectionError, match="^unsafe_decision_path$"):
            operation()
    assert path.read_bytes() == before and path.stat().st_mode & 0o777 == mode


@requires_anchored_io
def test_round6_opened_log_permissions_are_rechecked(bindings, policy, tmp_path, monkeypatch):
    path = tmp_path / "log"
    _, record = choose(bindings, policy)
    append_decision(path, record)
    real_open, changed = os.open, []

    def change_after_stat(name, flags, mode=0o777, *, dir_fd=None):
        if name == "log" and dir_fd is not None:
            os.chmod(name, 0o666, dir_fd=dir_fd)
            changed.append(True)
        return real_open(name, flags, mode, dir_fd=dir_fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", change_after_stat)
        with pytest.raises(ModelSelectionError, match="^unsafe_decision_path$"):
            read_decisions(path)
    assert changed


def test_round6_large_parsed_unknown_host_registry_is_bounded(bindings):
    import tracemalloc

    row = bindings["hosts"][0]
    bindings["hosts"] = [dict(row, host="unknown-%d" % i) for i in range(100_000)]
    tracemalloc.start()
    try:
        with pytest.raises(ModelSelectionError, match="^invalid_bindings$"):
            core.validate_bindings(bindings, host_kinds=("codex-cli", "claude-code"))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 512 * 1024


@pytest.mark.parametrize("kind", ["string", "collection", "nodes", "depth"])
@pytest.mark.parametrize("field", ["bindings", "policy"])
def test_round6_parsed_input_budgets_precede_semantic_traversal(bindings, policy, field, kind):
    import tracemalloc

    nested = None
    for _ in range(65):
        nested = [nested]
    value = {"string": "x" * 8_000_000, "collection": [None] * 100_000,
             "nodes": [[None] * 256] * 256, "depth": nested}[kind]
    data = bindings if field == "bindings" else policy
    data["oversized"] = value
    tracemalloc.start()
    try:
        with pytest.raises(ModelSelectionError, match="^invalid_" + field + "$"):
            choose(bindings, policy)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 512 * 1024


@pytest.mark.parametrize("task,stages,code", [
    ("T4", {"primary": "first"}, "formal_primaries"),
    ("T5", {"primary": "second"}, "formal_primaries"),
    ("T6", {"primary": "first", "whole": "first"}, "t6_family_coverage"),
])
def test_round6_formal_lenses_cover_both_families(bindings, policy, task, stages, code):
    policy["review_families"][task] = stages
    with pytest.raises(ModelSelectionError, match="^invalid_policy:" + code + "$"):
        choose(bindings, policy)


def test_round6_calibration_counts_only_matching_policy(bindings, policy):
    history, baseline = [], []
    for _ in range(10):
        _, row = select_model(bindings, policy, "T9", "implementer", history)
        history.append(row)
        baseline.append(row)
    paused = copy.deepcopy(policy)
    paused["target_shares"] = {"first": 1.0, "second": 0.0}
    for _ in range(20):
        _, row = select_model(bindings, paused, "T9", "implementer", history)
        assert row["choice"]["family"] == "first"
        history.append(row)
    for _ in range(10):
        expected, old = select_model(bindings, policy, "T9", "implementer", baseline)
        actual, row = select_model(bindings, policy, "T9", "implementer", history)
        assert actual == expected and row["counts_before"] == old["counts_before"]
        history.append(row)
        baseline.append(old)


@requires_anchored_io
def test_round6_identical_launches_have_distinct_chained_ids(bindings, policy, tmp_path):
    path = tmp_path / "log"
    rows = [core.select_and_append(path, bindings, policy, "T4", "reviewer",
                host_kinds=("codex-cli", "claude-code"), subject="same", author_family="first")[1]
            for _ in range(3)]
    assert len({row["decision_id"] for row in rows}) == 3
    assert rows[0]["previous_decision_id"] == ""
    assert rows[1]["previous_decision_id"] == rows[0]["decision_id"]
    assert rows[2]["previous_decision_id"] == rows[1]["decision_id"]
    assert read_decisions(path) == rows
    path.write_bytes(b"".join(path.read_bytes().splitlines(keepends=True)[::2]))
    error = "^invalid_history:decision_chain: restore_complete_decision_log$"
    for history in ([rows[0], rows[2]], core_read_decisions(path)):
        with pytest.raises(ModelSelectionError, match=error):
            select_model(bindings, policy, "T9", "implementer", history)
    with pytest.raises(ModelSelectionError, match=error):
        read_decisions(path)
    before = path.read_bytes()
    with pytest.raises(ModelSelectionError, match=error):
        append_decision(path, dict(rows[0], outcome={"review": "ACCEPT"}))
    assert path.read_bytes() == before


@pytest.mark.parametrize("observation", [False, True])
def test_round6_hold_does_not_count_a_launch(bindings, policy, observation):
    _, first = choose(bindings, policy)
    held = dict(first, outcome={"launch_status": "not_launched", "reason": "HOLD"})
    history = [first, held] if observation else [held]
    retry_choice, retry = select_model(bindings, policy, "T9", "implementer", history)
    assert retry_choice == first["choice"]
    assert retry["counts_before"] == {"first": 0, "second": 0}
    assert retry["decision_id"] != first["decision_id"]
    history.append(retry)
    next_choice, row = select_model(bindings, policy, "T9", "implementer", history)
    assert next_choice["family"] == "second" and row["counts_before"] == {"first": 1, "second": 0}


@pytest.mark.parametrize("stages", [{"primary": "first"}, {"primary": "second", "second": "first"},
                                  {"primary": "author", "second": "opposite"}])
def test_round6_t8_requires_stage_markers(bindings, policy, stages):
    policy["review_families"]["T8"] = stages
    with pytest.raises(ModelSelectionError, match="^invalid_policy:t8_markers$"):
        select_model(bindings, policy, "T8", "reviewer", [], author_family="first")


@pytest.mark.parametrize("author", ["first", "second"])
def test_round6_t8_marker_policy_is_accepted(bindings, policy, author):
    policy["review_families"]["T8"] = {"primary": "opposite", "second": "author"}
    a, _ = select_model(bindings, policy, "T8", "reviewer", [], author_family=author)
    b, _ = select_model(bindings, policy, "T8", "reviewer", [], author_family=author, review_stage="second")
    assert a["family"] != author and b["family"] == author


def test_round6_policy_subcode_names_the_cause_without_echo(bindings, policy):
    policy["target_shares"] = {"first": 0.8, "second": 0.3}
    with pytest.raises(ModelSelectionError, match="^invalid_policy:target_shares_sum$"):
        choose(bindings, policy)
    policy["team_id"] = "private attacker text"
    with pytest.raises(ModelSelectionError, match="^invalid_policy:team_id$"):
        choose(bindings, policy)


@pytest.mark.parametrize("field", ["bindings", "policy"])
@requires_anchored_io
def test_round6_configuration_ancestor_swap_refuses(bindings, policy, tmp_path, monkeypatch, field):
    parent = tmp_path / "parent"
    parent.mkdir()
    path = parent / "input.json"
    path.write_text(json.dumps(bindings if field == "bindings" else policy))
    real_open, changed = os.open, []

    def swap(name, flags, mode=0o777, *, dir_fd=None):
        if not changed and (str(name) == str(path) or (name == "parent" and dir_fd is not None)):
            parent.rename(tmp_path / "old-parent")
            parent.symlink_to(tmp_path / "old-parent", target_is_directory=True)
            changed.append(True)
        return real_open(name, flags, mode, dir_fd=dir_fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", swap)
        with pytest.raises(ModelSelectionError, match="^invalid_" + field + "$"):
            choose(path if field == "bindings" else bindings, path if field == "policy" else policy)
    assert changed


@pytest.mark.parametrize("status", ["HOLD", "private free text", None, []])
def test_round6_unknown_launch_status_has_fixed_refusal(bindings, policy, status):
    _, row = choose(bindings, policy)
    row["outcome"] = {"launch_status": status}
    with pytest.raises(ModelSelectionError, match="^invalid_history:launch_status$"):
        select_model(bindings, policy, "T9", "implementer", [row])


@requires_anchored_io
def test_round6_hold_observations_and_calibration_publish_consistently(bindings, policy, tmp_path):
    path = tmp_path / "log"

    def launch(current):
        return core.select_and_append(path, bindings, current, "T9", "implementer",
            host_kinds=("codex-cli", "claude-code"), subject="same")

    _, held = launch(policy)
    held["outcome"] = {"launch_status": "not_launched", "reason": "HOLD"}
    append_decision(path, held)
    retry, retry_row = launch(policy)
    assert retry["family"] == "first" and retry_row["counts_before"] == {"first": 0, "second": 0}
    held["outcome"] = {"launch_status": "launched"}
    append_decision(path, held)
    _, resumed = launch(policy)
    assert resumed["counts_before"] == {"first": 2, "second": 0}
    changed = copy.deepcopy(policy)
    changed["target_shares"] = {"first": 1.0, "second": 0.0}
    _, calibrated = launch(changed)
    assert calibrated["counts_before"] == {"first": 0, "second": 0}
    _, restored = launch(policy)
    assert restored["counts_before"] == {"first": 2, "second": 1}
    assert restored["previous_decision_id"] == calibrated["decision_id"]
    assert read_decisions(path)[-1] == restored


@requires_anchored_io
def test_round6_stale_fixed_launch_refuses_even_with_equal_counts(bindings, policy, tmp_path):
    path = tmp_path / "log"
    _, row = select_model(bindings, policy, "T4", "reviewer", [], author_family="first")
    _, stale = select_model(bindings, policy, "T4", "reviewer", [], author_family="first", subject="other")
    append_decision(path, row)
    before = path.read_bytes()
    with pytest.raises(ModelSelectionError, match="^stale_decision$"):
        append_decision(path, stale)
    assert path.read_bytes() == before


def reidentify_record(record):
    """Model a corrupt row with a valid public SHA256 identity (not authentication)."""
    import hashlib

    payload = {k: v for k, v in record.items() if k not in ("decision_id", "outcome")}
    record["decision_id"] = hashlib.sha256(json.dumps(
        payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")).hexdigest()


@requires_anchored_io
def test_round6_argon_zero_share_row_refuses_all_surfaces(bindings, policy, tmp_path):
    policy["target_shares"] = {"first": 1.0, "second": 0.0}
    _, forged = choose(bindings, policy)
    forged["choice"]["family"] = "second"
    reidentify_record(forged)
    path = tmp_path / "log"
    error = "^invalid_history:family_split: restore_complete_decision_log$"
    with pytest.raises(ModelSelectionError, match=error):
        append_decision(path, forged)
    assert list(tmp_path.iterdir()) == []
    path.write_text(json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n")
    path.chmod(0o600)
    with pytest.raises(ModelSelectionError, match=error):
        read_decisions(path)
    with pytest.raises(ModelSelectionError, match=error):
        select_model(bindings, policy, "T9", "implementer", [forged])


@requires_anchored_io
def test_round6_argon_chained_inconsistent_counts_refuse_replay(bindings, policy, tmp_path):
    _, first = choose(bindings, policy)
    _, forged = choose(bindings, policy, subject="another")
    forged["previous_decision_id"] = first["decision_id"]
    reidentify_record(forged)
    path = tmp_path / "log"
    path.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                            for row in (first, forged)))
    path.chmod(0o600)
    before = path.read_bytes()
    error = "^invalid_history:counts_before: restore_complete_decision_log$"
    for history in ([first, forged], core_read_decisions(path)):
        with pytest.raises(ModelSelectionError, match=error):
            select_model(bindings, policy, "T9", "implementer", history)
    with pytest.raises(ModelSelectionError, match=error):
        read_decisions(path)
    with pytest.raises(ModelSelectionError, match=error):
        append_decision(path, dict(first, outcome={"review": "ACCEPT"}))
    assert path.read_bytes() == before


@requires_anchored_io
def test_round6_argon_cleanup_does_not_mask_descriptor_failure(bindings, policy, tmp_path, monkeypatch):
    path = tmp_path / "log"
    _, row = choose(bindings, policy)
    append_decision(path, row)
    before = path.read_bytes()
    primary, unlink = OSError(errno.EIO, "injected descriptor failure"), os.unlink

    def fail_sync(descriptor):
        raise primary

    def fail_cleanup(name, *, dir_fd=None):
        raise OSError(errno.EROFS, "injected cleanup failure")

    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", fail_sync)
        patch.setattr(os, "unlink", fail_cleanup)
        with pytest.raises(OSError) as caught:
            append_decision(path, row)
        assert caught.value is primary
        assert isinstance(caught.value.__cause__, ModelSelectionError)
        assert str(caught.value.__cause__) == "unsafe_decision_path"
    assert path.read_bytes() == before and read_decisions(path) == [row]
    leftovers = list(tmp_path.glob(".model-select-*"))
    assert len(leftovers) == 1  # failed cleanup is observable, never repaired silently
    unlink(leftovers[0])


@pytest.mark.parametrize("role", ["implementer", "integrator"])
@pytest.mark.parametrize("task", ["T2", "T3", "T7", "T9", "T13"])
def test_round7_writer_lane_cannot_migrate_families(bindings, policy, task, role):
    with pytest.raises(ModelSelectionError, match="^invalid_request:lane_family$"):
        select_model(bindings, policy, task, role, [], lane_family="second")
    choice, _ = select_model(bindings, policy, task, role, [], lane_family="first")
    assert choice["family"] == "first"


@pytest.mark.parametrize("field", ["bindings", "policy", "validate"])
def test_round7_config_paths_require_anchored_io(bindings, policy, tmp_path, monkeypatch, field):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(policy if field == "policy" else bindings))
    def forbidden_open(*args, **kwargs):
        pytest.fail("unsupported config input must refuse before filesystem opens")

    with monkeypatch.context() as patch:
        patch.setattr(core, "_DIR_FD_SUPPORTED", False)
        patch.setattr(os, "open", forbidden_open)
        with pytest.raises(ModelSelectionError, match="^anchored_io_unavailable$"):
            if field == "validate":
                core.validate_bindings(path)
            else:
                choose(path if field == "bindings" else bindings, path if field == "policy" else policy)


@pytest.mark.parametrize("change", ["intent", "host"])
def test_round7_unrelated_policy_edits_keep_split_counts(bindings, policy, change):
    history = []
    for _ in range(3):
        history.append(select_model(bindings, policy, "T9", "implementer", history)[1])
    changed = copy.deepcopy(policy)
    registry = ["codex-cli", "claude-code"]
    if change == "intent":
        changed["task_intents"]["T5"]["first"] = "deep"
    else:
        registry.append("new-host")
        bindings["hosts"].extend(dict(copy.deepcopy(row), host="new-host")
                                 for row in list(bindings["hosts"]) if row["host"] == "codex-cli")
        changed["family_hosts"]["first"].append("new-host")
    expected, previous = select_model(bindings, policy, "T9", "implementer", history, host_kinds=registry)
    choice, record = select_model(bindings, changed, "T9", "implementer", history, host_kinds=registry)
    assert choice == expected and record["counts_before"] == previous["counts_before"]
    assert record["policy_id"] != previous["policy_id"]
    assert record["split_id"] == previous["split_id"]


@pytest.mark.parametrize("change", ["targets", "order"])
@requires_anchored_io
def test_round7_preserved_split_identity_cannot_change_snapshot(bindings, policy, tmp_path, change):
    from fractions import Fraction

    _, original = choose(bindings, policy)
    _, forged = select_model(bindings, policy, "T9", "implementer", [original])
    if change == "targets":
        forged["target_shares"] = {"first": 0.0, "second": 1.0}
    else:
        forged["family_order"].reverse()
    first, second = forged["family_order"]
    counts, shares = forged["counts_before"], forged["target_shares"]
    forged["choice"]["family"] = (first if shares[first] and (not shares[second] or
        Fraction(counts[first], sum(counts.values())) < Fraction(str(shares[first]))) else second)
    reidentify_record(forged)
    path = tmp_path / "log"
    append_decision(path, original)
    before = path.read_bytes()
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        append_decision(path, forged)
    assert path.read_bytes() == before
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        select_model(bindings, policy, "T9", "implementer", [original, forged])
    path.write_bytes(before + (json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        read_decisions(path)


@pytest.mark.parametrize("outcome", [None, {"tests_passed": False}, "finished", []])
def test_round7_observation_without_status_preserves_hold(bindings, policy, outcome):
    _, row = choose(bindings, policy)
    history = [row, dict(row, outcome={"launch_status": "not_launched"}), dict(row, outcome=outcome)]
    choice, retry = select_model(bindings, policy, "T9", "implementer", history)
    assert choice["family"] == "first" and retry["counts_before"] == {"first": 0, "second": 0}


@requires_anchored_io
def test_round7_disk_observation_without_status_preserves_hold(bindings, policy, tmp_path):
    path = tmp_path / "log"
    _, row = core.select_and_append(path, bindings, policy, "T9", "implementer",
                                   host_kinds=("codex-cli", "claude-code"), subject="same")
    append_decision(path, dict(row, outcome={"launch_status": "not_launched"}))
    append_decision(path, dict(row, outcome={"tests_passed": False}))
    _, retry = core.select_and_append(path, bindings, policy, "T9", "implementer",
                                     host_kinds=("codex-cli", "claude-code"), subject="same")
    assert retry["counts_before"] == {"first": 0, "second": 0}


@pytest.mark.parametrize("family", ["first", "second"])
def test_round7_t7_author_is_the_chosen_family(bindings, policy, family):
    policy["flexible_tasks"].append("T7")
    policy["target_shares"] = {"first": int(family == "first"), "second": int(family == "second")}
    choice, row = select_model(bindings, policy, "T7", "implementer", [])
    assert row["author_family"] == choice["family"] == family
    assert select_model(bindings, policy, "T7", "implementer", [], author_family=family)[1] == row
    wrong = "first" if family == "second" else "second"
    with pytest.raises(ModelSelectionError, match="^invalid_request:author_family$"):
        select_model(bindings, policy, "T7", "implementer", [], author_family=wrong)
    forged = dict(row, author_family=wrong)
    reidentify_record(forged)
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        select_model(bindings, policy, "T9", "implementer", [forged])


@requires_anchored_io
def test_round7_transaction_validates_history_once(bindings, policy, tmp_path):
    import hashlib
    import sys
    from aegis_core.storage import file_lock

    history = []
    for _ in range(6):
        history.append(select_model(bindings, policy, "T9", "implementer", history)[1])
    populated, empty = tmp_path / "populated", tmp_path / "empty"
    populated.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                                 for row in history))
    populated.chmod(0o600)

    def measure(path):
        counts = {"json": 0, "sha": 0}
        timeouts, previous = [], sys.getprofile()

        def profile(frame, event, function):
            if event == "call" and frame.f_code is json.loads.__code__:
                counts["json"] += 1
            if event == "c_call" and function is hashlib.sha256:
                counts["sha"] += 1
            if event == "call" and frame.f_code is file_lock.__wrapped__.__code__:
                timeouts.append(frame.f_locals["timeout"])

        sys.setprofile(profile)
        try:
            core.select_and_append(path, bindings, policy, "T9", "implementer",
                                   host_kinds=("codex-cli", "claude-code"), subject="same")
        finally:
            sys.setprofile(previous)
        return counts, timeouts

    (base, base_timeouts), (actual, actual_timeouts) = measure(empty), measure(populated)
    assert actual["json"] - base["json"] == len(history)
    # One identity hash per old row, plus one check of their shared split snapshot.
    assert actual["sha"] - base["sha"] == len(history) + 1
    assert base_timeouts and actual_timeouts and min(base_timeouts + actual_timeouts) >= 60.0
    assert read_decisions(populated)[:len(history)] == history


@pytest.mark.parametrize("limit", ["bytes", "records"])
@requires_anchored_io
def test_round7_transaction_limit_refuses_before_temp_creation(bindings, policy, tmp_path, monkeypatch, limit):
    path = tmp_path / "log"
    _, row = choose(bindings, policy)
    append_decision(path, row)
    before = path.read_bytes()
    if limit == "bytes":
        monkeypatch.setattr(core, "MAX_HISTORY_BYTES", len(before))
    else:
        monkeypatch.setattr(core, "MAX_HISTORY_RECORDS", 1)
    real_open, temporary_opens = os.open, []

    def track_open(name, flags, mode=0o777, *, dir_fd=None):
        if str(name).startswith(".model-select-"):
            temporary_opens.append(name)
        return real_open(name, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", track_open)
    with pytest.raises(ModelSelectionError, match="^history_limit_exceeded: archive_or_rotate_decision_log$"):
        core.select_and_append(path, bindings, policy, "T9", "implementer",
                               host_kinds=("codex-cli", "claude-code"), subject="same")
    assert not temporary_opens and path.read_bytes() == before


@requires_anchored_io
def test_round7_transaction_refuses_corrupt_input_before_publication(bindings, policy, tmp_path):
    path = tmp_path / "log"
    path.write_bytes(b"{broken}\n")
    path.chmod(0o600)
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        core.select_and_append(path, bindings, policy, "T9", "implementer",
                               host_kinds=("codex-cli", "claude-code"), subject="same")
    assert path.read_bytes() == b"{broken}\n"
    assert not list(tmp_path.glob(".model-select-*"))


@pytest.mark.parametrize("eligible", [False, True])
@pytest.mark.parametrize("surface", ["parsed", pytest.param("reader", marks=requires_anchored_io),
                                   pytest.param("transaction", marks=requires_anchored_io)])
def test_round7b_replay_derives_split_eligibility_from_policy(bindings, policy, tmp_path, eligible, surface):
    if eligible:
        policy["flexible_tasks"] = []
    _, forged = choose(bindings, policy)
    forged["split_eligible"] = eligible
    forged["choice"]["reason"] = "family_split" if eligible else "team_family"
    reidentify_record(forged)
    path = tmp_path / "log"
    original = (json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    path.write_bytes(original)
    path.chmod(0o600)
    with pytest.raises(ModelSelectionError, match="^invalid_history:policy_rules_changed: start a new team history$"):
        if surface == "transaction":
            core.select_and_append(path, bindings, policy, "T9", "implementer",
                                   host_kinds=("codex-cli", "claude-code"), subject="same")
        else:
            history = [forged] if surface == "parsed" else core_read_decisions(path)
            select_model(bindings, policy, "T9", "implementer", history)
    assert path.read_bytes() == original
    assert not list(tmp_path.glob(".model-select-*"))


@pytest.mark.parametrize("surface", ["parsed", pytest.param("reader", marks=requires_anchored_io),
    pytest.param("transaction", marks=requires_anchored_io), pytest.param("disk", marks=requires_anchored_io)])
def test_round7b_replay_refuses_same_family_formal_pair(bindings, policy, tmp_path, surface):
    _, first = select_model(bindings, policy, "T4", "reviewer", [], author_family="first")
    _, second = select_model(bindings, policy, "T5", "reviewer", [first], author_family="first")
    second["choice"] = dict(first["choice"])
    reidentify_record(second)
    path = tmp_path / "log"
    original = "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                       for row in (first, second)).encode("ascii")
    path.write_bytes(original)
    path.chmod(0o600)
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        if surface == "disk":
            read_decisions(path)
        elif surface == "transaction":
            core.select_and_append(path, bindings, policy, "T9", "implementer",
                                   host_kinds=("codex-cli", "claude-code"), subject="same")
        else:
            history = [first, second] if surface == "parsed" else core_read_decisions(path)
            select_model(bindings, policy, "T9", "implementer", history)
    assert path.read_bytes() == original


@pytest.mark.parametrize("task", ["T1", "T2", "T3", "T4", "T5", "T6", "T8"])
def test_round7b_replay_derives_each_family_from_supplied_policy(bindings, policy, task):
    role = "orchestrator" if task == "T1" else ("reviewer" if task in ("T4", "T5", "T6", "T8") else "implementer")
    _, forged = select_model(bindings, policy, task, role, [], author_family="first" if role == "reviewer" else None,
                             lane_family="first" if task == "T3" else None)
    if task == "T8":
        # This remains structurally valid: the claimed author still opposes the choice.
        forged["author_family"] = "second"
    forged["choice"]["family"] = "second" if forged["choice"]["family"] == "first" else "first"
    reidentify_record(forged)
    if task == "T8":
        # T8 follows the author marker, so this is a valid change of request, not a forgery.
        assert select_model(bindings, policy, "T9", "implementer", [forged])[1]["counts_before"] == {"first": 0, "second": 0}
    else:
        with pytest.raises(ModelSelectionError, match="^invalid_history:policy_rules_changed: start a new team history$"):
            select_model(bindings, policy, "T9", "implementer", [forged])


@requires_anchored_io
def test_round7b_missing_directory_is_not_empty_history(tmp_path):
    for path in (tmp_path / "absent" / "private" / "log", tmp_path / "absent" / ".."):
        with pytest.raises(ModelSelectionError, match="^unsafe_decision_path$"):
            read_decisions(path)
    assert list(tmp_path.iterdir()) == []
    assert read_decisions(tmp_path / "missing-log") == []
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("surface", ["parsed-other-team", pytest.param("disk", marks=requires_anchored_io),
    pytest.param("reader-other-team", marks=requires_anchored_io), pytest.param("append", marks=requires_anchored_io),
    pytest.param("transaction", marks=requires_anchored_io)])
def test_round7b_changed_family_sets_refuse_on_every_path(bindings, policy, tmp_path, surface):
    _, first = choose(bindings, policy)
    changed = copy.deepcopy(policy)
    for key in ("family_hosts", "target_shares"):
        changed[key]["third"] = changed[key].pop("second")
    changed["family_order"] = ["first", "third"]
    changed["manager_family"] = "third"
    for stages in changed["review_families"].values():
        for stage, family in stages.items():
            if family == "second":
                stages[stage] = "third"
    for intents in changed["task_intents"].values():
        if "second" in intents:
            intents["third"] = intents.pop("second")
    _, second = choose(bindings, changed)
    second["previous_decision_id"] = first["decision_id"]
    reidentify_record(second)
    path = tmp_path / "log"
    original = "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                       for row in (first, second)).encode("ascii")
    path.write_bytes(original)
    path.chmod(0o600)
    unrelated = dict(policy, team_id="other-team")
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        if surface == "disk":
            read_decisions(path)
        elif surface == "parsed-other-team":
            select_model(bindings, unrelated, "T9", "implementer", [first, second])
        elif surface == "reader-other-team":
            select_model(bindings, unrelated, "T9", "implementer", core_read_decisions(path))
        elif surface == "append":
            append_decision(path, dict(first, outcome={"tests_passed": False}))
        else:
            core.select_and_append(path, bindings, unrelated, "T9", "implementer",
                                   host_kinds=("codex-cli", "claude-code"), subject="same")
    assert path.read_bytes() == original


def test_round7b_current_policy_cannot_claim_a_different_calibration(bindings, policy):
    import hashlib

    _, forged = choose(bindings, policy)
    forged["target_shares"] = {"first": 0.0, "second": 1.0}
    forged["choice"]["family"] = "second"
    split = {"target_shares": forged["target_shares"], "family_order": forged["family_order"]}
    forged["split_id"] = hashlib.sha256(json.dumps(
        split, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
    reidentify_record(forged)
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        select_model(bindings, policy, "T9", "implementer", [forged])


@pytest.mark.parametrize("surface", ["read", "append", "transaction"])
def test_round7b_final_parent_component_refuses_before_io(bindings, policy, tmp_path, monkeypatch, surface):
    path = tmp_path / "absent" / ".."
    _, row = choose(bindings, policy)

    def forbidden_open(*args, **kwargs):
        pytest.fail("a final parent component must refuse before any OS open")

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", forbidden_open)
        with pytest.raises(ModelSelectionError, match="^unsafe_decision_path$"):
            if surface == "read":
                read_decisions(path)
            elif surface == "append":
                append_decision(path, row)
            else:
                core.select_and_append(path, bindings, policy, "T9", "implementer",
                                       host_kinds=("codex-cli", "claude-code"), subject="same")


@pytest.mark.parametrize("surface", ["parsed", pytest.param("disk", marks=requires_anchored_io)])
def test_round7b_split_snapshot_preserves_canonical_number_forms(bindings, policy, tmp_path, surface):
    policy["target_shares"] = {"first": 1, "second": 0}
    _, first = choose(bindings, policy)
    _, forged = select_model(bindings, policy, "T9", "implementer", [first])
    forged["target_shares"] = {"first": 1.0, "second": 0.0}
    reidentify_record(forged)  # its claimed split hash still describes integer targets
    if surface == "parsed":
        with pytest.raises(ModelSelectionError, match="^invalid_history$"):
            select_model(bindings, policy, "T9", "implementer", [first, forged])
    else:
        path = tmp_path / "log"
        path.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
                                for row in (first, forged)))
        path.chmod(0o600)
        with pytest.raises(ModelSelectionError, match="^invalid_history$"):
            read_decisions(path)


def test_round7b_policy_id_binds_its_exact_split_hash(bindings, policy):
    import hashlib

    policy["target_shares"] = {"first": 1, "second": 0}
    _, forged = choose(bindings, policy)
    forged["target_shares"] = {"first": 1.0, "second": 0.0}
    split = {"target_shares": forged["target_shares"], "family_order": forged["family_order"]}
    forged["split_id"] = hashlib.sha256(json.dumps(
        split, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
    reidentify_record(forged)
    with pytest.raises(ModelSelectionError, match="^invalid_history$"):
        select_model(bindings, policy, "T9", "implementer", [forged])


@pytest.mark.parametrize("surface", ["bindings", "policy", "read", "append", "transaction"])
def test_round7b_path_budget_precedes_path_parsing(bindings, policy, tmp_path, surface):
    import tracemalloc

    _, row = choose(bindings, policy)
    path = str(tmp_path) + "/" + "x" * 8_000_000
    error = "invalid_" + surface if surface in ("bindings", "policy") else "unsafe_decision_path"
    tracemalloc.start()
    try:
        with pytest.raises(ModelSelectionError, match="^" + error + "$"):
            if surface == "bindings":
                choose(path, policy)
            elif surface == "policy":
                choose(bindings, path)
            elif surface == "read":
                read_decisions(path)
            elif surface == "append":
                append_decision(path, row)
            else:
                core.select_and_append(path, bindings, policy, "T9", "implementer",
                                       host_kinds=("codex-cli", "claude-code"), subject="same")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 512 * 1024
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("bad", [None, [], True, b"bytes"])
def test_round7b_invalid_decision_path_types_have_a_refusal(bindings, policy, bad):
    _, row = choose(bindings, policy)
    for operation in (lambda: read_decisions(bad), lambda: append_decision(bad, row),
                      lambda: core.select_and_append(bad, bindings, policy, "T9", "implementer",
                          host_kinds=("codex-cli", "claude-code"), subject="same")):
        with pytest.raises(ModelSelectionError, match="^unsafe_decision_path$"):
            operation()


@pytest.mark.parametrize("surface", ["bindings", "read"])
def test_round7b_path_depth_is_bounded_before_parent_allocation(bindings, policy, tmp_path, surface):
    import tracemalloc

    path = str(tmp_path) + "/" + "nested/" * 300 + "log"
    error = "invalid_bindings" if surface == "bindings" else "unsafe_decision_path"
    tracemalloc.start()
    try:
        with pytest.raises(ModelSelectionError, match="^" + error + "$"):
            if surface == "bindings":
                choose(path, policy)
            else:
                read_decisions(path)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 512 * 1024


@pytest.mark.parametrize("change", ["manager", "team", "flexible", "formal", "lenses", "second"])
@pytest.mark.parametrize("surface", ["parsed", pytest.param("reader", marks=requires_anchored_io),
                                   pytest.param("transaction", marks=requires_anchored_io)])
def test_mr3c_older_policy_rules_preserve_history(bindings, policy, tmp_path, change, surface):
    history = []
    for task, role, stage in [("T9", "implementer", "primary"), ("T9", "implementer", "primary"),
                              ("T1", "orchestrator", "primary"), ("T2", "implementer", "primary"),
                              ("T4", "reviewer", "primary"), ("T5", "reviewer", "primary"),
                              ("T6", "reviewer", "whole"), ("T8", "reviewer", "second")]:
        history.append(select_model(bindings, policy, task, role, history, review_stage=stage,
                                    author_family="first" if role == "reviewer" else None)[1])
    original = b"".join((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
                        for row in history)
    if change == "manager":
        policy["manager_family"] = "first"
    elif change == "team":
        policy["team_family"] = "second"
    elif change == "flexible":
        policy["flexible_tasks"] = []
    elif change == "formal":
        policy["review_families"]["T4"]["primary"] = "first"
        policy["review_families"]["T5"]["primary"] = "second"
    elif change == "lenses":
        policy["review_families"]["T6"] = {"primary": "second", "whole": "first"}
    else:
        del policy["review_families"]["T8"]["second"]
    path = tmp_path / "log"
    if surface != "parsed":
        path.write_bytes(original)
        path.chmod(0o600)
    if surface == "transaction":
        _, row = core.select_and_append(path, bindings, policy, "T9", "implementer",
                                       host_kinds=("codex-cli", "claude-code"), subject="new")
        assert read_decisions(path) == history + [row]
        assert path.read_bytes().startswith(original)
    else:
        _, row = select_model(bindings, policy, "T9", "implementer",
                              history if surface == "parsed" else core_read_decisions(path))
    assert row["policy_id"] != history[-1]["policy_id"]
    assert row["split_id"] == history[-1]["split_id"]
    assert row["counts_before"] == {"first": 1, "second": 1}
    assert row["previous_decision_id"] == history[-1]["decision_id"]


def test_mr3c_current_policy_missing_review_stage_has_action(bindings, policy):
    _, forged = select_model(bindings, policy, "T6", "reviewer", [], author_family="first")
    forged["review_stage"] = "security"  # Structurally valid, absent from supplied policy.
    reidentify_record(forged)
    with pytest.raises(ModelSelectionError, match="^invalid_history:policy_rules_changed: start a new team history$"):
        select_model(bindings, policy, "T9", "implementer", [forged])


@requires_anchored_io
@pytest.mark.parametrize("surface", ["append", "read", "transaction"])
def test_mr3c_every_log_lock_uses_policy_timeout(bindings, policy, tmp_path, surface):
    import sys
    from aegis_core.storage import file_lock

    path = tmp_path / "log"
    _, row = choose(bindings, policy)
    append_decision(path, row)
    timeouts, previous = [], sys.getprofile()

    def profile(frame, event, function):
        if event == "call" and frame.f_code is file_lock.__wrapped__.__code__:
            timeouts.append(frame.f_locals["timeout"])

    sys.setprofile(profile)
    try:
        if surface == "append":
            append_decision(path, dict(row, outcome={"launch_status": "not_launched"}))
        elif surface == "read":
            assert read_decisions(path) == [row]
        else:
            core.select_and_append(path, bindings, policy, "T9", "implementer",
                                   host_kinds=("codex-cli", "claude-code"), subject="new")
    finally:
        sys.setprofile(previous)
    # Generator profiling records both initial entry and resumption after yield.
    assert timeouts and set(timeouts) == {core._LOCK_TIMEOUT_SECONDS}


@pytest.mark.parametrize("surface", ["parsed", pytest.param("file", marks=requires_anchored_io),
                                   pytest.param("transaction", marks=requires_anchored_io)])
def test_mr3c_260_bindings_have_mr1_parity(bindings, policy, tmp_path, monkeypatch, surface):
    import importlib

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[3] / "tools"))
    provision = importlib.import_module("hierarchy_provision")
    registry = tuple("host-%d" % i for i in range(65))
    templates = [row for row in bindings["hosts"] if row["host"] == "codex-cli"]
    bindings["hosts"] = [dict(copy.deepcopy(row), host=host) for host in registry for row in templates]
    raw = json.dumps(bindings, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert len(bindings["hosts"]) == 260
    assert len(raw) < core.MAX_INPUT_BYTES
    path = tmp_path / "bindings.json"
    path.write_bytes(raw)
    monkeypatch.setattr(provision.hierarchy_hosts, "TEAM_HOSTS", registry)
    monkeypatch.setattr(provision, "read_pinned_bindings", lambda setup, base: (path, raw))
    roles, hosts, _, _ = provision.load_model_bindings({}, tmp_path)
    supplied = path if surface != "parsed" else bindings
    assert core.validate_bindings(supplied, host_kinds=registry) == (roles, hosts)
    policy["family_hosts"] = {"first": [registry[0]], "second": [registry[1]]}
    if surface == "transaction":
        choice, _ = core.select_and_append(tmp_path / "log", supplied, policy, "T9", "implementer",
                                           host_kinds=registry, subject="large")
    else:
        choice, _ = choose(supplied, policy, host_kinds=registry)
    assert choice["host"] == registry[0]


@requires_anchored_io
@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-32",
                                      "utf-32-le", "utf-32-be", "invalid-utf-8"])
@pytest.mark.parametrize("field", ["bindings", "policy"])
def test_mr3c_config_bytes_require_strict_utf8(bindings, policy, tmp_path, encoding, field):
    text = json.dumps(bindings if field == "bindings" else policy)
    raw = text.encode(encoding) if encoding != "invalid-utf-8" else b"\xff" + text.encode("utf-8")
    path = tmp_path / "config.json"
    path.write_bytes(raw)
    with pytest.raises(ModelSelectionError, match="^invalid_" + field + "$"):
        choose(path if field == "bindings" else bindings, path if field == "policy" else policy)


@requires_anchored_io
@pytest.mark.parametrize("surface", ["append", "transaction"])
@pytest.mark.parametrize("change", ["rewrite", "grow", "replace", "unlink", "create"])
def test_mr3c_publication_refuses_changed_log(bindings, policy, tmp_path, monkeypatch, surface, change):
    from types import SimpleNamespace

    path = tmp_path / "log"
    _, first = choose(bindings, policy)
    if change != "create":
        append_decision(path, first)
    history = [] if change == "create" else [first]
    _, pending = select_model(bindings, policy, "T9", "implementer", history, subject="pending")
    fsync, changed = os.fsync, []

    def sync_and_change(descriptor):
        fsync(descriptor)
        if changed:
            return
        if change == "unlink":
            path.unlink()
            changed.append(None)
            return
        if change == "replace":
            replacement = tmp_path / "replacement"
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(path)
        elif change == "rewrite":
            before = path.stat()
            raw = path.read_bytes()
            path.write_bytes(raw.replace(b'lane-one', b'lane-two'))
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000000))
        else:
            with path.open("ab") as stream:
                stream.write(b"external\n")
            path.chmod(0o600)
        changed.append(path.read_bytes())

    monkeypatch.setattr(core, "os", SimpleNamespace(**dict(vars(os), fsync=sync_and_change)))
    with pytest.raises(ModelSelectionError, match="^stale_decision$"):
        if surface == "append":
            append_decision(path, pending)
        else:
            core.select_and_append(path, bindings, policy, "T9", "implementer",
                                   host_kinds=("codex-cli", "claude-code"), subject="pending")
    assert changed
    assert (path.read_bytes() if path.exists() else None) == changed[0]
    assert not list(tmp_path.glob(".model-select-*"))


@requires_anchored_io
def test_mr3c_generation_failure_closes_source(bindings, policy, tmp_path, monkeypatch):
    from types import SimpleNamespace

    path = tmp_path / "log"
    _, row = choose(bindings, policy)
    append_decision(path, row)
    original = path.read_bytes()
    open_log, fstat, streams = core._open_log, os.fstat, []

    def track_open(name, directory):
        stream = open_log(name, directory)
        streams.append(stream)
        return stream

    def fail_generation(descriptor):
        if streams and not streams[0].closed and descriptor == streams[0].fileno():
            raise OSError(errno.EIO, "generation unavailable")
        return fstat(descriptor)

    monkeypatch.setattr(core, "_open_log", track_open)
    monkeypatch.setattr(core, "os", SimpleNamespace(**dict(vars(os), fstat=fail_generation)))
    with pytest.raises(OSError, match="generation unavailable") as raised:
        append_decision(path, dict(row, outcome={"tests_passed": True}))
    assert raised.value.errno == errno.EIO
    assert streams and all(stream.closed for stream in streams)
    assert path.read_bytes() == original
    assert not list(tmp_path.glob(".model-select-*"))


@requires_anchored_io
@pytest.mark.parametrize("surface", ["append", "transaction"])
def test_mr3c_stale_probe_fdopen_failure_closes_descriptor(bindings, policy, tmp_path, monkeypatch, surface):
    from types import SimpleNamespace

    path = tmp_path / "log"
    _, row = choose(bindings, policy)
    append_decision(path, row)
    original = path.read_bytes()
    fdopen, fsync, synced, failed = os.fdopen, os.fsync, [], []

    def track_sync(descriptor):
        fsync(descriptor)
        synced.append(descriptor)

    def fail_probe(descriptor, *args, **kwargs):
        if synced:
            failed.append(descriptor)
            raise OSError(errno.EIO, "probe stream unavailable")
        return fdopen(descriptor, *args, **kwargs)

    monkeypatch.setattr(core, "os", SimpleNamespace(**dict(vars(os), fdopen=fail_probe, fsync=track_sync)))
    with pytest.raises(OSError, match="probe stream unavailable") as raised:
        if surface == "append":
            append_decision(path, dict(row, outcome={"tests_passed": True}))
        else:
            core.select_and_append(path, bindings, policy, "T9", "implementer",
                                   host_kinds=("codex-cli", "claude-code"), subject="new")
    assert raised.value.errno == errno.EIO
    assert len(failed) == 1
    with pytest.raises(OSError) as closed:
        os.fstat(failed[0])
    assert closed.value.errno == errno.EBADF
    assert path.read_bytes() == original
    assert not list(tmp_path.glob(".model-select-*"))
