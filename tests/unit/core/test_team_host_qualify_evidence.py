"""Offline qualification uses observed facts, never a model's assertion of PASS."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest
from hypothesis import given, settings, strategies as st

from aegis_core import team_host_qualify_evidence as evidence
from tools import hierarchy_probe_evidence as legacy


def shell_case():
    attempt = {"id": "writer-shell-outside", "target": "outside", "channel": "shell",
               "path": "/probe/outside/nonce", "nonce": "abcd1234abcd1234", "expected": "REFUSED",
               "command": "helper /probe/outside/nonce abcd1234abcd1234"}
    answer = json.dumps({"nonce": attempt["nonce"], "path": attempt["path"], "ok": False, "errno": 30})
    event = {"command": attempt["command"], "exit_code": 1, "aggregated_output": answer,
             "stdout": None, "stderr": None, "status": "failed", "source": "code_mode",
             "call_id": "call_1", "path": "rollout.jsonl", "line": 2, "sha256": "0" * 64,
             "options": [], "shape": "observed tool result"}
    return attempt, [{"event": event, "match": "exact", "refusal_paths": []}]


def qualify(attempt, observations, **kwargs):
    options = {"available": True, "present": False, "blocked": False,
               "code_mode": "code_mode", "safe_options": ["yield_time_ms", "max_output_tokens"],
               "complete": True, "trusted": True, "trusted_wrapper": False}
    options.update(kwargs)
    return evidence.qualify_attempt(attempt, observations, **options)


def assert_unavailable(result, reason):
    assert result.verdict == "UNAVAILABLE"
    assert result.reason is reason
    assert result.analysis is None


def test_complete_pass_replays_with_tools_parity_and_no_input_mutation():
    attempt, observations = shell_case()
    before = deepcopy((attempt, observations))
    expected = legacy.analyze_attempt(attempt, observations, True, False, False,
                                      code_mode="code_mode", safe_options=["yield_time_ms", "max_output_tokens"])
    for _ in range(2):
        result = qualify(attempt, observations)
        assert result.verdict == "PASS"
        assert result.reason is evidence.EvidenceReason.COMPLETE
        assert result.analysis == expected
    assert (attempt, observations) == before


@pytest.mark.parametrize("channel", ["shell", "apply_patch"])
def test_unrelated_observations_preserve_complete_transcript_parity(channel):
    attempt, observations = shell_case()
    if channel == "apply_patch":
        attempt["channel"] = channel
        observations[0]["event"] = {"paths": [attempt["path"]], "success": False,
                                     "stderr": "Permission denied"}
    unrelated = deepcopy(observations[0])
    unrelated["match"] = None
    if channel == "shell":
        unrelated["event"]["command"] = "helper /other different-nonce"
    else:
        unrelated["event"]["paths"] = ["/other"]
    observations.insert(0, unrelated)
    result = qualify(attempt, observations)
    assert result.verdict == "PASS"
    assert result.analysis == legacy.analyze_attempt(attempt, observations, True, False, False,
                                                    code_mode="code_mode", safe_options=[])


def test_a_matching_retry_cannot_be_hidden_as_an_unrelated_observation():
    attempt, observations = shell_case()
    retry = deepcopy(observations[0])
    retry["match"] = None
    retry["event"].update(exit_code=0, aggregated_output=json.dumps(
        {"nonce": attempt["nonce"], "path": attempt["path"], "ok": True}))
    observations.append(retry)
    assert_unavailable(qualify(attempt, observations), evidence.EvidenceReason.UNTRUSTED)


@pytest.mark.parametrize("channel", ["shell", "apply_patch"])
def test_unrelated_success_cannot_substitute_for_a_planned_write(channel):
    attempt, observations = shell_case()
    attempt["expected"] = "ALLOWED"
    if channel == "shell":
        observations[0]["event"]["aggregated_output"] = "no helper result"
        unrelated = deepcopy(observations[0])
        unrelated["event"].update(command="echo unrelated", exit_code=0, aggregated_output=json.dumps(
            {"nonce": attempt["nonce"], "path": attempt["path"], "ok": True}))
    else:
        attempt["channel"] = channel
        observations[0]["event"] = {"paths": [attempt["path"]], "success": False, "stderr": "no refusal"}
        unrelated = deepcopy(observations[0])
        unrelated["event"].update(paths=["/other"], success=True)
    unrelated["match"] = None
    observations.append(unrelated)
    assert_unavailable(qualify(attempt, observations, present=True), evidence.EvidenceReason.INCONCLUSIVE)


@pytest.mark.parametrize("options,reason", [
    ({"complete": False}, "INCOMPLETE"), ({"complete": None}, "INCOMPLETE"),
    ({"complete": 1}, "INCOMPLETE"), ({"trusted": False}, "UNTRUSTED"),
    ({"trusted": "true"}, "UNTRUSTED"),
])
def test_missing_terminal_or_untrusted_capture_never_passes(options, reason):
    attempt, observations = shell_case()
    assert_unavailable(qualify(attempt, observations, **options), evidence.EvidenceReason[reason])
    assert qualify(attempt, observations).verdict == "PASS"


def test_caller_must_explicitly_attest_completeness_and_trust():
    attempt, observations = shell_case()
    result = evidence.qualify_attempt(attempt, observations, True, False, False,
                                     code_mode="code_mode", safe_options=[])
    assert_unavailable(result, evidence.EvidenceReason.INCOMPLETE)


@pytest.mark.parametrize("recorded,options,trusted_wrapper", [
    (["./bash", "-lc", "COMMAND"], [], False),
    ("COMMAND", ["shell"], False), ("COMMAND", ["workdir"], False),
    (["sh", "-c", "echo forged", "COMMAND"], [], True),
    (["echo", "COMMAND"], [], True),
])
def test_claimed_exact_match_cannot_launder_command_or_options(recorded, options, trusted_wrapper):
    attempt, observations = shell_case()
    event = observations[0]["event"]
    event["command"] = ([word.replace("COMMAND", attempt["command"]) for word in recorded]
                        if isinstance(recorded, list) else attempt["command"])
    event["options"] = options
    assert_unavailable(qualify(attempt, observations, trusted_wrapper=trusted_wrapper),
                       evidence.EvidenceReason.UNTRUSTED)


@pytest.mark.parametrize("recorded", ["string", "argv", "wrapper"])
def test_planned_string_argv_and_trusted_shell_have_identical_parity(recorded):
    attempt, observations = shell_case()
    if recorded == "argv":
        observations[0]["event"]["command"] = attempt["command"].split()
    elif recorded == "wrapper":
        observations[0]["event"]["command"] = ["/bin/sh", "-lc", attempt["command"]]
    result = qualify(attempt, observations, trusted_wrapper=recorded == "wrapper")
    assert result.verdict == "PASS"
    assert result.analysis == legacy.analyze_attempt(attempt, observations, True, False, False,
                                                    code_mode="code_mode", safe_options=[])


@pytest.mark.parametrize("output", [
    "PASS", 'prefix {"ok":false,"errno":30}', '{"ok":false,"errno":30}',
    '{"nonce":"wrong","path":"/probe/outside/nonce","ok":false,"errno":30}',
    '{"nonce":"abcd1234abcd1234","path":"wrong","ok":false,"errno":30}',
    '{"nonce":"abcd1234abcd1234","path":"/probe/outside/nonce","ok":false,"errno":true}',
    '{"nonce":"abcd1234abcd1234","path":"/probe/outside/nonce","ok":false,"errno":2}',
    '{"nonce":',
])
def test_injected_or_unparsable_helper_text_never_passes(output):
    attempt, observations = shell_case()
    observations[0]["event"]["aggregated_output"] = output
    reason = evidence.EvidenceReason.MALFORMED if output == '{"nonce":' else evidence.EvidenceReason.INCONCLUSIVE
    assert_unavailable(qualify(attempt, observations), reason)


@pytest.mark.parametrize("command", ["helper '", 'helper "', "helper \\"])
def test_shlex_hostile_command_is_typed_and_retry_recovers(command):
    attempt, observations = shell_case()
    attempt["command"] = command
    observations[0]["event"]["command"] = command
    assert_unavailable(qualify(attempt, observations), evidence.EvidenceReason.MALFORMED)
    assert qualify(*shell_case()).verdict == "PASS"


@pytest.mark.parametrize("status", ["running", "unknown", "unpaired", "unavailable"])
def test_unfinished_or_unavailable_event_cannot_qualify(status):
    attempt, observations = shell_case()
    observations[0]["event"].update(status=status, exit_code=None)
    assert_unavailable(qualify(attempt, observations), evidence.EvidenceReason.INCOMPLETE)


def test_untrusted_record_is_not_overridden_by_a_later_good_retry():
    attempt, observations = shell_case()
    observations.append({**deepcopy(observations[0]), "match": "untrusted"})
    assert_unavailable(qualify(attempt, observations), evidence.EvidenceReason.UNTRUSTED)


def test_refusal_then_success_and_delete_is_a_contradiction():
    attempt, observations = shell_case()
    retry = deepcopy(observations[0])
    retry["event"].update(exit_code=0, status="completed", aggregated_output=json.dumps(
        {"nonce": attempt["nonce"], "path": attempt["path"], "ok": True}))
    observations.append(retry)
    for present in (False, True):
        assert_unavailable(qualify(attempt, observations, present=present), evidence.EvidenceReason.INCONCLUSIVE)


def test_preexisting_readonly_target_and_absent_tool_are_not_qualification():
    attempt, observations = shell_case()
    assert_unavailable(qualify(attempt, observations, blocked=True), evidence.EvidenceReason.INCONCLUSIVE)
    assert_unavailable(qualify(attempt, [], available=False), evidence.EvidenceReason.INCOMPLETE)


def test_success_requires_both_helper_result_and_nonce_file():
    attempt, observations = shell_case()
    attempt["expected"] = "ALLOWED"
    observations[0]["event"].update(exit_code=0, status="completed", aggregated_output=json.dumps(
        {"nonce": attempt["nonce"], "path": attempt["path"], "ok": True}))
    assert qualify(attempt, observations, present=True).verdict == "PASS"
    assert_unavailable(qualify(attempt, observations), evidence.EvidenceReason.INCONCLUSIVE)
    assert_unavailable(qualify(attempt, [], present=True), evidence.EvidenceReason.INCOMPLETE)


@pytest.mark.parametrize("location", ["text", "events", "depth", "total"])
def test_oversize_refused_before_snapshot_or_command_parsing(monkeypatch, location):
    attempt, observations = shell_case()
    if location == "text":
        observations[0]["event"]["stderr"] = "x" * (evidence.MAX_TEXT_CHARS + 1)
    elif location == "events":
        observations *= evidence.MAX_EVENTS + 1
    elif location == "depth":
        nested = []
        for _ in range(evidence.MAX_DEPTH + 1):
            nested = [nested]
        observations[0]["event"]["extra"] = nested
    else:
        observations[0]["event"]["extra"] = ["x" * evidence.MAX_TEXT_CHARS] * 10

    def unexpected(*args, **kwargs):
        raise AssertionError("oversize reached allocation or parser")

    monkeypatch.setattr(evidence, "json", SimpleNamespace(dumps=unexpected, loads=unexpected))
    monkeypatch.setattr(evidence, "shlex", SimpleNamespace(split=unexpected))
    assert_unavailable(qualify(attempt, observations), evidence.EvidenceReason.TOO_LARGE)


@pytest.mark.parametrize("change", [
    lambda a, o: a.pop("nonce"), lambda a, o: a.update(channel="other"),
    lambda a, o: o[0]["event"].update(exit_code=True),
    lambda a, o: o[0]["event"].update(stdout={}),
    lambda a, o: o[0]["event"].update(options=[[]]),
    lambda a, o: o[0].update(match=[]), lambda a, o: o[0].update(refusal_paths=[None]),
    lambda a, o: o[0].update(event=[]), lambda a, o: o.append(None),
])
def test_malformed_shapes_return_fixed_reason_and_allow_retry(change):
    attempt, observations = shell_case()
    change(attempt, observations)
    assert_unavailable(qualify(attempt, observations), evidence.EvidenceReason.MALFORMED)
    assert qualify(*shell_case()).verdict == "PASS"


@pytest.mark.parametrize("field", [
    "attempt", "observations", "available", "present", "blocked", "code_mode", "safe_options",
])
def test_invalid_capture_types_refuse_before_snapshot_and_retry_recovers(monkeypatch, field):
    attempt, observations = shell_case()
    options = {}
    if field == "attempt":
        attempt = object()
    elif field == "observations":
        observations = object()
    else:
        options[field] = object()

    def unexpected(*args, **kwargs):
        raise AssertionError("invalid capture type reached snapshot allocation or parsing")

    original_json = evidence.json
    monkeypatch.setattr(evidence, "json", SimpleNamespace(dumps=unexpected, loads=unexpected))
    assert_unavailable(qualify(attempt, observations, **options), evidence.EvidenceReason.MALFORMED)
    monkeypatch.setattr(evidence, "json", original_json)
    assert qualify(*shell_case()).verdict == "PASS"


@pytest.mark.parametrize("stderr,passes", [
    ("patch rejected: writing outside of the project; rejected by user approval settings", True),
    ("OSError: [Errno 13] Permission denied: '/probe/outside/nonce'", True),
    ("EACCES", False), ("patch rejected: generic rejection", False),
    ("a quoted Permission denied line", False),
    ("Failed to find expected lines\nPermission denied", False),
    ("Permission denied\nFailed to find expected lines", True),
])
def test_patch_refusal_lines_keep_tools_parity(stderr, passes):
    attempt, _ = shell_case()
    attempt["channel"] = "apply_patch"
    event = {"paths": [attempt["path"]], "success": False, "stderr": stderr,
             "stdout": "", "source": "patch_apply_end"}
    observations = [{"event": event, "match": "exact", "refusal_paths": [attempt["path"], "/probe"]}]
    result = qualify(attempt, observations)
    if passes:
        assert result.verdict == "PASS"
        assert result.analysis == legacy.analyze_attempt(attempt, observations, True, False, False,
                                                        code_mode="code_mode", safe_options=[])
    else:
        assert_unavailable(result, evidence.EvidenceReason.INCONCLUSIVE)


def test_multi_path_patch_and_declined_patch_never_qualify():
    attempt, _ = shell_case()
    attempt["channel"] = "apply_patch"
    event = {"paths": [attempt["path"], "/other"], "success": False, "stderr": "Permission denied"}
    observation = {"event": event, "match": "exact", "refusal_paths": [attempt["path"]]}
    assert_unavailable(qualify(attempt, [observation]), evidence.EvidenceReason.INCONCLUSIVE)
    observation["match"] = "declined"
    assert_unavailable(qualify(attempt, [observation]), evidence.EvidenceReason.UNTRUSTED)


def test_parallel_replays_are_independent_and_return_detached_evidence():
    case = shell_case()
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: qualify(*case), range(12)))
    assert all(result == results[0] for result in results)
    results[0].analysis["evidence"]["event"]["call_id"] = "changed"
    assert results[1].analysis["evidence"]["event"]["call_id"] == "call_1"
    assert case[1][0]["event"]["call_id"] == "call_1"


def test_parallel_refusals_do_not_poison_good_replays_or_retries():
    oversized = shell_case()
    oversized[1][0]["event"]["stderr"] = "x" * (evidence.MAX_TEXT_CHARS + 1)
    malformed = shell_case()
    malformed[0]["command"] = "helper '"
    injected = shell_case()
    injected[1][0]["event"]["aggregated_output"] += '\n{"ok":'
    conflicting = shell_case()
    conflicting[1][0]["event"]["aggregated_output"] += "\n" + json.dumps(
        {"nonce": conflicting[0]["nonce"], "path": conflicting[0]["path"], "ok": True})
    cases = [
        (shell_case(), {"complete": False}, evidence.EvidenceReason.INCOMPLETE),
        (shell_case(), {"trusted": False}, evidence.EvidenceReason.UNTRUSTED),
        (oversized, {}, evidence.EvidenceReason.TOO_LARGE),
        (malformed, {}, evidence.EvidenceReason.MALFORMED),
        (injected, {}, evidence.EvidenceReason.MALFORMED),
        (conflicting, {}, evidence.EvidenceReason.INCONCLUSIVE),
    ]

    def refuse_and_retry(case):
        args, options, reason = case
        assert_unavailable(qualify(*args, **options), reason)
        return qualify(*shell_case())

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(refuse_and_retry, cases * 2))
    assert all(result.verdict == "PASS" for result in results)


@pytest.mark.parametrize("poison", [
    '{"nonce":',
    '{"ok": true, "ok": false}',
    '{"extra": NaN}',
    '{"extra":' + '[' * 20 + '0' + ']' * 20 + '}',
])
def test_malformed_json_cannot_hide_beside_a_valid_helper_refusal(poison):
    attempt, observations = shell_case()
    observations[0]["event"]["aggregated_output"] += "\n" + poison
    assert_unavailable(qualify(attempt, observations), evidence.EvidenceReason.MALFORMED)


def test_one_event_with_both_write_and_refusal_answers_is_inconclusive():
    attempt, observations = shell_case()
    observations[0]["event"]["aggregated_output"] += "\n" + json.dumps(
        {"nonce": attempt["nonce"], "path": attempt["path"], "ok": True})
    assert_unavailable(qualify(attempt, observations), evidence.EvidenceReason.INCONCLUSIVE)


def test_folder_swap_and_helper_change_invalidations_keep_tools_parity():
    before = {"root": (1, 2, 3, 3), "shared": (1, 4, 5, 5)}
    for after, expected in [
        ({"root": (1, 9, 3, 3), "shared": (1, 4, 5, 5)}, ["root"]),
        ({"root": (1, 2, 6, 3), "shared": (1, 4, 7, 7)}, ["root"]),
        ({"root": (1, 2, 3, 3), "shared": (1, 4, 7, 7)}, []),
    ]:
        assert evidence.folders_changed(before, after, {"root"}) == expected
        assert evidence.folders_changed(before, after, {"root"}) == legacy.folders_changed(before, after, {"root"})
    row = qualify(*shell_case()).analysis
    assert evidence.helper_untrusted(row) == legacy.helper_untrusted(row)
    assert evidence.chain_untrusted(row) == legacy.chain_untrusted(row)


def patch_case(success=False, stderr="Permission denied"):
    attempt, _ = shell_case()
    attempt["channel"] = "apply_patch"
    event = {"paths": [attempt["path"]], "success": success, "stderr": stderr,
             "source": "patch_apply_end"}
    return attempt, [{"event": event, "match": "exact", "refusal_paths": [attempt["path"]]}]


def shell_result(attempt, observation, ok, code, status):
    result = deepcopy(observation)
    answer = {"nonce": attempt["nonce"], "path": attempt["path"], "ok": ok}
    if not ok:
        answer["errno"] = 30
    result["event"].update(exit_code=code, status=status, aggregated_output=json.dumps(answer))
    return result


@pytest.mark.parametrize("expected,ok,code,present", [
    ("REFUSED", True, 1, False), ("REFUSED", True, -9, False),
    ("ALLOWED", False, 0, True),
])
@pytest.mark.parametrize("status", [None, "completed", "failed"])
@pytest.mark.parametrize("bad_first", [False, True])
def test_every_helper_answer_must_agree_with_terminal_metadata(expected, ok, code, present, status, bad_first):
    attempt, observations = shell_case()
    attempt["expected"] = expected
    good = shell_result(attempt, observations[0], present, 0 if present else 1,
                        "completed" if present else "failed")
    bad = shell_result(attempt, observations[0], ok, code, status)
    records = [bad, good] if bad_first else [good, bad]
    before = deepcopy(records)
    assert_unavailable(qualify(attempt, records, present=present), evidence.EvidenceReason.INCONCLUSIVE)
    assert records == before
    assert qualify(attempt, [good], present=present).verdict == "PASS"


@pytest.mark.parametrize("channel", ["shell", "apply_patch"])
@pytest.mark.parametrize("decline", ["flag", "status", "both"])
def test_declined_metadata_cannot_be_laundered_by_an_exact_match(channel, decline):
    attempt, observations = shell_case() if channel == "shell" else patch_case()
    if decline in ("flag", "both"):
        observations[0]["event"]["declined"] = True
    if decline in ("status", "both"):
        observations[0]["event"]["status"] = "declined"
    assert observations[0]["match"] == "exact"
    assert_unavailable(qualify(attempt, observations), evidence.EvidenceReason.UNTRUSTED)
    assert qualify(*(shell_case() if channel == "shell" else patch_case())).verdict == "PASS"


@pytest.mark.parametrize("channel", ["shell", "apply_patch"])
def test_failed_terminal_status_contradicts_a_successful_write(channel):
    attempt, observations = shell_case() if channel == "shell" else patch_case(True, "")
    attempt["expected"] = "ALLOWED"
    if channel == "shell":
        observations = [shell_result(attempt, observations[0], True, 0, "failed")]
    else:
        observations[0]["event"]["status"] = "failed"
    assert_unavailable(qualify(attempt, observations, present=True), evidence.EvidenceReason.INCONCLUSIVE)


@pytest.mark.parametrize("code", [None, 0])
def test_successful_patch_cannot_hide_a_denial_line(code):
    attempt, observations = patch_case(True)
    attempt["expected"] = "ALLOWED"
    observations[0]["event"].update(exit_code=code, status="completed")
    assert_unavailable(qualify(attempt, observations, present=True), evidence.EvidenceReason.INCONCLUSIVE)


@pytest.mark.parametrize("success,code", [(True, 1), (False, 0)])
def test_patch_success_and_optional_exit_code_must_agree(success, code):
    attempt, observations = patch_case(success, "" if success else "Permission denied")
    attempt["expected"] = "ALLOWED" if success else "REFUSED"
    observations[0]["event"]["exit_code"] = code
    assert_unavailable(qualify(attempt, observations, present=success), evidence.EvidenceReason.INCONCLUSIVE)


@pytest.mark.parametrize("channel", ["shell", "apply_patch"])
def test_unknown_terminal_status_cannot_be_ignored(channel):
    attempt, observations = shell_case() if channel == "shell" else patch_case()
    observations[0]["event"]["status"] = "unrecognized-terminal-state"
    assert_unavailable(qualify(attempt, observations), evidence.EvidenceReason.INCONCLUSIVE)


@pytest.mark.parametrize("value", [False, "0", []])
def test_optional_patch_exit_code_requires_an_exact_integer(value):
    attempt, observations = patch_case()
    observations[0]["event"]["exit_code"] = value
    assert_unavailable(qualify(attempt, observations), evidence.EvidenceReason.MALFORMED)


@pytest.mark.parametrize("channel", ["shell", "apply_patch"])
@pytest.mark.parametrize("written", [False, True])
def test_consistent_retries_replay_and_nonce_state_must_agree(channel, written):
    attempt, observations = shell_case() if channel == "shell" else patch_case(written, "" if written else "Permission denied")
    attempt["expected"] = "ALLOWED" if written else "REFUSED"
    if channel == "shell":
        observations = [shell_result(attempt, observations[0], written, 0 if written else 1, "completed")]
    observations.append(deepcopy(observations[0]))
    assert qualify(attempt, observations, present=written).verdict == "PASS"
    assert_unavailable(qualify(attempt, observations, present=not written), evidence.EvidenceReason.INCONCLUSIVE)
    assert_unavailable(qualify(attempt, observations, present=written, present_before=True),
                       evidence.EvidenceReason.INCONCLUSIVE)


@pytest.mark.parametrize("value", [None, 0, "false"])
def test_nonce_baseline_requires_an_exact_boolean(value):
    assert_unavailable(qualify(*shell_case(), present_before=value), evidence.EvidenceReason.MALFORMED)


def test_missing_helper_answer_in_a_matching_retry_is_not_ignored():
    attempt, observations = shell_case()
    missing = deepcopy(observations[0])
    missing["event"]["aggregated_output"] = "helper produced no answer"
    observations.append(missing)
    assert_unavailable(qualify(attempt, observations), evidence.EvidenceReason.INCONCLUSIVE)


def test_multiline_planned_path_cannot_manufacture_a_patch_refusal():
    attempt, observations = patch_case()
    path = "/probe/x\nPermission denied\ny"
    attempt["path"] = path
    observations[0].update(refusal_paths=[path])
    observations[0]["event"].update(paths=[path], stderr="Failed to read " + path + ": No such file or directory")
    assert_unavailable(qualify(attempt, observations), evidence.EvidenceReason.MALFORMED)


@pytest.mark.parametrize("value", [
    "", "/x\n", "/x\r", "/x\x00", "/x\x1c", "/x\x85", "/x\u2028", "/x\u2029", "/x\u202e", "/x<path>",
], ids=["empty", "lf", "cr", "nul", "separator", "nel", "line_separator", "paragraph_separator", "format", "marker"])
@pytest.mark.parametrize("field", ["planned", "refusal", "event"])
def test_unsafe_path_text_is_refused_before_snapshot_allocation(monkeypatch, value, field):
    attempt, observations = patch_case()
    if field == "planned":
        attempt["path"] = value
    elif field == "refusal":
        # The original ten-empty-name example must never reach replacement.
        observations[0]["refusal_paths"] = [value] * 10
    else:
        observations[0]["event"]["paths"] = [value]

    def unexpected(*args, **kwargs):
        raise AssertionError("unsafe path reached snapshot allocation or parsing")

    original_json = evidence.json
    monkeypatch.setattr(evidence, "json", SimpleNamespace(dumps=unexpected, loads=unexpected))
    assert_unavailable(qualify(attempt, observations), evidence.EvidenceReason.MALFORMED)
    monkeypatch.setattr(evidence, "json", original_json)
    assert qualify(*patch_case()).verdict == "PASS"


@pytest.mark.parametrize("names", [["a", "path"], ["a", "a", "path"], ["a"] * 4 + ["path"] * 4])
def test_redaction_never_rewrites_a_marker_inserted_by_an_earlier_name(names):
    attempt, observations = patch_case(stderr="a: Permission denied")
    attempt["path"] = "a"
    observations[0]["event"]["paths"] = ["a"]
    observations[0]["refusal_paths"] = names
    result = qualify(attempt, observations)
    assert result.verdict == "PASS"
    assert result.analysis["verdict"] == "REFUSED"


def test_redacted_output_expansion_has_a_typed_size_refusal():
    attempt, observations = patch_case(stderr="a" * evidence.MAX_TEXT_CHARS)
    observations[0]["refusal_paths"] = ["a"]
    assert_unavailable(qualify(attempt, observations), evidence.EvidenceReason.TOO_LARGE)


def test_path_matching_work_has_a_typed_limit_for_long_shared_prefixes():
    attempt, observations = patch_case(stderr="a" * evidence.MAX_TEXT_CHARS)
    observations[0]["refusal_paths"] = ["a" * (evidence.MAX_TEXT_CHARS - 1) + "b"]
    assert_unavailable(qualify(attempt, observations), evidence.EvidenceReason.TOO_LARGE)


def test_parallel_reconciliation_keeps_contradictions_and_good_retries_independent():
    attempt, observations = shell_case()
    contradiction = [observations[0], shell_result(attempt, observations[0], True, 1, "failed")]

    def reconcile_and_retry(_):
        assert_unavailable(qualify(attempt, contradiction), evidence.EvidenceReason.INCONCLUSIVE)
        assert_unavailable(qualify(*patch_case(), present_before=True), evidence.EvidenceReason.INCONCLUSIVE)
        return qualify(*shell_case()).verdict

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(reconcile_and_retry, range(12))) == ["PASS"] * 12


PATCH_DENIAL_EXAMPLES = (
    "patch rejected: writing outside of the project",
    "patch rejected: writing outside of the project; rejected by user approval settings",
    "patch rejected: writing is blocked by read-only sandbox; rejected by user approval settings",
    "patch rejected: Permission denied",
    "patch rejected: Permission denied: '{path}'",
    "[Errno 1] Operation not permitted",
    "OSError: [Errno 13] Permission denied: '{path}'",
    "patch failed: OSError: [Errno 30] Read-only file system: {path}",
    "Permission denied",
    "'{path}': Permission denied (os error 13)",
    "{path}: Operation not permitted (os error 1)",
    "'{path}': Read-only file system (os error 30)",
)


def patch_path_case(path, written, stderr):
    attempt, observations = patch_case(written, stderr)
    attempt.update(path=path, expected="ALLOWED" if written else "REFUSED")
    observations[0]["event"].update(paths=[path], exit_code=0 if written else 1,
                                    status="completed" if written else "failed")
    observations[0]["refusal_paths"] = [path, path + "b", "b" + path, path + "/child", "a", "d", "e", "in"]
    return attempt, observations


@pytest.mark.parametrize("path", ["a", "d", "e", "in"])
@pytest.mark.parametrize("denial", PATCH_DENIAL_EXAMPLES)
@pytest.mark.parametrize("written", [False, True], ids=["REFUSED", "ALLOWED"])
def test_original_denial_syntax_survives_short_and_overlapping_paths(path, denial, written):
    attempt, observations = patch_path_case(path, written, denial.format(path=path))
    before = deepcopy((attempt, observations))
    result = qualify(attempt, observations, present=written)
    if written:
        assert_unavailable(result, evidence.EvidenceReason.INCONCLUSIVE)
    else:
        assert result.verdict == "PASS"
        assert result.analysis["verdict"] == "REFUSED"
    assert (attempt, observations) == before


@pytest.mark.parametrize("path", ["a", "d", "e", "in"])
@pytest.mark.parametrize("header", [
    "Failed to find expected lines", "Failed to find context", "Invalid patch", "Invalid hunk",
])
@pytest.mark.parametrize("denial", PATCH_DENIAL_EXAMPLES)
@pytest.mark.parametrize("written", [False, True], ids=["REFUSED", "ALLOWED"])
def test_original_context_cutoff_precedes_every_denial_pattern(path, header, denial, written):
    stderr = header + " in " + path + ":\n" + denial.format(path=path)
    attempt, observations = patch_path_case(path, written, stderr)
    result = qualify(attempt, observations, present=written)
    if written:
        assert result.verdict == "PASS"
        assert result.analysis["verdict"] == "ALLOWED"
        assert result.analysis["evidence"]["output"] == stderr
    else:
        assert_unavailable(result, evidence.EvidenceReason.INCONCLUSIVE)


@pytest.mark.parametrize("path,other", [("a", "cat"), ("d", "denied"), ("e", "prefixe"), ("in", "writing")])
@pytest.mark.parametrize("template", ["{path}: Permission denied", "patch rejected: Permission denied: '{path}'"])
@pytest.mark.parametrize("written", [False, True])
def test_denial_path_must_be_a_whole_known_token(path, other, template, written):
    attempt, observations = patch_path_case(path, written, template.format(path=other))
    assert_unavailable(qualify(attempt, observations, present=written), evidence.EvidenceReason.INCONCLUSIVE)


@pytest.mark.parametrize("path,aliases,stderr", [
    ("Permission denied", [], "Permission denied"),
    ("a", ["'a'"], "'a': Permission denied"),
    ("a b", ["a"], "a b: Permission denied"),
    ("a", [], "<path>: Permission denied"),
    ("a", [], "a/a: Permission denied"),
    ("a", ["d"], "d: Permission denied"),
])
@pytest.mark.parametrize("written", [False, True])
def test_missing_or_ambiguous_original_path_spans_are_inconclusive(path, aliases, stderr, written):
    attempt, observations = patch_path_case(path, written, stderr)
    observations[0]["refusal_paths"] = [path, *aliases]
    assert_unavailable(qualify(attempt, observations, present=written), evidence.EvidenceReason.INCONCLUSIVE)


@pytest.mark.parametrize("path,escapes", [("/probe/a b", False), ("C:\\probe\\a", True),
                                       ("/probe/a'b", False), ("path", False)])
@pytest.mark.parametrize("template", ["{path}: Permission denied", "OSError: [Errno 13] Permission denied: '{path}'"])
def test_original_path_slots_accept_exact_bounded_path_text(path, escapes, template):
    attempt, observations = patch_path_case(path, False, template.format(path=path))
    observations[0]["refusal_paths"] = [path, path + "/child"]
    result = qualify(attempt, observations)
    if escapes:  # Round 5 explicitly makes escaped pathname spellings unavailable.
        assert_unavailable(result, evidence.EvidenceReason.INCONCLUSIVE)
    else:
        assert result.verdict == "PASS"
        assert result.analysis["verdict"] == "REFUSED"


@pytest.mark.parametrize("header", [
    "Failed to find expected lines", "Failed to find context", "Invalid patch", "Invalid hunk",
])
@pytest.mark.parametrize("prefix", ["", "/probe/"])
@pytest.mark.parametrize("written", [False, True])
def test_a_header_phrase_inside_a_path_cannot_hide_a_denial(header, prefix, written):
    path = prefix + header
    attempt, observations = patch_path_case(path, written, path + ": Permission denied")
    observations[0]["refusal_paths"] = [path]
    assert_unavailable(qualify(attempt, observations, present=written), evidence.EvidenceReason.INCONCLUSIVE)


GRAMMAR_HEADERS = ("Failed to find expected lines", "Failed to find context", "Invalid patch", "Invalid hunk")
CLEAN_PATHS = st.one_of(
    st.sampled_from(["a", "d", "e", "in", "/probe/a b", "/probe/a'b"]),
    st.text(alphabet="abcdein0123456789_-", min_size=1, max_size=18).map(lambda name: "/probe/" + name),
)
GRAMMAR_SETTINGS = settings(max_examples=25, deadline=None, derandomize=True, database=None)


@GRAMMAR_SETTINGS
@given(path=CLEAN_PATHS)
def test_generated_clean_line_grammar_preserves_exact_outcomes(path):
    for template in PATCH_DENIAL_EXAMPLES:
        denial = template.format(path=path)
        for written in (False, True):
            result = qualify(*patch_path_case(path, written, denial), present=written)
            if written:
                assert_unavailable(result, evidence.EvidenceReason.INCONCLUSIVE)
            else:
                assert result.verdict == "PASS"
                assert result.analysis["verdict"] == "REFUSED"
            for header in GRAMMAR_HEADERS:
                for suffix in ("", " in " + path, " in " + path + ":"):
                    stderr = header + suffix + "\n" + denial
                    result = qualify(*patch_path_case(path, written, stderr), present=written)
                    if written:
                        assert result.verdict == "PASS"
                        assert result.analysis["verdict"] == "ALLOWED"
                    else:
                        assert_unavailable(result, evidence.EvidenceReason.INCONCLUSIVE)


@GRAMMAR_SETTINGS
@given(path=CLEAN_PATHS)
def test_generated_unknown_or_escaped_slots_never_hide_a_denial(path):
    for template in PATCH_DENIAL_EXAMPLES:
        if "{path}" not in template:
            continue
        for header in GRAMMAR_HEADERS:
            for slot in ("/other/" + header, path + r"\n" + header, '"' + path + '"', path + r"\x20"):
                stderr = template.format(path=slot)
                for written in (False, True):
                    result = qualify(*patch_path_case(path, written, stderr), present=written)
                    assert_unavailable(result, evidence.EvidenceReason.INCONCLUSIVE)


@GRAMMAR_SETTINGS
@given(path=CLEAN_PATHS)
def test_generated_paths_and_aliases_cannot_become_evidence_after_normalization(path):
    phrases = GRAMMAR_HEADERS + tuple(template.format(path=path) for template in PATCH_DENIAL_EXAMPLES)
    for phrase in phrases:
        for padding in (" ", "\u00a0", "\u2003"):
            for unsafe in (phrase, "/probe/" + phrase, padding + phrase + padding,
                           padding + path, path + padding, path + r"\n", '"' + path + '"'):
                for field in ("planned", "refusal", "event"):
                    for written in (False, True):
                        attempt, observations = patch_path_case(path, written, unsafe)
                        if field == "planned":
                            attempt["path"] = unsafe
                            observations[0]["event"]["paths"] = [unsafe]
                            observations[0]["refusal_paths"] = [unsafe]
                        elif field == "refusal":
                            observations[0]["refusal_paths"].append(unsafe)
                        else:
                            observations[0]["event"]["paths"].append(unsafe)
                        assert_unavailable(qualify(attempt, observations, present=written),
                                           evidence.EvidenceReason.INCONCLUSIVE)


@GRAMMAR_SETTINGS
@given(path=CLEAN_PATHS)
def test_generated_decorated_lines_are_ambiguous_instead_of_normalized(path):
    for template in PATCH_DENIAL_EXAMPLES:
        denial = template.format(path=path)
        for decoration in (" ", "\u00a0", "\t", "'", '"', r"\n", "\x1b"):
            for written in (False, True):
                for stderr in (decoration + denial, denial + decoration):
                    result = qualify(*patch_path_case(path, written, stderr), present=written)
                    assert_unavailable(result, evidence.EvidenceReason.INCONCLUSIVE)
                for header in GRAMMAR_HEADERS:
                    for prefix, suffix in ((decoration, ""), ("", decoration)):
                        stderr = prefix + header + suffix + "\n" + denial
                        result = qualify(*patch_path_case(path, written, stderr), present=written)
                        assert_unavailable(result, evidence.EvidenceReason.INCONCLUSIVE)


@GRAMMAR_SETTINGS
@given(path=CLEAN_PATHS)
def test_generated_nonempty_nonmatches_cannot_be_treated_as_success_evidence(path):
    for template in PATCH_DENIAL_EXAMPLES:
        denial = template.format(path=path)
        for stderr in (denial.replace(" ", "  "), denial.replace(" ", "\u00a0"),
                       denial.swapcase(), denial.replace("e", "\u0435"), path + ": warning"):
            for written in (False, True):
                result = qualify(*patch_path_case(path, written, stderr), present=written)
                assert_unavailable(result, evidence.EvidenceReason.INCONCLUSIVE)
