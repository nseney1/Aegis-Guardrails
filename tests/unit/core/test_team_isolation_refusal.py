"""The capability, mount, and verify APIs share one fixed refusal type."""
import ast
from concurrent.futures import ThreadPoolExecutor
import importlib
from pathlib import Path
from threading import Barrier

import pytest

from aegis_core import team_isolation_capability as capability, team_isolation_mounts as mounts
from aegis_core import team_isolation_verify as verify


def test_shared_refusal_preserves_the_code_string_and_legacy_imports():
    shared = importlib.import_module("aegis_core.team_isolation_refusal")
    assert capability.IsolationRefusal is mounts.IsolationRefusal is verify.IsolationRefusal is shared.IsolationRefusal
    assert capability.REFUSALS is mounts.REFUSALS is shared.REFUSALS
    for code in ("unknown_host", "unsafe_mount", "expected_record"):
        refusal = shared.IsolationRefusal(code)
        assert str(refusal) == refusal.code == refusal.reason == code
        assert refusal.exit_code == 1
        assert refusal.message == shared.REFUSALS[code]
        assert refusal.next_action == {"actor": "operator", "command": refusal.message}


@pytest.mark.parametrize("code", ["undefined_refusal", [], None], ids=["unregistered", "unhashable", "missing"])
def test_unknown_refusal_codes_have_one_fixed_response(code):
    refusal = capability.IsolationRefusal(code)
    assert str(refusal) == refusal.code == refusal.reason == "internal"
    assert refusal.exit_code == 1
    assert refusal.message == "Report an internal isolation check failure."
    assert refusal.next_action == {"actor": "operator", "command": refusal.message}


def test_list_literal_capability_result_codes(request):
    """Publish literal code sites as an advisory pytest report section."""
    path = Path(capability.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    sites = set()
    for node in ast.walk(tree):
        candidates = []
        if isinstance(node, ast.Dict):
            candidates.extend(value for key, value in zip(node.keys, node.values)
                              if isinstance(key, ast.Constant) and key.value == "code")
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
              and node.func.id == "_refusal"):
            candidates.extend(node.args[:1])
        sites.update((value.lineno, value.value) for value in candidates
                     if isinstance(value, ast.Constant) and type(value.value) is str)
    request.node.add_report_section("call", "literal result codes",
                                    "\n".join(f"{path.name}:{line} {code}" for line, code in sorted(sites)))


_UNSTAGED = {"status", "code", "reason", "next_action"}
_STAGED = _UNSTAGED | {"stage"}
_DOCUMENT_STAGES = {"config", "container-inspection", "image-inspection"}
_DOCUMENT_CODES = {"document_invalid", "document_read", "document_size"}


def test_plan_projection_pins_staged_and_unstaged_keys_and_preserves_capability():
    """Invariant: one plan projection; capability responses keep their own schema."""
    shared = importlib.import_module("aegis_core.team_isolation_refusal")
    assert set(shared.UNSTAGED_PLAN_KEYS) == _UNSTAGED
    assert set(shared.STAGED_PLAN_KEYS) == _STAGED
    assert set(shared.PLAN_STAGES) == _DOCUMENT_STAGES
    assert set(shared.DOCUMENT_CODES) == _DOCUMENT_CODES
    plain = shared.plan_response(shared.IsolationRefusal("team_run_fields"))
    assert set(plain) == _UNSTAGED
    assert plain["reason"] == shared.REFUSALS["team_run_fields"]
    assert plain["next_action"] == {"actor": "operator", "command": plain["reason"]}
    assert "\n" not in plain["reason"] and "\r" not in plain["reason"]
    staged = shared.plan_response(shared.IsolationRefusal("document_invalid", stage="config"))
    assert set(staged) == _STAGED
    assert staged["stage"] == "config"
    assert staged["code"] == "document_invalid"
    usage = shared.plan_response(shared.IsolationRefusal("invalid_arguments"))
    assert usage["code"] == "invalid_arguments"
    assert shared.IsolationRefusal("invalid_arguments").exit_code == 2
    capability_body = shared.refusal("document_invalid")
    assert set(capability_body) == {"status", "code", "next_action"}
    assert "reason" not in capability_body and "stage" not in capability_body
    assert capability_body["code"] == "document_invalid"
    dropped = shared.IsolationRefusal("document_invalid", stage="stdout")
    assert dropped.stage is None and "stage" not in shared.plan_response(dropped)
    foreign = shared.IsolationRefusal("image_inspect", stage="image-inspection")
    assert foreign.stage is None and foreign.message == shared.REFUSALS["image_inspect"]
    joined = shared.IsolationRefusal("image_inspect", note="launcher_environment\nbad")
    assert joined.message == shared.REFUSALS["image_inspect"]
    assert "\n" not in shared.plan_text(shared.plan_response(joined))
    text = shared.plan_text(staged)
    assert text == "document_invalid — " + staged["reason"] + " (config)"
    assert text.count("\n") == 0


def test_launcher_environment_note_keeps_image_inspect_and_a_fixed_recovery():
    shared = importlib.import_module("aegis_core.team_isolation_refusal")
    error = shared.IsolationRefusal("image_inspect", note="launcher_environment")
    assert str(error) == error.code == error.reason == "image_inspect"
    assert error.exit_code == 1 and error.stage is None
    assert error.message == shared.LAUNCHER_ENVIRONMENT_REASON == "Retry from a clean launcher environment."
    assert error.next_action == {"actor": "operator", "command": error.message}
    body = shared.plan_response(error)
    assert set(body) == _UNSTAGED
    assert body["reason"] == error.message
    assert body["reason"] != shared.REFUSALS["image_inspect"]
    generic = shared.plan_response(shared.IsolationRefusal("image_inspect"))
    assert generic["reason"] == shared.REFUSALS["image_inspect"]
    assert "\n" not in shared.plan_text(body)
    assert shared.plan_text(body) == "image_inspect — " + error.message


def test_plan_projection_is_isolated_across_concurrent_callers():
    shared = importlib.import_module("aegis_core.team_isolation_refusal")

    def project(index):
        if index % 2:
            error = shared.IsolationRefusal("document_read", stage="container-inspection")
        else:
            error = shared.IsolationRefusal("image_inspect", note="launcher_environment")
        return shared.plan_response(error), shared.plan_text(shared.plan_response(error))

    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(project, range(8)))
    for index, (body, text) in enumerate(rows):
        if index % 2:
            assert body["stage"] == "container-inspection" and body["code"] == "document_read"
            assert text.endswith("(container-inspection)")
        else:
            assert "stage" not in body and body["reason"] == shared.LAUNCHER_ENVIRONMENT_REASON
            assert "container-inspection" not in text


@pytest.mark.parametrize(("code", "supplied_reason"), [
    ("document_invalid", "Supply a valid bounded JSON document."),
    ("document_size", "Reduce the isolation input to its documented size limits."),
])
def test_image_document_repair_advice_is_bound_to_stage(code, supplied_reason):
    shared = importlib.import_module("aegis_core.team_isolation_refusal")
    image_reason = "Check local engine inspection for the configured image and retry."
    stages = (None, "config", "container-inspection", "image-inspection")
    barrier = Barrier(len(stages), timeout=10)

    def project(stage):
        barrier.wait()
        error = shared.with_document_stage(shared.IsolationRefusal(code), stage)
        body = shared.plan_response(error)
        reason, wrong_reason = ((image_reason, supplied_reason) if stage == "image-inspection"
                                else (supplied_reason, image_reason))
        expected = {"status": "refused", "code": code, "reason": reason,
                    "next_action": {"actor": "operator", "command": reason}}
        suffix = ""
        if stage is not None:
            expected["stage"] = stage
            suffix = " (" + stage + ")"
        assert error.exit_code == 1 and str(error) == code
        assert body == expected
        assert shared.plan_text(body) == code + " — " + reason + suffix
        assert shared.plan_text(dict(body, reason=wrong_reason)) == (
            "internal — Report an internal isolation check failure.")

    with ThreadPoolExecutor(max_workers=len(stages)) as pool:
        list(pool.map(project, stages))


@pytest.mark.parametrize(("code", "stage", "note", "expected_stage"), [
    ("document_read", "container-inspection", "launcher_environment", "container-inspection"),
    ("image_inspect", "image-inspection", "launcher_environment", None),
    ("image_inspect", None, ["launcher_environment"], None),
    ("untrusted-code", "config", "launcher_environment", None),
], ids=["document", "launcher", "malformed-note", "unknown-code"])
def test_plan_projection_derives_public_fields_for_typed_subclasses(code, stage, note, expected_stage):
    shared = importlib.import_module("aegis_core.team_isolation_refusal")

    class ReaderRefusal(shared.IsolationRefusal):
        status = "untrusted-status"

    error = ReaderRefusal("internal")
    error.code, error.stage, error.note = code, stage, note
    error.message = "untrusted\nmessage"
    error.next_action = {"actor": "untrusted", "command": "untrusted"}
    registered = code if code in shared.REFUSALS else "internal"
    reason = (shared.LAUNCHER_ENVIRONMENT_REASON if code == "image_inspect" and note == "launcher_environment"
              else shared.REFUSALS[registered])
    expected = {"status": "refused", "code": registered, "reason": reason,
                "next_action": {"actor": "operator", "command": reason}}
    if expected_stage is not None:
        expected["stage"] = expected_stage
    assert shared.plan_response(error) == expected


@pytest.mark.parametrize("edits", [
    {"stage": "unknown-stage"},
    {"stage": "image-inspection"},
    {"stage": None},
    {"reason": "untrusted reason"},
    {"reason": "untrusted\u2028reason"},
    {"code": "untrusted-code"},
], ids=["unknown-stage", "engine-stage", "null-stage", "unknown-reason", "multiline", "unknown-code"])
def test_plan_text_refuses_invalid_mapping(edits):
    shared = importlib.import_module("aegis_core.team_isolation_refusal")
    body = shared.plan_response(shared.IsolationRefusal("image_inspect"))
    assert shared.plan_text(dict(body, **edits)) == "internal — " + shared.REFUSALS["internal"]
