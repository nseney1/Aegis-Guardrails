"""Workspace display and fixed refusal envelopes never echo hostile diagnostics."""
import pytest

from aegis_core import team_workspace_display as display
from tools import hierarchy_workspace_display as legacy


@pytest.mark.parametrize("raw", ["plain/path.py", "req-00000001", "bad\nvalue", "bad\x1b[31m",
                                  "password=hunter2", "ghp_" + "a" * 30, "x" * 100000,
                                  b"\xff", "\ud800"],
                         ids=["path", "request", "newline", "escape", "assignment", "token", "large",
                              "bytes", "surrogate"])
def test_raw_value_screening_preserves_legacy_decisions(raw):
    assert display.display(raw) == legacy._display(raw)


def test_fixed_refusal_ignores_untrusted_diagnostic():
    secret = "password=hunter2\n" + "x" * 10000
    @display.refusals
    def fail():
        raise ValueError(secret)
    with pytest.raises(display.WorkspaceRefusal) as error:
        fail()
    result = error.value.as_dict()
    assert result["reason"] == "invalid_record"
    assert result["code"] == 1
    assert result["next_action"]
    assert "hunter2" not in str(result)
    assert "\n" not in str(error.value)


def test_refusal_display_retains_next_action_and_screens_raw_fields():
    raw = "password=hunter2\n" + "x" * 10000
    result = display.display_refusal(display.WorkspaceRefusal("unsafe_path"),
                                     diagnostics={"path": raw, "error": raw})
    assert result["next_action"]
    assert result["reason"] == "unsafe_path"
    assert "hunter2" not in str(result)
    assert len(result["diagnostics"]["path"]) < 256


@pytest.mark.parametrize("raw", ["password=hunter2\n", "x" * 10000], ids=["controls", "oversized"])
def test_nonerror_refusal_response_screens_every_field_and_key(raw):
    """Accepted delta: unknown fields, keys and token-shaped ids are screened."""
    payload = {"reason": "initiative is paused", "arbitrary": raw,
               "initiative": "ghp_" + "a" * 30, raw: "value"}
    @legacy._display_response
    def old_response(value):
        return 3, value
    @display.display_response
    def response(value):
        return 3, value
    before = dict(payload)
    old_code, old_result = old_response(payload)
    code, result = response(payload)
    assert code == old_code == 3
    assert old_result["arbitrary"] == raw
    assert raw in old_result
    assert old_result["initiative"] == payload["initiative"]
    assert result["reason"] == "initiative is paused"
    assert "hunter2" not in str(result)
    assert "ghp_" + "a" * 30 not in str(result)
    assert raw not in result
    assert result["arbitrary"] == legacy._display(raw)
    assert payload == before
    clean = {"reason": "initiative is paused", "arbitrary": "ordinary/path", "initiative": "alpha"}
    assert response(clean) == old_response(clean) == (3, clean)


def credential_positions(depth):
    """Generate every branch and key position across each admitted container."""
    yield "password=hunter2"
    if depth:
        for child in credential_positions(depth - 1):
            yield {"ordinary": child}
            yield [child, "ordinary"]
            yield ["ordinary", child]
            yield (child, "ordinary")
            yield ("ordinary", child)
        yield {"password=hunter2": "ordinary"}


@pytest.mark.parametrize("payload", list(credential_positions(3)))
def test_generated_credential_positions_are_screened(payload):
    @display.display_response
    def response(value):
        return 3, value
    before = repr(payload)
    code, result = response(payload)
    assert code == 3
    assert "hunter2" not in repr(result)
    assert "redacted" in repr(result)
    assert repr(payload) == before
    assert response(("ordinary/path",)) == (3, ("ordinary/path",))


@pytest.mark.parametrize("oversized", ["requests", "kinds"])
def test_queue_report_bounds_before_projection_and_valid_retry(oversized):
    from aegis_core.team_mailbox_primitives import MAX_RECORDS
    requests = {str(index): {"kind": "other"} for index in range(MAX_RECORDS + 1)} if oversized == "requests" else {}
    kinds = ["writer"] * (MAX_RECORDS + 1) if oversized == "kinds" else ["writer"]
    with pytest.raises(display.WorkspaceRefusal) as error:
        display.queue_facts(requests, "2026-11-17T14:00:00Z", kinds=kinds)
    assert error.value.reason == "too_large" and error.value.code == 1 and error.value.next_action
    assert display.queue_facts({}, "2026-11-17T14:00:00Z", kinds=["writer"])["writer"]["queued"] == 0
