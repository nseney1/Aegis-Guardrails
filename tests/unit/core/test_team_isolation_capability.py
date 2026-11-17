"""Isolation capability report: document boundary, injected tables, tools parity.

The tools module is a read-only oracle for this file. Product code must not import it.
"""
import ast
import copy
import json
import signal
from collections.abc import Mapping
from pathlib import Path
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from aegis_core.diagnostic_messages import receipt_value
from aegis_core import team_isolation_capability as cap


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
import hierarchy_capability_check as tools_check  # noqa: E402
import hierarchy_roles as tools_roles  # noqa: E402


REGISTRY = json.loads((ROOT / "tools/hierarchy_templates/role-registry.json").read_text(encoding="utf-8"))["roles"]
MCP = ["mcp:fixture/status", "mcp:fixture/read"]
CALL_TOOLS = {name: ["mcp:forbidden/" + name.replace(":", "_")] for name in tools_roles.VOCABULARY["calls"]}
FILE_MAP = {name: "read" for name in tools_roles.READ_TOOLS}
FILE_MAP.update({name: "write-scope" for name in tools_roles.WRITE_TOOLS})
HOSTS = {
    "claude-code": {"file_tools": dict(FILE_MAP), "reader_shell": False, "writer_shell": False,
                    "session_helpers": False},
    "codex-cli": {"file_tools": dict(FILE_MAP), "reader_shell": True, "writer_shell": True,
                  "session_helpers": False},
}
VOCAB = {
    "reads": set(tools_roles.VOCABULARY["reads"]),
    "writes": set(tools_roles.VOCABULARY["writes"]),
    "calls": set(tools_roles.VOCABULARY["calls"]),
    "approvals": set(tools_roles.VOCABULARY["approvals"]),
    "assistants": set(tools_roles.ASSISTANTS),
    "endpoint_roles": set(tools_roles.ENDPOINT_ROLES),
    "lane_kinds": set(tools_roles.LANE_KINDS),
    "kinds": set(tools_roles.KINDS),
    "m1_uses": set(tools_roles.M1_USE),
    "independence_rules": set(tools_roles.INDEPENDENCE),
    "lifecycle_roles": set(tools_roles.LIFECYCLE_ROLES),
    "adapters": {"mailbox", "decision"},
    "profile_sources": {"team", "fixed", "none"},
    "lifecycle_tools": set(tools_roles.LIFECYCLE_TOOLS),
    "decision_tools": set(tools_roles.DECISION_READ_TOOLS),
    "decision_reads": {name: set(needed) for name, needed in tools_roles.DECISION_TOOL_READS.items()},
    "read_tools": list(tools_roles.READ_TOOLS),
    "write_tools": list(tools_roles.WRITE_TOOLS),
}


def document(entry, host="claude-code", mcp=None, calls=None, file_tools=None, **extra):
    payload = {
        "v": 1,
        "entry": entry,
        "host": host,
        "mcp_tools": list(MCP if mcp is None else mcp),
        "prohibited_call_tools": CALL_TOOLS if calls is None else calls,
        "file_tools": file_tools,
    }
    payload.update(extra)
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def report(raw, vocabulary=VOCAB, hosts=HOSTS):
    return cap.capability_report(raw, vocabulary=vocabulary, hosts=hosts)


def _boom(*_args, **_kwargs):
    raise AssertionError("untrusted input was decoded or parsed")


class _CountingSeq(list):
    """len() lies. Each yield is one observed entry."""

    def __init__(self, count):
        self.count = count
        self.trips = 0

    def __len__(self):
        return 1

    def __iter__(self):
        for _index in range(self.count):
            self.trips += 1
            yield "read"


class _LyingMap(Mapping):
    """len() matches the vocabulary. The iterator would not stop on its own."""

    def __init__(self, claimed):
        self.claimed = claimed
        self.trips = 0
        self.reads = 0

    def __len__(self):
        return self.claimed

    def __iter__(self):
        for _index in range(cap.MAX_ITEMS * 4):
            self.trips += 1
            yield "reads"
        raise AssertionError("unbounded mapping iterator")

    def __getitem__(self, _key):
        self.reads += 1
        raise AssertionError("mapping value was walked")


class _WideMap(Mapping):
    """len() hides a table wider than MAX_ITEMS."""

    def __init__(self, count):
        self.count = count
        self.trips = 0
        self.reads = 0

    def __len__(self):
        return 1

    def __iter__(self):
        for index in range(self.count):
            self.trips += 1
            yield "claude-code" if index == 0 else "h%d" % index

    def __getitem__(self, _key):
        self.reads += 1
        return "x"


class _MeasuredTable(Mapping):
    """One in-limit key whose value exceeds the document byte limit."""

    def __init__(self, key):
        self.key = key
        self.reads = 0

    def __len__(self):
        return 1

    def __iter__(self):
        yield self.key

    def __getitem__(self, _key):
        self.reads += 1
        return "v" * (cap.MAX_DOCUMENT_BYTES + 1)


class _WalkedValue(Mapping):
    """A value whose iteration is visible. Unknown keys must not reach it."""

    def __init__(self):
        self.trips = 0

    def __len__(self):
        return 1

    def __iter__(self):
        self.trips += 1
        yield "child"

    def __getitem__(self, _key):
        self.trips += 1
        return "x"


class _CountEncode(str):
    """Counts encode() so an oversized string cannot allocate its UTF-8 form."""

    encodes = 0

    def encode(self, *args, **kwargs):
        type(self).encodes += 1
        return str.encode(self, *args, **kwargs)


class _FlipList(list):
    """First iteration is the reader shape. Every later iteration is the writer shape."""

    def __init__(self, reader, writer):
        self.shapes = (list(reader), list(writer))
        self.walks = 0

    def __iter__(self):
        shape = self.shapes[0 if self.walks == 0 else 1]
        self.walks += 1
        return iter(shape)

    def __len__(self):
        return len(self.shapes[0 if self.walks == 0 else 1])


class _FlipMap(dict):
    """First iteration is the reader shape. Later iteration and lookup are the writer shape."""

    def __init__(self, reader, writer):
        self.shapes = (dict(reader), dict(writer))
        self.walks = 0

    def __iter__(self):
        shape = self.shapes[0 if self.walks == 0 else 1]
        self.walks += 1
        return iter(shape)

    def __getitem__(self, key):
        shape = self.shapes[0 if self.walks <= 1 else 1]
        return shape[key]

    def __len__(self):
        return len(self.shapes[0 if self.walks == 0 else 1])


def _shared_tower():
    node = []
    for _level in range(7):
        node = [node] * 256
    return node


def _within_one_second(function):
    """Stop a runaway walk. Windows has no SIGALRM; the fixed walk returns immediately."""
    if not hasattr(signal, "setitimer"):
        return function()

    def handler(_signum, _frame):
        raise TimeoutError("shared table walk did not stop")

    previous = signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, 1.0)
    try:
        return function()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _same_document(name, host):
    entry = REGISTRY[name]
    raw = document(entry, host)
    expected = tools_check.resolved_capabilities(entry, HOSTS[host], MCP, CALL_TOOLS)
    assert expected["status"] == "resolved"
    assert report(raw) == expected


@pytest.mark.parametrize("name", ["reviewer", "implementer", "decider"])
@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
def test_report_parity_covers_reader_and_writer_hosts(name, host):
    _same_document(name, host)


def test_narrowed_file_tools_match_the_tools_result():
    entry = REGISTRY["implementer"]
    selected = ["Read", "Edit"]
    raw = document(entry, "codex-cli", file_tools=selected)
    expected = tools_check.resolved_capabilities(
        entry, HOSTS["codex-cli"], MCP, CALL_TOOLS, file_tools=selected)
    assert report(raw) == expected


def test_compare_probe_and_verdict_match_tools_on_success():
    entry = REGISTRY["implementer"]
    resolved = tools_check.resolved_capabilities(entry, HOSTS["codex-cli"], MCP, CALL_TOOLS)
    assert cap.compare(resolved, resolved["capabilities"], CALL_TOOLS, vocabulary=VOCAB) == tools_check.compare(
        resolved, resolved["capabilities"], CALL_TOOLS)
    kwargs = dict(entry=entry, resolved=resolved, host_capabilities=HOSTS["codex-cli"], mcp_tools=MCP,
                  prohibited_call_tools=CALL_TOOLS, prohibited_tool="subagent",
                  prohibited_mcp="mcp:forbidden/merge", write_roots=["/probe/lanes/a"],
                  outside_path="/probe/outside/write", edit_path="/probe/outside/existing-edit-canary",
                  canary_path="/probe/outside/canary", sibling_path="/probe/lanes/ab/file")
    planned = cap.probe_plan(**kwargs, vocabulary=VOCAB)
    assert planned == tools_check.probe_plan(**kwargs)
    observations = [dict(attempt, outcome="refused") for attempt in planned["attempts"]]
    verdict_kwargs = dict(entry=entry, resolved=resolved, roots=["/probe/lanes/a"], plan=planned,
                          observations=observations, host_capabilities=HOSTS["codex-cli"], mcp_tools=MCP,
                          prohibited_call_tools=CALL_TOOLS)
    assert cap.probe_verdict(**verdict_kwargs, vocabulary=VOCAB) == tools_check.probe_verdict(**verdict_kwargs)


def test_unknown_field_is_a_typed_refusal_without_echo():
    raw = document(REGISTRY["reviewer"], unexpected_field="echo-unknown-field")
    result = report(raw)
    assert result["status"] == "refused"
    assert result["code"] == "unknown_field"
    assert result["next_action"]["command"] == cap.REFUSALS["unknown_field"]
    assert "echo-unknown-field" not in json.dumps(result)


def test_unknown_role_is_a_typed_refusal_without_echo():
    entry = copy.deepcopy(REGISTRY["reviewer"])
    entry["endpoint"] = {"role": "not-a-role"}
    result = report(document(entry))
    assert result["status"] == "refused"
    assert result["code"] == "unknown_role"
    assert result["next_action"]["actor"] == "operator"
    assert result["next_action"]["command"] == cap.REFUSALS["unknown_role"]
    assert "not-a-role" not in json.dumps(result)


def test_endpoint_without_a_role_object_is_refused():
    result = report(document(REGISTRY["test-author"]))
    assert result["code"] == "unknown_role"
    assert "test-author" not in json.dumps(result)


def _helpers_host():
    helpers = copy.deepcopy(HOSTS["claude-code"])
    helpers["session_helpers"] = True
    return helpers


@pytest.mark.parametrize("lane_kind", ["reviewer", "echo-unknown-lane"])
def test_non_lane_endpoint_with_a_lane_kind_is_refused(lane_kind):
    helpers = _helpers_host()
    hosts = {"claude-code": helpers}
    entry = REGISTRY["orchestrator"]
    expected = tools_check.resolved_capabilities(entry, helpers, MCP, CALL_TOOLS)
    assert "subagent" in expected["capabilities"]
    assert report(document(entry), hosts=hosts) == expected
    mutated = copy.deepcopy(entry)
    mutated["endpoint"] = {"role": "orchestrator", "lane_kind": lane_kind}
    result = report(document(mutated), hosts=hosts)
    assert result["status"] == "refused"
    assert result["code"] == "unknown_role"
    assert lane_kind not in json.dumps(result)


def test_lane_endpoint_without_lane_kind_is_refused():
    entry = copy.deepcopy(REGISTRY["reviewer"])
    entry["endpoint"] = {"role": "lane"}
    result = report(document(entry))
    assert result["status"] == "refused"
    assert result["code"] == "unknown_role"
    assert "lane_kind" not in json.dumps(result)


def test_null_lane_kind_is_refused_by_resolution_and_probe():
    helpers = _helpers_host()
    hosts = {"claude-code": helpers}
    entry = copy.deepcopy(REGISTRY["reviewer"])
    entry["endpoint"] = {"role": "lane", "lane_kind": None}
    result = report(document(entry), hosts=hosts)
    assert result["status"] == "refused"
    assert result["code"] == "unknown_role"
    assert "subagent" not in json.dumps(result)
    resolved = cap.resolved_capabilities(entry, helpers, MCP, CALL_TOOLS, vocabulary=VOCAB)
    assert resolved["code"] == "unknown_role"
    assert "subagent" not in json.dumps(resolved)
    good = REGISTRY["reviewer"]
    good_resolved = cap.resolved_capabilities(good, helpers, MCP, CALL_TOOLS, vocabulary=VOCAB)
    assert good_resolved["status"] == "resolved"
    probe_kwargs = dict(
        host_capabilities=helpers, mcp_tools=MCP, prohibited_call_tools=CALL_TOOLS,
        prohibited_tool="subagent", prohibited_mcp="mcp:forbidden/merge",
        write_roots=["/probe/lanes/a"], outside_path="/probe/outside/write",
        edit_path="/probe/outside/existing-edit-canary", canary_path="/probe/outside/canary",
        sibling_path="/probe/lanes/ab/file", vocabulary=VOCAB)
    planned = cap.probe_plan(entry=entry, resolved=good_resolved, **probe_kwargs)
    assert planned["status"] == "refused"
    assert planned["code"] == "invalid_probe_plan"
    assert "subagent" not in json.dumps(planned)
    good_plan = cap.probe_plan(entry=good, resolved=good_resolved, **probe_kwargs)
    assert good_plan["status"] == "planned"
    verdict = cap.probe_verdict(
        entry=entry, resolved=good_resolved, roots=["/probe/lanes/a"], plan=good_plan,
        observations=[], host_capabilities=helpers, mcp_tools=MCP,
        prohibited_call_tools=CALL_TOOLS, vocabulary=VOCAB)
    assert verdict["code"] == "invalid_probe_plan"


def _insert(entry, path, key, value):
    body = copy.deepcopy(entry)
    cursor = body
    for part in path:
        cursor = cursor[part]
    cursor[key] = value
    return body


@pytest.mark.parametrize("path,key", [
    ((), "echo-entry-field"),
    (("prohibitions",), "echo-prohibition-field"),
    (("provision",), "echo-provision-field"),
    (("endpoint",), "echo-endpoint-field"),
    (("independence",), "echo-independence-field"),
    (("model_profile",), "echo-profile-field"),
])
def test_unknown_nested_field_is_a_typed_refusal_without_echo(path, key):
    entry = _insert(REGISTRY["orchestrator"], path, key, "echo-nested-value")
    if path == ("prohibitions",):
        entry["prohibitions"].pop("approvals")
    result = report(document(entry))
    assert result["status"] == "refused"
    assert result["code"] == "unknown_field"
    blob = json.dumps(result)
    assert key not in blob
    assert "echo-nested-value" not in blob


@pytest.mark.parametrize("group", ["approvals", "prohibitions"])
def test_unknown_approval_is_refused_without_echo(group):
    entry = copy.deepcopy(REGISTRY["root"])
    if group == "approvals":
        entry["approvals"] = ["echo-unknown-approval"]
    else:
        entry["prohibitions"]["approvals"] = ["echo-unknown-approval"]
    result = report(document(entry))
    assert result["status"] == "refused"
    assert result["code"] == "unknown_role"
    assert "echo-unknown-approval" not in json.dumps(result)


def test_decision_adapter_cannot_carry_a_banned_write():
    entry = copy.deepcopy(REGISTRY["root"])
    entry["writes"] = ["mailbox"]
    entry["prohibitions"]["writes"] = [
        name for name in entry["prohibitions"]["writes"] if name != "mailbox"]
    result = report(document(entry))
    assert result["code"] == "unknown_role"
    assert "mailbox" not in json.dumps(result)


def test_lifecycle_tool_binding_is_refused():
    entry = copy.deepcopy(REGISTRY["decider"])
    entry["provision"]["lifecycle_tools"] = ["router_status"]
    result = report(document(entry))
    assert result["code"] == "unknown_role"
    assert "router_status" not in json.dumps(result)


def test_nested_object_inside_an_action_list_is_refused():
    entry = copy.deepcopy(REGISTRY["orchestrator"])
    entry["reads"] = [{"echo-nested-object": True}]
    result = report(document(entry))
    assert result["code"] == "unknown_role"
    assert "echo-nested-object" not in json.dumps(result)


def test_fixed_profile_optional_keys_may_be_absent():
    entry = copy.deepcopy(REGISTRY["router"])
    entry["model_profile"] = {"source": "fixed"}
    expected = tools_check.resolved_capabilities(REGISTRY["router"], HOSTS["claude-code"], MCP, CALL_TOOLS)
    assert report(document(entry)) == expected


def test_nested_unknown_field_retry_then_success_has_no_sticky_state():
    mutated = _insert(REGISTRY["reviewer"], ("provision",), "echo-provision-field", True)
    refused = report(document(mutated))
    assert refused["code"] == "unknown_field"
    assert "echo-provision-field" not in json.dumps(refused)
    entry = REGISTRY["reviewer"]
    assert report(document(entry)) == tools_check.resolved_capabilities(
        entry, HOSTS["claude-code"], MCP, CALL_TOOLS)


def test_concurrent_schema_checks_match_and_do_not_mutate_tables():
    vocab = copy.deepcopy(VOCAB)
    hosts = copy.deepcopy(HOSTS)
    good = document(REGISTRY["reviewer"])
    expected = tools_check.resolved_capabilities(REGISTRY["reviewer"], hosts["claude-code"], MCP, CALL_TOOLS)
    bad_entry = copy.deepcopy(REGISTRY["orchestrator"])
    bad_entry["endpoint"] = {"role": "orchestrator", "lane_kind": "echo-unknown-lane"}
    bad = document(bad_entry)

    def once(index):
        raw = good if index % 2 == 0 else bad
        return cap.capability_report(raw, vocabulary=vocab, hosts=hosts)

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(once, range(8)))
    assert results[0::2] == [expected] * 4
    assert [item["code"] for item in results[1::2]] == ["unknown_role"] * 4
    assert vocab == VOCAB
    assert hosts == HOSTS


@pytest.mark.parametrize("name", sorted(name for name, entry in REGISTRY.items() if entry["endpoint"] is not None))
@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
def test_every_endpoint_entry_matches_the_tools_oracle(name, host):
    _same_document(name, host)


@pytest.mark.parametrize("name", sorted(name for name, entry in REGISTRY.items() if entry["endpoint"] is None))
def test_an_entry_without_an_endpoint_is_refused(name):
    result = report(document(REGISTRY[name]))
    assert result["code"] == "unknown_role"
    oracle = tools_check.resolved_capabilities(REGISTRY[name], HOSTS["claude-code"], MCP, CALL_TOOLS)
    assert oracle["status"] == "unknown"


@pytest.mark.parametrize("vocabulary, hosts, code", [
    (None, HOSTS, "missing_vocabulary"),
    (VOCAB, None, "missing_host_table"),
    (None, None, "missing_vocabulary"),
])
def test_missing_injected_table_is_a_typed_refusal(vocabulary, hosts, code, monkeypatch):
    monkeypatch.setattr(cap, "_decode_utf8", _boom)
    monkeypatch.setattr(cap, "json_preflight", _boom)
    monkeypatch.setattr(cap, "strict_loads", _boom)
    result = report(b"{}", vocabulary=vocabulary, hosts=hosts)
    assert result["status"] == "refused"
    assert result["code"] == code
    assert result["next_action"]["command"] == cap.REFUSALS[code]


def test_oversized_bytes_are_refused_before_decode(monkeypatch):
    monkeypatch.setattr(cap, "_decode_utf8", _boom)
    monkeypatch.setattr(cap, "json_preflight", _boom)
    monkeypatch.setattr(cap, "strict_loads", _boom)
    raw = b"x" * (cap.MAX_DOCUMENT_BYTES + 1)
    result = report(raw)
    assert result["code"] == "oversized"
    assert result["status"] == "refused"
    assert "xxxx" not in result["next_action"]["command"]


def test_oversized_text_is_refused_before_parse(monkeypatch):
    monkeypatch.setattr(cap, "json_preflight", _boom)
    monkeypatch.setattr(cap, "strict_loads", _boom)
    result = report("{" + ("x" * cap.MAX_DOCUMENT_BYTES))
    assert result["code"] == "oversized"


def _just_under_multibyte_document():
    """JSON array of multi-byte strings whose UTF-8 form fits the byte ceiling."""
    mark = "\u00e9"
    parts = []
    size = 2
    while len(parts) < cap.MAX_ITEMS:
        comma = 1 if parts else 0
        room = cap.MAX_DOCUMENT_BYTES - size - comma - 2
        chars = min(cap.MAX_STRING, room // 2)
        if chars <= 0:
            break
        parts.append('"' + (mark * chars) + '"')
        size += comma + 2 + chars * 2
    return "[" + ",".join(parts) + "]"


def test_multibyte_text_over_the_byte_ceiling_is_oversized(monkeypatch):
    monkeypatch.setattr(cap, "_decode_utf8", _boom)
    monkeypatch.setattr(cap, "json_preflight", _boom)
    monkeypatch.setattr(cap, "strict_loads", _boom)
    text = '"' + ("\u00e9" * (cap.MAX_DOCUMENT_BYTES // 2)) + '"'
    assert len(text) == (cap.MAX_DOCUMENT_BYTES // 2) + 2
    raw = text.encode("utf-8")
    assert len(raw) == cap.MAX_DOCUMENT_BYTES + 2
    result = report(text)
    assert result["status"] == "refused"
    assert result["code"] == "oversized"
    assert "\u00e9" not in json.dumps(result)
    result = report(raw)
    assert result["status"] == "refused"
    assert result["code"] == "oversized"
    assert "\u00e9" not in json.dumps(result)


def test_multibyte_document_just_under_the_byte_ceiling_parses(monkeypatch):
    seen = {"loads": 0}
    real_loads = cap.strict_loads

    def spy(text):
        seen["loads"] += 1
        return real_loads(text)

    monkeypatch.setattr(cap, "strict_loads", spy)
    text = _just_under_multibyte_document()
    raw = text.encode("utf-8")
    assert len(text) <= cap.MAX_DOCUMENT_BYTES
    assert len(raw) <= cap.MAX_DOCUMENT_BYTES
    assert len(raw) + 2 > cap.MAX_DOCUMENT_BYTES
    for payload in (text, raw):
        result = report(payload)
        assert result["status"] == "refused"
        assert result["code"] == "invalid_document"
        assert "\u00e9" not in json.dumps(result)
    assert seen["loads"] == 2


def test_non_utf8_is_refused_before_parse(monkeypatch):
    monkeypatch.setattr(cap, "json_preflight", _boom)
    monkeypatch.setattr(cap, "strict_loads", _boom)
    result = report(b"\xff\xfe not-utf8-echo")
    assert result["code"] == "invalid_encoding"
    assert result["status"] == "refused"
    encoded = json.dumps(result)
    assert "not-utf8-echo" not in encoded
    assert "\\xff" not in encoded


def test_duplicate_key_is_ambiguous_and_does_not_echo():
    raw = b'{"echo-duplicate-key": 1, "echo-duplicate-key": 2}'
    result = report(raw)
    assert result["code"] == "ambiguous"
    assert "echo-duplicate-key" not in json.dumps(result)


def test_malformed_json_does_not_echo_or_raise():
    result = report(b'{"v": echo-malformed-token}')
    assert result["code"] == "invalid_document"
    assert "echo-malformed-token" not in json.dumps(result)


def test_multiline_host_is_refused_and_not_joined():
    raw = document(REGISTRY["reviewer"], host="good\nbad")
    result = report(raw)
    assert result["status"] == "refused"
    blob = json.dumps(result)
    assert "good bad" not in blob
    assert "good\\nbad" not in blob
    assert "\n" not in result["next_action"]["command"]


def test_present_text_uses_the_shared_receipt_projection():
    secret = "AKIAIOSFODNN7EXAMPLE"
    samples = (
        "\x1bP" + secret,
        "\x1bP\x1b[31m" + secret,
        "note\x1b]0;title\x1b7" + secret,
        "\x1b]note\x1b[31m" + secret,
        "note\x1b]\x1bP" + secret,
        "note\x1b]0;title\x1bc" + secret,
        "note\x1b]0;title\x1b[31m" + secret,
        "note\x1b]0;title\x9b31m" + secret,
        "note\x1bN" + secret,
        "plain note",
    )
    for raw in samples:
        shown = cap.present_text(raw)
        assert shown == receipt_value(raw)
        assert secret not in shown
        assert "PAKIA" not in shown
    huge = "\r" * 10_000_000
    shown = cap.present_text(huge)
    assert shown == receipt_value(huge)
    assert len(shown) <= 120


def test_present_text_canonicalizes_then_redacts_then_truncates():
    secret = "AKIAIOSFODNN7EXAMPLE"
    raw = "note\n" + secret + ("Y" * 300)
    shown = cap.present_text(raw)
    assert shown == receipt_value(raw)
    assert "\n" not in shown
    assert secret not in shown
    assert "[REDACTED_AWS]" in shown
    assert len(shown) <= 120


def test_present_text_redacts_a_secret_split_by_a_control():
    secret = "AKIAIOSFODNN7EXAMPLE"
    samples = (
        "note\r" + secret,
        "note\x1b[31m" + secret,
        "note\x00" + secret,
        "note\x9b31m" + secret,
    )
    for raw in samples:
        shown = cap.present_text(raw)
        assert shown == receipt_value(raw)
        assert secret not in shown
        assert "[REDACTED_AWS]" in shown


def test_present_text_truncation_does_not_split_a_mask():
    secret = "AKIAIOSFODNN7EXAMPLE"
    near = ("x" * 110) + " " + secret
    shown = cap.present_text(near)
    assert shown == receipt_value(near)
    assert secret not in shown
    assert "[REDACTED_AWS]" in shown
    assert shown.index("[REDACTED_AWS]") + len("[REDACTED_AWS]") <= len(shown)
    clipped = ("x" * 190) + " " + secret
    shown = cap.present_text(clipped)
    assert shown == receipt_value(clipped)
    assert secret not in shown
    assert "AKIA" not in shown
    assert len(shown) <= 120


def test_present_text_redacts_the_canonical_text_before_truncation():
    secret = "AKIAIOSFODNN7EXAMPLE"
    raw = "note\r" + secret + ("Y" * 6000)
    shown = cap.present_text(raw)
    assert shown == receipt_value(raw)
    assert secret not in shown
    assert "[REDACTED_AWS]" in shown
    assert len(shown) <= 120


def test_present_text_does_not_slice_an_osc_title_before_the_key():
    secret = "AKIAIOSFODNN7EXAMPLE"
    raw = "\x1b]0;" + ("a" * 4080) + "\x07" + secret
    shown = cap.present_text(raw)
    assert shown == receipt_value(raw)
    assert secret not in shown
    assert "AKIAIOSFODN" not in shown
    assert "[REDACTED_AWS]" in shown
    assert len(shown) <= 120


def test_present_text_redacts_a_pem_block_after_a_terminated_osc():
    body = "MIIEpAIBAAKCAQEA0123456789abcdef"
    pem = "-----BEGIN " + "RSA PRIVATE KEY-----\n" + body + "\n-----END " + "RSA PRIVATE KEY-----"
    raw = "hdr\x1b]0;title\x1b\\" + pem
    shown = cap.present_text(raw)
    assert shown == receipt_value(raw)
    assert shown.startswith("hdr")
    assert "BEGIN RSA PRIVATE KEY" not in shown
    assert body not in shown
    assert "END RSA PRIVATE KEY" not in shown
    assert "[REDACTED_PEM]" in shown
    assert "\x1b" not in shown


def test_present_text_escape_classes_leave_no_fragment_before_the_key():
    secret = "AKIAIOSFODNN7EXAMPLE"
    escapes = ["\x1b[31m", "\x1b[0m", "\x1b]0;title\x07", "\x1b]0;title\x1b\\"]
    escapes += ["\x1bP$q\x07", "\x1bP$q\x1b\\"]
    escapes += ["\x1b" + char for char in "=><NOM78c"]
    for escape in escapes:
        raw = "note" + escape + secret
        shown = cap.present_text(raw)
        assert shown == receipt_value(raw)
        assert secret not in shown
        assert "[REDACTED_AWS]" in shown
        assert "\x1b" not in shown


def test_present_text_keeps_text_after_a_terminated_osc():
    raw = "\x1b]0;title\x1b\\Restore configuration"
    shown = cap.present_text(raw)
    assert shown == receipt_value(raw)
    assert "Restore configuration" in shown
    assert "title" not in shown
    assert "\x1b" not in shown


def test_present_text_drops_a_terminated_dcs_body():
    secret = "AKIAIOSFODNN7EXAMPLE"
    raw = "\x1bPq" + secret + "\x1b\\"
    shown = cap.present_text(raw)
    assert shown == receipt_value(raw)
    assert secret not in shown
    assert "q" + secret not in shown
    assert "\x1b" not in shown


def test_present_text_abandons_an_unterminated_string_at_newline_or_end():
    secret = "AKIAIOSFODNN7EXAMPLE"
    raw = "note\x1b]0;title\n" + secret
    at_newline = cap.present_text(raw)
    assert at_newline == receipt_value(raw)
    assert secret not in at_newline
    assert "[REDACTED_AWS]" in at_newline
    assert "\x1b" not in at_newline
    assert "title" in at_newline
    raw = "head\x1b]0;kept"
    at_end = cap.present_text(raw)
    assert at_end == receipt_value(raw)
    assert at_end.startswith("head")
    assert "kept" in at_end
    assert "\x1b" not in at_end


def test_oversized_vocabulary_is_refused_before_traversal():
    vocab = _LyingMap(10_000)
    result = report(b"{}", vocabulary=vocab, hosts=HOSTS)
    assert result["status"] == "refused"
    assert result["code"] == "invalid_table"
    assert vocab.trips <= cap.MAX_ITEMS + 1
    assert vocab.reads == 0


def test_oversized_host_table_is_refused_before_traversal():
    hosts = _WideMap(10_000)
    result = report(b"{}", vocabulary=VOCAB, hosts=hosts)
    assert result["status"] == "refused"
    assert result["code"] == "invalid_table"
    assert hosts.trips <= cap.MAX_ITEMS + 1
    assert hosts.reads == 0


def test_vocabulary_over_document_bytes_is_invalid_table():
    vocab = _MeasuredTable("reads")
    result = report(b"{}", vocabulary=vocab, hosts=HOSTS)
    assert result["code"] == "invalid_table"
    # The key set is not the vocabulary. Its value is not walked.
    assert vocab.reads == 0
    assert "v" * 32 not in json.dumps(result)


def test_unknown_vocabulary_key_is_refused_before_its_value_is_walked():
    vocab = dict(VOCAB)
    bomb = _WalkedValue()
    vocab["unexpected"] = bomb
    result = report(b"{}", vocabulary=vocab, hosts=HOSTS)
    assert result["code"] == "invalid_table"
    assert bomb.trips == 0


def test_shared_reference_tower_is_refused_within_the_node_budget():
    vocab = dict(VOCAB)
    vocab["reads"] = _shared_tower()
    result = _within_one_second(lambda: report(b"{}", vocabulary=vocab, hosts=HOSTS))
    assert result["code"] == "invalid_table"
    hosts = dict(HOSTS)
    hosts["unused-host"] = _shared_tower()
    result = _within_one_second(lambda: report(b"{}", vocabulary=VOCAB, hosts=hosts))
    assert result["code"] == "invalid_table"


def test_wide_shared_rows_are_refused_within_the_node_budget(monkeypatch):
    visits = {"n": 0}
    real = cap._snapshot

    def counting(value, work, depth, values=True):
        visits["n"] += 1
        return real(value, work, depth, values)

    monkeypatch.setattr(cap, "_snapshot", counting)
    hosts = dict(HOSTS)
    hosts["other"] = [[""] * 256] * 256
    result = report(document(REGISTRY["reviewer"]), vocabulary=VOCAB, hosts=hosts)
    assert result["code"] == "invalid_table"
    assert visits["n"] < 65_964


def test_huge_int_is_refused_by_a_bit_length_bound():
    hosts = dict(HOSTS)
    hosts["other"] = 1 << 10_000_000
    result = report(document(REGISTRY["reviewer"]), vocabulary=VOCAB, hosts=hosts)
    assert result["status"] == "refused"
    assert result["code"] == "invalid_table"


def test_small_host_int_stays_inside_the_table_budget():
    hosts = dict(HOSTS)
    hosts["other"] = 1
    result = report(document(REGISTRY["reviewer"]), vocabulary=VOCAB, hosts=hosts)
    assert result["status"] == "resolved"


def test_oversized_string_is_refused_before_encode():
    _CountEncode.encodes = 0
    hosts = dict(HOSTS)
    hosts["other"] = _CountEncode("\U0001f600" * cap.MAX_DOCUMENT_BYTES)
    result = report(document(REGISTRY["reviewer"]), vocabulary=VOCAB, hosts=hosts)
    assert result["code"] == "invalid_table"
    assert _CountEncode.encodes == 0


def test_host_table_over_document_bytes_is_invalid_table(monkeypatch):
    monkeypatch.setattr(cap, "_decode_utf8", _boom)
    monkeypatch.setattr(cap, "json_preflight", _boom)
    monkeypatch.setattr(cap, "strict_loads", _boom)
    hosts = _MeasuredTable("claude-code")
    result = report(b"{}", vocabulary=VOCAB, hosts=hosts)
    assert result["code"] == "invalid_table"
    assert hosts.reads >= 1
    assert "v" * 32 not in json.dumps(result)


def test_refusal_retry_then_success_has_no_sticky_state():
    refused = report(document(REGISTRY["reviewer"], unexpected=True))
    assert refused["code"] == "unknown_field"
    entry = REGISTRY["reviewer"]
    raw = document(entry)
    assert report(raw) == tools_check.resolved_capabilities(entry, HOSTS["claude-code"], MCP, CALL_TOOLS)


def test_concurrent_reports_match_and_do_not_mutate_tables():
    vocab = copy.deepcopy(VOCAB)
    hosts = copy.deepcopy(HOSTS)
    entry = REGISTRY["implementer"]
    raw = document(entry, "codex-cli")
    expected = tools_check.resolved_capabilities(entry, hosts["codex-cli"], MCP, CALL_TOOLS)

    def once(_index):
        return cap.capability_report(raw, vocabulary=vocab, hosts=hosts)

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(once, range(8)))
    assert results == [expected] * 8
    assert vocab == VOCAB
    assert hosts == HOSTS


def test_analysis_does_not_mutate_inputs_and_matches_tools_failures():
    entry = {"reads": ["source"] * 2, "writes": [], "prohibitions": {}, "provision": {}, "endpoint": {}}
    snapshot = copy.deepcopy(entry)
    mapping = {"merge": ["mcp:forbidden/merge"]}
    served = ["read", " read"]
    core = cap.resolved_capabilities(entry, HOSTS["claude-code"], ["mcp:fixture/status"], mapping, vocabulary=VOCAB)
    oracle = tools_check.resolved_capabilities(entry, HOSTS["claude-code"], ["mcp:fixture/status"], mapping)
    assert core["code"] == "unknown_role"
    assert core["status"] == "refused"
    assert oracle["code"] == "invalid_role"
    assert entry == snapshot
    compared = cap.compare({"status": "resolved", "capabilities": ["read"], "prohibited_calls": []},
                           served, {}, vocabulary=VOCAB)
    oracle_compare = tools_check.compare(
        {"status": "resolved", "capabilities": ["read"], "prohibited_calls": []}, served, {})
    assert compared["status"] == oracle_compare["status"] == "exceeds"
    assert compared["extras"] == oracle_compare["extras"] == [" read"]


def test_catalog_limits_precede_traversal():
    resolved = report(document(REGISTRY["reviewer"]))
    served = _CountingSeq(cap.MAX_ITEMS + 1)
    assert cap.compare(resolved, served, CALL_TOOLS, vocabulary=VOCAB)["code"] == "invalid_catalog"
    assert served.trips <= cap.MAX_ITEMS + 1
    values = _CountingSeq(cap.MAX_ITEMS + 1)
    assert cap.resolved_capabilities(
        REGISTRY["reviewer"], HOSTS["claude-code"], MCP, {"merge": values}, vocabulary=VOCAB
    )["code"] == "invalid_prohibited_call_tools"
    assert values.trips <= cap.MAX_ITEMS + 1


def test_lying_length_mapping_stops_on_observed_entries():
    vocab = _LyingMap(len(VOCAB))
    result = report(b"{}", vocabulary=vocab, hosts=HOSTS)
    assert result["code"] == "invalid_table"
    assert vocab.trips <= cap.MAX_ITEMS + 1
    assert vocab.reads == 0


def test_mapping_over_max_items_is_refused_from_observed_entries():
    hosts = _WideMap(cap.MAX_ITEMS + 3)
    result = report(b"{}", vocabulary=VOCAB, hosts=hosts)
    assert result["code"] == "invalid_table"
    assert hosts.trips <= cap.MAX_ITEMS + 1
    assert hosts.reads == 0


def test_compare_preserves_resolver_refusal_codes():
    served = ["read"]
    pairs = (
        ("invalid_host_mapping", report(document(REGISTRY["reviewer"]), hosts={"claude-code": {"reader_shell": False}})),
        ("invalid_mcp_tools", report(document(REGISTRY["reviewer"], mcp=["nope"]))),
        ("prohibited_capability", cap.resolved_capabilities(
            REGISTRY["reviewer"], HOSTS["claude-code"], MCP, dict(CALL_TOOLS, merge=["read"]), vocabulary=VOCAB)),
    )
    for code, envelope in pairs:
        assert envelope["code"] == code
        assert cap.compare(envelope, served, CALL_TOOLS, vocabulary=VOCAB)["code"] == code
    host = cap.resolved_capabilities(
        REGISTRY["reviewer"], {"reader_shell": False}, MCP, CALL_TOOLS, vocabulary=VOCAB)
    tools = cap.resolved_capabilities(
        REGISTRY["reviewer"], HOSTS["claude-code"], ["nope"], CALL_TOOLS, vocabulary=VOCAB)
    assert host["code"] == "invalid_host_mapping"
    assert tools["code"] == "invalid_mcp_tools"
    assert cap.compare(host, served, CALL_TOOLS, vocabulary=VOCAB)["code"] == "invalid_host_mapping"
    assert cap.compare(tools, served, CALL_TOOLS, vocabulary=VOCAB)["code"] == "invalid_mcp_tools"
    early = report(b"not-json")
    assert early["code"] == "invalid_document"
    assert "prohibited_calls" not in early
    assert cap.compare(early, served, vocabulary=VOCAB)["code"] == "invalid_document"


def test_unknown_host_and_bad_host_mapping_are_typed():
    assert report(document(REGISTRY["reviewer"], host="missing-host"))["code"] == "unknown_host"
    hosts = {"claude-code": {"reader_shell": False}}
    result = report(document(REGISTRY["reviewer"]), hosts=hosts)
    assert result["code"] == "invalid_host_mapping"
    assert "reader_shell" not in json.dumps(result["next_action"])


def _shifted_file_resolution():
    """Writer-shaped envelope a second file-tool walk would publish for a reviewer."""
    return {
        "status": "resolved", "code": "resolved",
        "capabilities": sorted(["write-scope", *MCP]),
        "file_tools": ["Edit"], "prohibited_calls": [], "uncovered_calls": [],
    }


def _reader_probe_kwargs():
    return dict(
        host_capabilities=HOSTS["claude-code"], mcp_tools=list(MCP), prohibited_call_tools=dict(CALL_TOOLS),
        prohibited_tool="subagent", prohibited_mcp="mcp:forbidden/merge",
        write_roots=["/probe/lanes/a"], outside_path="/probe/outside/write",
        edit_path="/probe/outside/existing-edit-canary", canary_path="/probe/outside/canary",
        sibling_path="/probe/lanes/ab/file", vocabulary=VOCAB)


def _reader_verdict_kwargs():
    body = _reader_probe_kwargs()
    return dict(
        host_capabilities=body["host_capabilities"], mcp_tools=body["mcp_tools"],
        prohibited_call_tools=body["prohibited_call_tools"], vocabulary=body["vocabulary"])


def _assert_no_unprobed_writer(result):
    if result.get("status") == "planned":
        assert any(item["id"] == "sibling-write" for item in result["attempts"])
        return
    assert result["status"] == "refused"
    assert result["code"] != "equal_catalog"


def test_compare_requires_a_mapping_when_the_resolution_succeeded():
    result = cap.compare(
        {"status": "resolved", "capabilities": ["read"], "prohibited_calls": []},
        ["read"], vocabulary=VOCAB)
    assert result["status"] == "refused"
    assert result["code"] == "invalid_prohibited_call_tools"
    assert result["status"] != "match"


def test_public_boundaries_keep_the_first_snapshot():
    reader = copy.deepcopy(REGISTRY["reviewer"])
    writer = copy.deepcopy(reader)
    writer["writes"] = list(reader["writes"]) + ["source"]
    writer["prohibitions"]["writes"] = [
        name for name in reader["prohibitions"]["writes"] if name != "source"]
    writer["provision"] = dict(reader["provision"], reader_shell=False)
    files = _FlipList(["Read"], ["Edit"])
    entry = _FlipMap(reader, writer)
    resolved = cap.resolved_capabilities(
        reader, HOSTS["claude-code"], list(MCP), dict(CALL_TOOLS), file_tools=files, vocabulary=VOCAB)
    assert files.walks == 1
    assert resolved["status"] == "resolved"
    assert resolved["file_tools"] == ["Read"]
    assert "write-scope" not in resolved["capabilities"]
    plain = cap.resolved_capabilities(
        reader, HOSTS["claude-code"], list(MCP), dict(CALL_TOOLS), vocabulary=VOCAB)
    shifted_entry = cap.resolved_capabilities(
        entry, HOSTS["claude-code"], list(MCP), dict(CALL_TOOLS), vocabulary=VOCAB)
    assert entry.walks == 1
    assert shifted_entry == plain
    assert "write-scope" not in shifted_entry["capabilities"]

    served = _FlipList(list(plain["capabilities"]), list(plain["capabilities"]) + ["write-scope"])
    flipped_resolved = _FlipMap(plain, dict(plain, capabilities=list(plain["capabilities"]) + ["write-scope"]))
    compared = cap.compare(flipped_resolved, served, dict(CALL_TOOLS), vocabulary=VOCAB)
    assert compared["status"] == "match"
    assert served.walks == 1
    assert flipped_resolved.walks == 1

    document_flip = _FlipList(["Read"], ["Edit"])
    refused = report(document_flip)
    assert refused["status"] == "refused"
    assert document_flip.walks <= 1
    reader_hosts = copy.deepcopy(HOSTS)
    writer_hosts = copy.deepcopy(HOSTS)
    writer_hosts["claude-code"] = dict(writer_hosts["claude-code"], reader_shell=True, writer_shell=True)
    hosts = _FlipMap(reader_hosts, writer_hosts)
    reported = report(document(reader), hosts=hosts)
    assert hosts.walks == 1
    assert reported["status"] == "resolved"
    assert "shell" not in reported["capabilities"]
    assert "write-scope" not in reported["capabilities"]

    buggy = _shifted_file_resolution()
    shifted_files = _FlipList(["Read"], ["Edit"])
    planned = cap.probe_plan(entry=reader, resolved=buggy, file_tools=shifted_files, **_reader_probe_kwargs())
    _assert_no_unprobed_writer(planned)
    assert shifted_files.walks == 1
    reader_resolved = cap.resolved_capabilities(
        reader, HOSTS["claude-code"], list(MCP), dict(CALL_TOOLS), file_tools=["Read"], vocabulary=VOCAB)
    reader_plan = cap.probe_plan(entry=reader, resolved=reader_resolved, file_tools=["Read"], **_reader_probe_kwargs())
    assert reader_plan["status"] == "planned"
    observations = [dict(attempt, outcome="refused") for attempt in reader_plan["attempts"]]
    verdict_files = _FlipList(["Read"], ["Edit"])
    verdict = cap.probe_verdict(
        entry=reader, resolved=buggy, roots=["/probe/lanes/a"], plan=reader_plan,
        observations=observations, file_tools=verdict_files, **_reader_verdict_kwargs())
    assert verdict["status"] == "refused"
    assert verdict_files.walks == 1
    entry_plan = _FlipMap(reader, writer)
    planned_entry = cap.probe_plan(entry=entry_plan, resolved=plain, **_reader_probe_kwargs())
    assert entry_plan.walks == 1
    assert planned_entry["status"] == "planned"
    assert all(item["id"] != "sibling-write" for item in planned_entry["attempts"])


def test_core_source_has_no_tools_import_subprocess_or_write_open():
    source = Path(cap.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
    assert not any(name.startswith("tools") or "hierarchy_" in name for name in imported)
    assert "subprocess" not in imported
    text = source
    assert "os.open" not in text
    assert ".claude" not in text and ".codex" not in text
    assert "/usr/bin/python3" not in text
