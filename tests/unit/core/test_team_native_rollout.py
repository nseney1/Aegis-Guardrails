"""Native observations retain legacy data, never execution authority."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import errno
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import symlink_or_skip
from aegis_core import team_mailbox_primitives as mailbox_primitives
from aegis_core import team_native_rollout as core
from aegis_core.team_mailbox_primitives import MailboxRefusal, strict_json
from tools import hierarchy_native as legacy


ROOT = Path(__file__).resolve().parents[3]
CID = "11111111-1111-7111-8111-111111111111"
WORK = str(Path("/fixture/work").absolute())


@pytest.fixture
def make_store(tmp_path):
    if not core.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    selected = tmp_path / "selected"
    selected.mkdir(mode=0o700)
    return selected


def context(**changes):
    value = {"model": "model", "effort": "ultra", "cwd": WORK,
             "approval_policy": "on-request", "approvals_reviewer": "auto_review",
             "permission_profile": {"type": "managed", "network": "restricted",
                                    "file_system": {"type": "restricted", "entries": [
                                        {"path": {"type": "special", "value": {"kind": "root"}}, "access": "read"},
                                        {"path": {"type": "path", "path": WORK}, "access": "write"}]}}}
    value.update(changes)
    return {"type": "turn_context", "payload": value}


def event(kind, **values):
    return {"type": "event_msg", "payload": {"type": kind, **values}}


def write_rollout(directory, rows=None):
    path = directory / "rollout.jsonl"
    if rows is None:
        rows = [{"type": "session_meta", "payload": {"id": CID, "source": "exec"}}, context()]
    path.write_bytes(b"".join(json.dumps(row).encode() + b"\n" for row in rows))
    return path


def refused(reason, function, *args, **kwargs):
    with pytest.raises(core.NativeRolloutRefusal) as caught:
        function(*args, **kwargs)
    error = caught.value
    assert error.reason == reason
    assert error.code == 2
    assert error.state == "NATIVE_HOLD"
    assert error.next_action
    assert error.as_dict() == {"state": "NATIVE_HOLD", "status": "refused", "code": 2,
                               "reason": reason, "next_action": error.next_action}
    assert "private-marker" not in str(error) + repr(error.as_dict())


def records(path, **kwargs):
    return list(core.rollout_records(path, **kwargs))


def test_inspect_profile_and_roles_match_legacy_without_qualification(make_store):
    path = write_rollout(make_store)
    observed = core.inspect_codex(path, CID)
    assert observed == legacy.inspect_codex(path, CID)
    assert core.codex_roles() == legacy.codex_roles()
    assert not observed["identity_authenticated"]
    assert not observed["tool_allowlist_verified"]
    assert not observed["native_execution_qualified"]
    for role in core.codex_roles():
        actual = core.assess_role(observed, role)
        expected = legacy.assess_role(observed, role)
        assert {key: value for key, value in actual.items() if key != "next_action"} == expected
        assert actual["next_action"]
    for requested in (("model", "ultra", WORK), (None, None, WORK), ("other", "low", WORK)):
        actual = core.check_profile(observed, *requested)
        expected = legacy.check_profile(observed, *requested)
        assert {key: value for key, value in actual.items() if key != "next_action"} == expected
    assert core.assess_role(observed, "implementer", qualification_gate=lambda: True)["state"] == "NATIVE_HOLD"


@pytest.mark.parametrize("tail", [
    [event("thread_settings_applied", thread_settings={"service_tier": "ultrafast"}),
     event("task_started", turn_id="a"), context(turn_id="a")],
    [event("task_started", turn_id="a"), context(turn_id="a"),
     event("thread_settings_applied", turn_id="a", thread_settings={"service_tier": "default"}),
     event("thread_settings_applied", thread_settings={"service_tier": "ultrafast"}),
     event("task_started", turn_id="b"), context(turn_id="b")],
    [event("task_started", turn_id="a"), context(turn_id="a", service_tier="default"),
     event("task_complete"), event("thread_settings_applied", turn_id="b", thread_settings={}),
     event("task_started", turn_id="b"), context(turn_id="b")],
    [event("thread_settings_applied", thread_settings={}), context()],
])
def test_turn_and_settings_order_parity(make_store, tail):
    path = write_rollout(make_store, [{"type": "session_meta", "payload": {"id": CID}}, *tail])
    assert core.inspect_codex(path, CID) == legacy.inspect_codex(path, CID)


@pytest.mark.parametrize("tail", [
    [event("task_started", turn_id="resumed")],
    [event("task_started", turn_id="resumed"), context(turn_id="old")],
    [event("task_started")],
    [{"type": "session_meta", "payload": {"id": "private-marker"}}],
    [event("thread_settings_applied", thread_settings=[])],
])
def test_invalid_order_identity_and_settings_refuse_and_retry(make_store, tail):
    path = write_rollout(make_store)
    with path.open("ab") as stream:
        for row in tail:
            stream.write(json.dumps(row).encode() + b"\n")
    before = path.read_bytes()
    with pytest.raises(ValueError):
        legacy.inspect_codex(path, CID)
    refused("invalid_record", core.inspect_codex, path, CID)
    assert path.read_bytes() == before
    assert core.inspect_codex(write_rollout(make_store), CID)["cid"] == CID


@pytest.mark.parametrize("raw", [b"{private-marker}\n", b"[]\n", b'{"a":1,"a":2}\n',
                                   b'{"a":NaN}\n', b'{"a":"\xff"}\n'])
def test_malformed_refusals_are_fixed_and_leave_bytes_unchanged(make_store, raw):
    path = make_store / "rollout.jsonl"
    path.write_bytes(raw)
    refused("invalid_record", records, path)
    assert path.read_bytes() == raw
    path.write_bytes(b"{}\n")
    assert records(path)[0][3] == {}


def test_tolerant_tail_matches_legacy_and_does_not_hide_malformed_middle(make_store):
    path = make_store / "rollout.jsonl"
    path.write_bytes(b'{}\n{"still":')
    assert records(path, tolerant=True) == list(legacy.rollout_records(path, True))
    refused("incomplete_record", records, path)
    path.write_bytes(b'{private-marker}\n{"still":')
    refused("invalid_record", records, path, tolerant=True)


def test_byte_budget_extension_keeps_default_unchanged():
    raw = json.dumps({"payload": "x" * 262144})
    assert strict_json(raw, limit=core.MAX_RECORD_BYTES) == legacy.strict_json(raw)
    default_over = b'"' + b"x" * 262143 + b'"'
    assert len(default_over) == 262145
    with pytest.raises(MailboxRefusal, match="^mailbox refused: too_large$"):
        strict_json(default_over)


@pytest.mark.parametrize("limit", [None, "private-marker", True, -1, 1.5])
def test_new_byte_budget_requires_a_nonnegative_integer(limit):
    with pytest.raises(MailboxRefusal, match="^mailbox refused: invalid_record$"):
        strict_json(b"{}", limit=limit)


@pytest.mark.parametrize("payload", [[None] * 10001, 2**64,
                                     json.loads("[" * 34 + "null" + "]" * 34),
                                     [[None] * 9000 for _ in range(4)]],
                         ids=["items", "integer", "depth", "nodes"])
def test_recorded_structure_exceptions_are_typed_and_retryable(make_store, payload):
    path = write_rollout(make_store, [{"type": "response_item", "payload": payload}])
    assert len(list(legacy.rollout_records(path))) == 1
    refused("invalid_record", records, path)
    assert records(write_rollout(make_store))[0][3]["type"] == "session_meta"


def test_262144_character_probe_matches_legacy_reader(make_store):
    path = write_rollout(make_store, [{"type": "response_item", "payload": {"text": "x" * 262144}}])
    assert records(path) == list(legacy.rollout_records(path))


def full_record(size):
    prefix, suffix = b'{"payload":"', b'"}\n'
    return prefix + b"x" * (size - len(prefix) - len(suffix)) + suffix


def test_exact_16_mib_record_and_one_byte_over(make_store):
    assert core.MAX_RECORD_BYTES == 16 * 1024 * 1024
    path = make_store / "rollout.jsonl"
    raw = full_record(core.MAX_RECORD_BYTES)
    path.write_bytes(raw)
    assert records(path) == list(legacy.rollout_records(path))
    path.write_bytes(raw[:-1] + b" \n")
    refused("too_large", records, path)


def test_128_mib_total_boundary_and_one_byte_over(make_store):
    assert core.MAX_ROLLOUT_BYTES == 128 * 1024 * 1024
    path = make_store / "rollout.jsonl"
    raw = full_record(core.MAX_RECORD_BYTES)
    try:
        with path.open("wb") as stream:
            for _ in range(8):
                stream.write(raw)
        assert path.stat().st_size == core.MAX_ROLLOUT_BYTES
        assert sum(1 for _ in core.rollout_records(path)) == 8
        with path.open("ab") as stream:
            stream.write(b" ")
        refused("too_large", records, path)
    finally:
        path.unlink()


def test_limits_are_checked_before_parse_or_stream_allocation(make_store, monkeypatch):
    path = make_store / "rollout.jsonl"
    with path.open("wb") as stream:
        stream.truncate(core.MAX_ROLLOUT_BYTES + 1)
    def unexpected(*args, **kwargs):
        pytest.fail("oversized input reached allocation or parsing")
    monkeypatch.setattr(core, "strict_json", unexpected)
    monkeypatch.setattr(core, "os", SimpleNamespace(**{**vars(os), "fdopen": unexpected}))
    refused("too_large", records, path)


def test_growing_rollout_enforces_total_before_parsing_extra_record(make_store, monkeypatch):
    path = make_store / "rollout.jsonl"
    path.write_bytes(b"{}\n")
    monkeypatch.setattr(core, "MAX_ROLLOUT_BYTES", 6)
    original = strict_json
    parsed = []
    def append_while_reading(raw, **kwargs):
        parsed.append(raw)
        if len(parsed) == 1:
            with path.open("ab") as stream:
                stream.write(b"{}\n{}\n")
        return original(raw, **kwargs)
    monkeypatch.setattr(core, "strict_json", append_while_reading)
    refused("too_large", records, path)
    assert parsed == [b"{}\n", b"{}\n"]


def test_closing_partial_iterator_releases_leaf_descriptor(make_store, monkeypatch):
    path = write_rollout(make_store)
    opened = []
    original = os.open
    def track(name, flags, **kwargs):
        fd = original(name, flags, **kwargs)
        opened.append(fd)
        return fd
    monkeypatch.setattr(core, "os", SimpleNamespace(**{**vars(os), "open": track}))
    reader = core.rollout_records(path)
    next(reader)
    reader.close()
    assert opened
    for fd in opened:
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize("kind", ["missing", "directory", "hardlink", "fifo"])
def test_unreadable_or_nonregular_paths_have_fixed_refusals(make_store, kind):
    path = make_store / "rollout.jsonl"
    if kind == "directory":
        path.mkdir()
    elif kind == "hardlink":
        source = make_store / "source"
        source.write_bytes(b"{}\n")
        os.link(source, path)
    elif kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO support required")
        os.mkfifo(path)
    refused("missing" if kind == "missing" else "unsafe_path", records, path)


@pytest.mark.parametrize("fixture", sorted((ROOT / "tests/fixtures").rglob("*.jsonl")),
                         ids=lambda path: path.name)
def test_every_committed_rollout_fixture_matches_legacy(make_store, fixture):
    # Repository-owned fixtures are read plainly on every platform, then copied
    # to the private selected directory used by the hostile-path reader.
    path = make_store / "rollout.jsonl"
    path.write_bytes(fixture.read_bytes())
    assert records(path) == list(legacy.rollout_records(path))


def test_unsupported_platform_is_fixed_before_path_processing(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "descriptor_supported", lambda: False)
    refused("unsupported_platform", records, tmp_path / "private-marker")
    assert not (tmp_path / "private-marker").exists()


@pytest.mark.parametrize("component", ["leaf", "parent", "ancestor"])
def test_symlink_at_any_component_refuses(make_store, component):
    path = write_rollout(make_store)
    if component == "leaf":
        target = path.with_name("saved")
        path.rename(target)
        symlink_or_skip(target, path)
    else:
        folder = make_store if component == "parent" else make_store.parent
        target = folder.with_name(folder.name + "-saved")
        folder.rename(target)
    try:
        if component != "leaf":
            symlink_or_skip(target, folder, target_is_directory=True)
        refused("unsafe_path", records, path)
    finally:
        if component != "leaf":
            if folder.is_symlink():
                folder.unlink()
            target.rename(folder)


def test_ancestor_rename_after_anchor_cannot_redirect_read(make_store, monkeypatch):
    path = write_rollout(make_store)
    raw = path.read_bytes()
    moved = make_store.with_name("saved")
    original_open = os.open
    changed = []
    def swap(name, flags, **kwargs):
        if name == path.name and not changed:
            make_store.rename(moved)
            make_store.mkdir(mode=0o700)
            (make_store / path.name).write_bytes(b'{"private-marker":true}\n')
            changed.append(True)
        return original_open(name, flags, **kwargs)
    monkeypatch.setattr(core, "os", SimpleNamespace(**{**vars(os), "open": swap}))
    actual = records(path)
    assert b"".join(row[2] for row in actual) == raw
    assert changed == [True]


@pytest.mark.parametrize("failure", ["fdopen", "read"])
def test_descriptor_closed_when_stream_creation_or_read_fails(make_store, monkeypatch, failure):
    path = write_rollout(make_store)
    opened = []
    original_open = os.open
    def track(name, flags, **kwargs):
        fd = original_open(name, flags, **kwargs)
        opened.append(fd)
        return fd
    def broken(*args, **kwargs):
        raise OSError(errno.EIO, "private-marker")
    class BrokenStream:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        readline = broken
    monkeypatch.setattr(core, "os", SimpleNamespace(**{**vars(os), "open": track,
                        "fdopen": broken if failure == "fdopen" else lambda *a, **k: BrokenStream()}))
    refused("io", records, path)
    assert opened
    for fd in opened:
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == errno.EBADF
    monkeypatch.setattr(core, "os", os)
    assert core.inspect_codex(path, CID)["cid"] == CID


def test_readonly_parallel_inspection_has_no_shared_state(make_store):
    path = write_rollout(make_store)
    before = path.read_bytes()
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: core.inspect_codex(path, CID), range(9)))
    assert all(value == results[0] for value in results)
    assert path.read_bytes() == before
    assert sorted(p.name for p in make_store.iterdir()) == [path.name]


@pytest.mark.parametrize("helper,args", [
    ("event_type", (None,)), ("observed_permissions", (None,)),
    ("turn_start", ({"turn_id": []},)), ("bounded_write_path", (None,)),
    ("check_profile", ({}, "m", "e", WORK)), ("assess_role", ({}, [])),
    ("patch_apply", ({"status": []}, None, "file_change", {"line": 1})),
    ("command_execution", ({"command": [], "exit_code": True}, None, "source", {"line": 1})),
])
def test_malformed_public_inputs_have_typed_refusals(helper, args):
    refused("invalid_record", getattr(core, helper), *args)


def test_command_and_patch_helpers_match_legacy():
    witness = {"line": 1, "sha256": "a" * 64}
    cases = [
        ("command_execution", ({"command": ["echo", "a b"], "exit_code": 0}, "t", "exec_command_end", witness)),
        ("patch_apply", ({"success": False, "changes": {"src/a.py": {}}}, "t", "patch_apply_end", witness)),
        ("patch_apply", ({"status": "completed", "changes": [{"path": "src/a.py"}]}, "t", "file_change", witness)),
        ("patch_input", ({"type": "function_call", "arguments": '{"patch":"*** Add File: a.py"}'},)),
        ("patch_input", ({"arguments": "*** Update File: a.py"},)),
        ("patch_paths", ("*** Add File: a.py\n*** Update File: b.py",)),
        ("patch_output", ({"output": '{"output":"Success","metadata":{"exit_code":0}}'},)),
        ("response_patch", ({"type": "custom_tool_call", "input": "*** Add File: a.py"}, None, "t", witness)),
    ]
    for name, args in cases:
        assert getattr(core, name)(*deepcopy(args)) == getattr(legacy, name)(*deepcopy(args))


def test_profile_refusal_display_redacts_after_canonicalization(make_store):
    observed = core.inspect_codex(write_rollout(make_store), CID)
    observed["requested_tier"] = "def\rault sk-" + "A" * 40
    observed["served_tier"] = "ultrafast"
    shown = core.check_profile(observed, "model", "ultra", WORK)
    assert "sk-" + "A" * 40 not in repr(shown["reasons"])
    assert "\r" not in "".join(shown["reasons"])


def test_profile_path_diagnostics_keep_legacy_lexical_byte_budget():
    profile = context()["payload"]
    profile["permission_profile"]["file_system"]["entries"][1]["path"]["path"] = WORK + "/" + "x" * 40000
    observed = {"profile": profile, "requested_tier": "default", "served_tier": None}
    assert core.check_profile(observed, "model", "ultra", WORK) == legacy.check_profile(
        observed, "model", "ultra", WORK)


@pytest.mark.parametrize("payload", [None, [], {}, {"type": []}, {"type": ""}])
def test_legacy_event_tolerance_is_preserved(make_store, payload):
    path = write_rollout(make_store)
    with path.open("ab") as stream:
        stream.write(json.dumps({"type": "event_msg", "payload": payload}).encode() + b"\n")
    assert core.inspect_codex(path, CID) == legacy.inspect_codex(path, CID)
    assert core.inspect_codex(write_rollout(make_store), CID)["cid"] == CID


def nested_arrays(depth):
    value = None
    for _ in range(depth):
        value = [value]
    return value


@pytest.mark.parametrize("shape,offset", [(shape, offset) for shape in ("items", "depth", "nodes", "integer")
                                         for offset in (-1, 0, 1)])
@pytest.mark.parametrize("side", ["input", "output"])
def test_class_a_nested_parser_refusals_never_become_text(shape, offset, side):
    if shape == "items":
        padding = [None] * (10000 + offset)
    elif shape == "depth":
        padding = nested_arrays(31 + offset)  # including the wrapper: 31, 32, 33 containers
    elif shape == "nodes":
        padding = [[None] * count for count in (8190, 8190, 8190, 8189 + offset)]
    else:
        padding = (2**64 - 1) + offset
    field = "patch" if side == "input" else "output"
    value = {field: "*** Add File: x.py" if side == "input" else "Success", "padding": padding}
    raw = json.dumps(value)
    payload = {"type": "function_call", "arguments": raw} if side == "input" else {"output": raw}
    name = "patch_input" if side == "input" else "patch_output"
    expected = getattr(legacy, name)(payload)
    before = deepcopy(payload)
    if offset > 0:
        refused("invalid_record", getattr(core, name), payload)
        call = payload if side == "input" else {"type": "custom_tool_call", "input": "*** Add File: x.py"}
        output = {"output": "Success"} if side == "input" else payload
        refused("invalid_record", core.response_patch, call, output, "turn", {"line": 1})
    else:
        assert getattr(core, name)(payload) == expected
    assert payload == before
    assert core.patch_input({"type": "function_call", "arguments": '{"patch":"*** Add File: retry.py"}'}) == "*** Add File: retry.py"


@pytest.mark.parametrize("raw", ["*** Add File: x.py", "{", "[null,", '{"a":1,"a":2}',
                                  '{"a":NaN}', '{"a":Infinity}', '{"a":-Infinity}',
                                  '{"patch":"x","padding":[' + "null," * 10000],
                         ids=["plain", "open-object", "open-array", "duplicate", "nan",
                              "infinity", "negative-infinity", "oversized-incomplete"])
@pytest.mark.parametrize("name,key", [("patch_input", "arguments"), ("patch_output", "output")])
def test_class_a_non_json_fallback_keeps_legacy_acceptance(raw, name, key):
    payload = {"type": "function_call", key: raw}
    assert getattr(core, name)(payload) == getattr(legacy, name)(payload)


@pytest.mark.parametrize("width", [63, 64, 65, 1000])
def test_class_b_finite_numeric_atoms_keep_legacy_acceptance(make_store, width):
    raw = '{"number":1.' + "0" * (width - 2) + '}\n'
    path = make_store / "rollout.jsonl"
    path.write_text(raw)
    assert records(path) == list(legacy.rollout_records(path))
    arguments = raw[:-2] + ',"patch":"*** Add File: x.py"}'
    payload = {"type": "function_call", "arguments": arguments}
    assert core.patch_input(payload) == legacy.patch_input(payload)


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_class_b_raw_byte_ceiling_does_not_charge_float_expansion(make_store, offset):
    size = core.MAX_RECORD_BYTES + offset
    prefix, suffix = b'{"number":1e15,"text":"', b'"}\n'
    raw = prefix + b"x" * (size - len(prefix) - len(suffix)) + suffix
    path = make_store / "rollout.jsonl"
    path.write_bytes(raw)
    if offset > 0:
        with pytest.raises(ValueError, match="^rollout record exceeds observation byte limit$"):
            list(legacy.rollout_records(path))
        refused("too_large", records, path)
    else:
        assert records(path) == list(legacy.rollout_records(path))
        value = legacy.strict_json(raw)
        assert core.observed_permissions(value) == legacy.observed_permissions(value)


def test_class_b_mailbox_default_numeric_and_byte_charging_stays_unchanged():
    with pytest.raises(MailboxRefusal, match="^mailbox refused: invalid_record$"):
        strict_json('{"number":1.' + "0" * 63 + '}')
    prefix, suffix = b'{"number":1e15,"text":"', b'"}'
    raw = prefix + b"x" * (262144 - len(prefix) - len(suffix)) + suffix
    with pytest.raises(MailboxRefusal, match="^mailbox refused: too_large$"):
        strict_json(raw)


@pytest.mark.parametrize("field", ["type", "access"])
@pytest.mark.parametrize("value", [[], {}, ["path"], {"private-marker": True}, None, 0, True, "other"])
def test_class_c_container_permission_fields_are_typed_scalar_diagnostics_match(make_store, field, value):
    profile = context()["payload"]
    entry = profile["permission_profile"]["file_system"]["entries"][1]
    (entry["path"] if field == "type" else entry)[field] = value
    path = write_rollout(make_store, [{"type": "session_meta", "payload": {"id": CID}},
                                     {"type": "turn_context", "payload": profile}])
    if isinstance(value, (list, dict)):
        with pytest.raises(TypeError):
            legacy.observed_permissions(profile)
        refused("invalid_record", core.observed_permissions, profile)
        refused("invalid_record", core.inspect_codex, path, CID)
    else:
        assert core.observed_permissions(profile) == legacy.observed_permissions(profile)
        assert core.inspect_codex(path, CID) == legacy.inspect_codex(path, CID)
    assert core.inspect_codex(write_rollout(make_store), CID)["cid"] == CID


@pytest.mark.parametrize("dangling", [False, True])
def test_class_d_leaf_symlink_including_dangling_is_unsafe(make_store, dangling):
    target = make_store / "target.jsonl"
    if not dangling:
        target.write_bytes(b"{}\n")
    path = make_store / "rollout.jsonl"
    symlink_or_skip(target, path)
    with pytest.raises(ValueError, match="symlink paths are not supported"):
        list(legacy.rollout_records(path))
    refused("unsafe_path", records, path)


@pytest.mark.parametrize("number,reason", [(errno.ELOOP, "unsafe_path"), (errno.ENOTDIR, "unsafe_path"),
                                           (errno.EIO, "io")])
@pytest.mark.parametrize("phase", ["leaf", "probe"])
def test_class_d_leaf_open_errno_is_mapped_and_retryable(make_store, monkeypatch, number, reason, phase):
    path = write_rollout(make_store)
    original = os.open
    def fail_leaf(name, flags, **kwargs):
        if name == path.name:
            raise OSError(number, "private-marker")
        return original(name, flags, **kwargs)
    monkeypatch.setattr(core, "os", SimpleNamespace(**{**vars(os), "open": fail_leaf}))
    probe = core.descriptor_supported
    if phase == "probe":
        def fail_probe():
            raise OSError(number, "private-marker")
        monkeypatch.setattr(core, "descriptor_supported", fail_probe)
    refused(reason, records, path)
    monkeypatch.setattr(core, "os", os)
    monkeypatch.setattr(core, "descriptor_supported", probe)
    assert core.inspect_codex(path, CID)["cid"] == CID


@pytest.mark.parametrize("kind", [1, 0, None, "", False, [], {}])
def test_class_e_record_type_tolerance_matches_legacy(make_store, kind):
    path = write_rollout(make_store)
    with path.open("ab") as stream:
        stream.write(json.dumps({"type": kind}).encode() + b"\n")
    if isinstance(kind, (list, dict)):
        with pytest.raises(TypeError):
            legacy.inspect_codex(path, CID)
        refused("invalid_record", core.inspect_codex, path, CID)
    else:
        assert core.inspect_codex(path, CID) == legacy.inspect_codex(path, CID)


@pytest.mark.parametrize("served,requested", [(1, 1), (True, True), ([], []), ({}, {}),
                                              (1, 2), ([], {}), (None, 1), ("default", 1)])
def test_class_e_non_string_tiers_compare_normally_and_render_fixed_text(served, requested):
    observed = {"profile": context()["payload"], "served_tier": served, "requested_tier": requested}
    expected = legacy.check_profile(observed, "model", "ultra", WORK)
    actual = core.check_profile(observed, "model", "ultra", WORK)
    assert actual["state"] == expected["state"]
    assert actual["checks"] == expected["checks"]
    assert actual["native_execution_qualified"] is False
    assert actual["observation"] == expected["observation"]
    if actual["state"] == "PROFILE_HOLD":
        assert actual["next_action"]
        assert "<non-string tier>" in " ".join(actual["reasons"])
    else:
        assert actual == expected


@pytest.mark.parametrize("tier", [1, True, [], {}, None])
def test_class_e_requested_tier_argument_keeps_legacy_observation(make_store, tier):
    path = write_rollout(make_store)
    assert core.inspect_codex(path, CID, requested_tier=tier) == legacy.inspect_codex(
        path, CID, requested_tier=tier)


@pytest.mark.parametrize("count", [9999, 10000, 10001])
@pytest.mark.parametrize("side", ["input", "output"])
def test_class_a_exact_review_response_preserves_patch_and_exit_code(count, side):
    call = {"type": "function_call", "call_id": "call", "arguments": json.dumps({
        "patch": "*** Add File: x.py", **({"padding": [None] * count} if side == "input" else {})})}
    output = {"output": json.dumps({"output": "Success", "metadata": {"exit_code": 0},
                                    **({"padding": [None] * count} if side == "output" else {})})}
    expected = legacy.response_patch(call, output, "turn", {"line": 1})
    assert expected["paths"] == ["x.py"] and expected["success"] is True
    if count > 10000:
        refused("invalid_record", core.response_patch, call, output, "turn", {"line": 1})
    else:
        assert core.response_patch(call, output, "turn", {"line": 1}) == expected


def test_class_a_b_bound_refusal_and_numeric_options_are_independent_across_threads():
    too_many = {"type": "function_call", "arguments": json.dumps({
        "patch": "*** Add File: x.py", "padding": [None] * 10001})}
    long_number = '{"number":1.' + "0" * 80 + ',"patch":"*** Add File: retry.py"}'
    def check(_index):
        refused("invalid_record", core.patch_input, too_many)
        assert core.patch_input({"type": "function_call", "arguments": long_number}) == "*** Add File: retry.py"
        with pytest.raises(MailboxRefusal, match="^mailbox refused: invalid_record$"):
            strict_json(long_number)
        return strict_json(b"{}")
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(check, range(6))) == [{}] * 6


@pytest.mark.parametrize("options", [{"max_atom": None}, {"max_atom": True}, {"max_atom": 0},
                                    {"max_atom": -1}, {"max_atom": "private-marker"},
                                    {"source_bytes": None}, {"source_bytes": 0}],
                         ids=["none-atom", "bool-atom", "zero-atom", "negative-atom", "text-atom",
                              "none-source", "integer-source"])
def test_class_b_new_parser_options_have_fixed_type_refusals(options):
    with pytest.raises(MailboxRefusal, match="^mailbox refused: invalid_record$"):
        strict_json(b"{}", **options)


@pytest.mark.parametrize("token", ["1e307", "1e308", "1e309", "-1e309", '"\\ud800"'],
                         ids=["exponent-under", "exponent-edge", "exponent-over", "negative-over", "escaped-surrogate"])
def test_class_b_raw_json_values_keep_legacy_acceptance_without_changing_mailbox_defaults(make_store, token):
    raw = ('{"number":' + token + '}\n').encode()
    path = make_store / "rollout.jsonl"
    path.write_bytes(raw)
    expected = list(legacy.rollout_records(path))
    assert records(path) == expected
    assert core.observed_permissions(expected[0][3]) == legacy.observed_permissions(expected[0][3])
    if token in ("1e309", "-1e309", '"\\ud800"'):
        with pytest.raises(MailboxRefusal, match="^mailbox refused: invalid_record$"):
            strict_json(raw)


def test_round1d_surrogate_arguments_round_trip(make_store):
    payload = {"type": "function_call", "arguments": '{"patch":"*** Add File: \ud800.py"}'}
    path = write_rollout(make_store, [{"type": "response_item", "payload": payload}])
    actual = records(path)
    expected = list(legacy.rollout_records(path))
    assert actual == expected
    assert core.patch_input(actual[0][3]["payload"]) == legacy.patch_input(expected[0][3]["payload"]) == "*** Add File: \ud800.py"
    witness = core.witness_of(*actual[0])
    assert witness == legacy.witness_of(*expected[0])
    call = actual[0][3]["payload"]
    output = {"output": "Success"}
    assert core.response_patch(call, output, "turn", witness) == legacy.response_patch(call, output, "turn", witness)


def test_round1d_surrogate_output_round_trip(make_store):
    payload = {"output": '{"output":"Success \ud800","metadata":{"exit_code":7}}'}
    path = write_rollout(make_store, [{"type": "response_item", "payload": payload}])
    actual = records(path)
    expected = list(legacy.rollout_records(path))
    assert actual == expected
    assert core.patch_output(actual[0][3]["payload"]) == legacy.patch_output(expected[0][3]["payload"]) == ("Success \ud800", 7)
    call = {"type": "custom_tool_call", "input": "*** Add File: x.py"}
    witness = core.witness_of(*actual[0])
    output = actual[0][3]["payload"]
    assert core.response_patch(call, output, "turn", witness) == legacy.response_patch(call, output, "turn", witness)


JSON_EDGE_FORMS = [
    ("lone-high", r'"\ud800"'), ("lone-low", r'"\udfff"'),
    ("valid-pair", r'"\ud83d\ude00"'), ("reversed-pair", r'"\ude00\ud83d"'),
    ("nul", r'"\u0000"'), ("literal-non-bmp", '"\U0001f600"'),
    ("largest-finite", "1.7976931348623157e308"), ("smallest-finite", "-1.7976931348623157e308"),
    ("smallest-positive", "5e-324"), ("largest-integer", "18446744073709551615"),
    ("smallest-integer", "-18446744073709551615"), ("overflow-number", "1e309"),
    ("duplicate-key", '{"edge":1,"edge":2}'), ("nan", "NaN"),
    ("infinity", "Infinity"), ("negative-infinity", "-Infinity"), ("empty", '""'),
    ("depth-30", "[" * 30 + "null" + "]" * 30),
    ("depth-31", "[" * 31 + "null" + "]" * 31),
    ("legacy-depth-100", "[" * 100 + "null" + "]" * 100),
]


@pytest.mark.parametrize("case,token", JSON_EDGE_FORMS, ids=[row[0] for row in JSON_EDGE_FORMS])
@pytest.mark.parametrize("side", ["arguments", "output"])
@pytest.mark.parametrize("mode", ["direct", "embedded", "embedded-literal"])
def test_round1d_json_edge_forms_match_legacy(make_store, case, token, side, mode):
    if mode != "direct":
        if mode == "embedded-literal" and token.startswith('"'):
            token = json.dumps(json.loads(token), ensure_ascii=False)
        field = "patch" if side == "arguments" else "output"
        token = json.dumps('{"' + field + '":' + token + ',"metadata":{"exit_code":7}}')
    raw = ('{"type":"response_item","payload":{"type":"function_call","' + side + '":' + token + '}}\n').encode("utf-8")
    path = make_store / "rollout.jsonl"
    path.write_bytes(raw)
    if mode == "direct" and case in ("duplicate-key", "nan", "infinity", "negative-infinity"):
        with pytest.raises(ValueError, match="^malformed rollout JSON at line 1$"):
            list(legacy.rollout_records(path))
        refused("invalid_record", records, path)
    else:
        expected = list(legacy.rollout_records(path))
        bounded = case == "legacy-depth-100" or mode == "direct" and case == "depth-31"
        if bounded and mode == "direct":
            refused("invalid_record", records, path)
        else:
            actual = records(path)
            assert actual == expected
            name = "patch_input" if side == "arguments" else "patch_output"
            helper, old_helper = getattr(core, name), getattr(legacy, name)
            payload = actual[0][3]["payload"]
            before = deepcopy(payload)
            if bounded:
                old_helper(payload)
                refused("invalid_record", helper, payload)
            else:
                assert helper(payload) == old_helper(expected[0][3]["payload"])
            assert payload == before
    assert path.read_bytes() == raw
    path.write_bytes(b'{"payload":{"arguments":"*** Add File: retry.py","output":"Success"}}\n')
    retried = records(path)[0][3]["payload"]
    assert core.patch_input(retried) == "*** Add File: retry.py"
    assert core.patch_output(retried) == ("Success", None)


@pytest.mark.parametrize("raw", [b'"\\ud800"', '"\ud800"'], ids=["escaped-bytes", "literal-text"])
def test_round1d_mailbox_default_still_rejects_lone_surrogate(raw):
    with pytest.raises(MailboxRefusal, match="^mailbox refused: invalid_record$"):
        strict_json(raw)
    assert strict_json(b'"retry"') == "retry"


def test_round1d_surrogate_policy_is_independent_across_threads():
    payload = {"arguments": '{"patch":"\ud800"}', "output": '{"output":"\udfff","metadata":{"exit_code":7}}'}
    before = deepcopy(payload)
    def check(_index):
        with pytest.raises(MailboxRefusal, match="^mailbox refused: invalid_record$"):
            strict_json('"\ud800"')
        assert core.patch_input(payload) == legacy.patch_input(payload) == "\ud800"
        assert core.patch_output(payload) == legacy.patch_output(payload) == ("\udfff", 7)
        refused("invalid_record", core.patch_input, {"arguments": '{"padding":' + "[" * 40 + "null" + "]" * 40 + '}'})
        assert core.patch_input(payload) == "\ud800"
        return strict_json(b"{}")
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(check, range(6))) == [{}] * 6
    assert payload == before


def test_round1d_surrogate_diagnostics_use_existing_canonicalizer():
    observation = {"profile": context()["payload"], "served_tier": "\ud800 sk-" + "A" * 40,
                   "requested_tier": "default"}
    result = core.check_profile(observation, "model", "ultra", WORK)
    assert result["state"] == "PROFILE_HOLD"
    shown = " ".join(result["reasons"])
    assert "\ud800" not in shown and "sk-" + "A" * 40 not in shown
    shown.encode("utf-8")


@pytest.mark.parametrize("limit", [4, 5, 6])
def test_round1d_surrogate_source_bytes_bound_before_copy(limit, monkeypatch):
    raw = '"\ud800"'
    assert len(raw.encode("utf-8", "surrogatepass")) == 5
    if limit < 5:
        def unexpected(*args, **kwargs):
            pytest.fail("oversized source reached the preflight-copy allocation")
        monkeypatch.setattr(mailbox_primitives, "re", SimpleNamespace(sub=unexpected))
        with pytest.raises(MailboxRefusal, match="^mailbox refused: too_large$"):
            strict_json(raw, limit=limit, source_bytes=True)
    else:
        assert strict_json(raw, limit=limit, source_bytes=True) == "\ud800"


def test_round1d_preflight_substitution_never_changes_parsed_keys_or_syntax():
    raw = '{"patch":"\ud800","\ud800":1,"\ufffd":2}'
    assert strict_json(raw, source_bytes=True) == legacy.strict_json(raw)
    assert core.patch_input({"arguments": raw}) == "\ud800"
    for malformed in ('{"patch":"\\\ud800"}', '{\ud800:1}', '"\ud800\x00"'):
        with pytest.raises(ValueError):
            legacy.strict_json(malformed)
        with pytest.raises(MailboxRefusal, match="^mailbox refused: invalid_record$"):
            strict_json(malformed, source_bytes=True)
    # rollout_records decodes bytes strictly before the legacy JSON parser.
    malformed_bytes = b'"\xed\xa0\x80"'
    with pytest.raises(UnicodeDecodeError, match="invalid continuation byte"):
        legacy.strict_json(malformed_bytes.decode("utf-8"))
    with pytest.raises(MailboxRefusal, match="^mailbox refused: invalid_record$"):
        strict_json(malformed_bytes, source_bytes=True)


# Past every supported decoder ceiling: CPython 3.9's recursion limit and the
# 3.12 Windows C recursion limit both exhaust before this depth. The string is
# only brackets plus one marker, so the refusal must not echo it.
_EXHAUSTING_DEPTH = 10000


def _exhausting_value(shape):
    if shape == "array":
        return "[" * _EXHAUSTING_DEPTH + '"private-marker"' + "]" * _EXHAUSTING_DEPTH
    return '{"k":' * _EXHAUSTING_DEPTH + '"private-marker"' + "}" * _EXHAUSTING_DEPTH


def _retry_embedded(name, key):
    plain = {key: "*** Add File: retry.py\n" + ("[" * 400)}
    assert getattr(core, name)(plain) == getattr(legacy, name)(plain)
    syntax = {key: "[" * 80}
    assert getattr(core, name)(syntax) == getattr(legacy, name)(syntax)
    duplicate = {key: '{"edge":1,"edge":2}'}
    assert getattr(core, name)(duplicate) == getattr(legacy, name)(duplicate)
    nan = {key: '{"a":NaN}'}
    assert getattr(core, name)(nan) == getattr(legacy, name)(nan)
    if name == "patch_input":
        assert core.patch_input({"arguments": '{"patch":"*** Add File: retry.py"}'}) == "*** Add File: retry.py"
    else:
        assert core.patch_output({"output": '{"output":"Success","metadata":{"exit_code":7}}'}) == ("Success", 7)


@pytest.mark.parametrize("shape", ["array", "object"])
@pytest.mark.parametrize("name,key", [("patch_input", "arguments"), ("patch_output", "output")])
def test_decoder_exhaustion_keeps_the_bounded_refusal(shape, name, key):
    payload = {"type": "function_call", key: _exhausting_value(shape)}
    before = deepcopy(payload)
    refused("invalid_record", getattr(core, name), payload)
    assert payload == before
    _retry_embedded(name, key)


def test_decoder_exhaustion_response_patch_refuses_either_side():
    raw = _exhausting_value("array")
    call = {"type": "function_call", "call_id": "call", "arguments": raw}
    output = {"output": "Success"}
    witness = {"line": 1}
    before_call, before_output = deepcopy(call), deepcopy(output)
    refused("invalid_record", core.response_patch, call, output, "turn", witness)
    assert call == before_call and output == before_output
    plain_call = {"type": "function_call", "call_id": "call", "arguments": "*** Add File: retry.py"}
    plain_output = {"output": "Success"}
    retried = core.response_patch(plain_call, plain_output, "turn", witness)
    assert retried["paths"] == ["retry.py"] and retried["success"] is True
    deep_output = {"output": raw}
    before_deep = deepcopy(deep_output)
    refused("invalid_record", core.response_patch, plain_call, deep_output, "turn", witness)
    assert deep_output == before_deep
    assert core.response_patch(plain_call, plain_output, "turn", witness) == retried


def test_decoder_exhaustion_refusal_is_stable_across_threads():
    raw = _exhausting_value("object")
    def check(_index):
        refused("invalid_record", core.patch_input, {"arguments": raw})
        assert core.patch_input({"arguments": "*** Add File: retry.py"}) == "*** Add File: retry.py"
        refused("invalid_record", core.patch_output, {"output": raw})
        assert core.patch_output({"output": '{"output":"Success","metadata":{"exit_code":3}}'}) == ("Success", 3)
        syntax = {"arguments": "[" * 80, "output": '{"a":1,"a":2}'}
        assert core.patch_input(syntax) == legacy.patch_input(syntax)
        assert core.patch_output(syntax) == legacy.patch_output(syntax)
        return True
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(check, range(6))) == [True] * 6


# Syntax, duplicate keys, bad escapes and non-ASCII digits stay legacy text even
# when later brackets are deep. Only a decoder RecursionError keeps the refusal.
_MALFORMED_DEEP_LABELS = (
    "unclosed", "invalid-escape", "raw-newline", "short-u",
    "duplicate-keys", "unicode-digit", "raw-nul",
)


def _malformed_deep_text(label):
    deep = "[" * 300 + "null" + "]" * 300
    if label == "unclosed":
        return "[" * 257
    if label == "invalid-escape":
        return '{"a":"\\q","b":' + deep + "}"
    if label == "raw-newline":
        return '["line1\nline2",' + "[" * 256
    if label == "short-u":
        return '{"a":"\\u12","b":' + deep + "}"
    if label == "duplicate-keys":
        return '[{"a":1,"a":2},' + "[" * 256 + "]" * 257
    if label == "unicode-digit":
        return "[\u00b2," + "[" * 256
    if label == "raw-nul":
        return '{"a":"\x00","b":' + deep + "}"
    raise AssertionError(label)


def _assert_legacy_text(name, key, raw):
    payload = {"type": "function_call", key: raw}
    before = deepcopy(payload)
    assert getattr(core, name)(payload) == getattr(legacy, name)(payload)
    assert payload == before


@pytest.mark.parametrize("label", _MALFORMED_DEEP_LABELS)
@pytest.mark.parametrize("name,key", [("patch_input", "arguments"), ("patch_output", "output")])
def test_malformed_deep_text_matches_the_legacy_reader(label, name, key):
    raw = _malformed_deep_text(label)
    _assert_legacy_text(name, key, raw)
    _retry_embedded(name, key)


@pytest.mark.parametrize("label", _MALFORMED_DEEP_LABELS)
def test_malformed_deep_text_response_patch_keeps_both_sides(label):
    raw = _malformed_deep_text(label)
    witness = {"line": 1}
    call = {"type": "function_call", "call_id": "call", "arguments": raw}
    output = {"output": "Success"}
    before_call = deepcopy(call)
    observed = core.response_patch(call, output, "turn", witness)
    assert call == before_call
    assert observed["paths"] == [] and observed["success"] is True and observed["stderr"] == "Success"
    plain_call = {"type": "function_call", "call_id": "call", "arguments": "*** Add File: retry.py"}
    bad_output = {"output": raw}
    before_output = deepcopy(bad_output)
    observed = core.response_patch(plain_call, bad_output, "turn", witness)
    assert bad_output == before_output
    assert observed["paths"] == ["retry.py"] and observed["stderr"] == raw and observed["success"] is False
    both = core.response_patch(
        {"type": "function_call", "call_id": "call", "arguments": raw}, {"output": raw}, "turn", witness)
    assert both["paths"] == [] and both["stderr"] == raw and both["success"] is False
    retried = core.response_patch(plain_call, output, "turn", witness)
    assert retried["paths"] == ["retry.py"] and retried["success"] is True


def test_malformed_deep_text_is_stable_across_threads():
    samples = [_malformed_deep_text(label) for label in _MALFORMED_DEEP_LABELS]

    def check(_index):
        for raw in samples:
            _assert_legacy_text("patch_input", "arguments", raw)
            _assert_legacy_text("patch_output", "output", raw)
            call = {"type": "function_call", "call_id": "call", "arguments": raw}
            assert core.response_patch(call, {"output": "Success"}, "turn", {"line": 1})["success"] is True
        assert core.patch_input({"arguments": "*** Add File: retry.py"}) == "*** Add File: retry.py"
        assert core.patch_output({"output": '{"output":"Success","metadata":{"exit_code":3}}'}) == ("Success", 3)
        return True

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(check, range(6))) == [True] * 6
