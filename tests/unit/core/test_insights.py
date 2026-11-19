"""Unit tests for aegis_core.insights edge cases, security boundaries, and clustering."""
from __future__ import annotations

import ast
import errno
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import stat
import subprocess
import sys
from types import SimpleNamespace
import unicodedata

import pytest

from tests.conftest import symlink_or_skip
from tests.helpers_reviewed_sources import (
    census_guard, check_census_rows, run_census_fixture,
    GITFILE_MAX_BYTES, git as _git, git_environment as _git_environment, reviewed_python_paths,
    run_isolated_test as _run_isolated,
)

from aegis_core import insights as core_insights
from aegis_core.errors import PathTraversalError
from aegis_core.primitives import real_path
from aegis_core.gitsafe_policy import LOCAL_ENV
from aegis_core.insights import (
    KEY_SIZE,
    add_insight,
    capture_suggestion,
    create_link_key,
    dirty_paths,
    host_capture_status,
    insight_workspace_id,
    insights_path,
    measure_recurrence,
    read_insight_rows,
    read_link_key,
    record_decision,
    record_hook_prompt,
    review_insights,
    session_hs,
    write_proposal,
)

REPO = Path(real_path(__file__)).parents[3]
# Reviewed parse-cost ratchet with headroom for ordinary tracked source additions.
# Raising this ceiling requires review; failures list every parsed path.
INSIGHTS_PARSE_CEILING = 80


_ROUND8_INSIGHT_FIELDS = {
    "v": "identity", "ts": "identity", "event": "identity", "id": "identity",
    "level": "identity", "text": "text", "paths": "path", "psrc": "identity",
    "host": "text", "hs": "identity", "source": "identity", "kind": "text",
    "approval_code": "identity", "revs": "identity", "corroborated_by": "identity",
    "paths_dropped": "identity", "cue": "identity", "inv": "identity",
    "decision": "identity", "insight_ids": "identity", "reason": "text", "rule_id": "identity",
}


def test_round8_writer_field_inventory_contract():
    from dataclasses import field, fields, make_dataclass
    import inspect

    from aegis_core.insights import capture, review
    from aegis_core.proposals import model, store

    assert dict(capture.INSIGHT_FIELD_POLICIES) == _ROUND8_INSIGHT_FIELDS
    assert set(model.PROPOSAL_FIELD_POLICIES) == {item.name for item in fields(model.Proposal)} | {"count"}
    assert set(model.PROPOSAL_FIELD_POLICIES.values()) <= {"identity", "path", "text"}
    source = ast.parse(inspect.getsource(store._validate_row))
    required = next(node.value for node in source.body[0].body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "required" for target in node.targets))
    allowed = next(node.value for node in source.body[0].body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "allowed" for target in node.targets))
    assert set(model.PROPOSAL_DECISION_FIELD_POLICIES) == ast.literal_eval(required) | ast.literal_eval(allowed.right)
    writers, literal_fields = set(), set()
    for module in (capture, review):
        tree = ast.parse(inspect.getsource(module))
        for function in (node for node in tree.body if isinstance(node, ast.FunctionDef)):
            nodes = list(ast.walk(function))
            if any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                   and node.func.id == "_append_user_insights" for node in nodes):
                writers.add(function.name)
                assert any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                           and node.func.id == "clean_insight_row" for node in nodes), function.name
            if function.name in {"_build_insight_row", "record_hook_prompt", "record_decision"}:
                for node in nodes:
                    if isinstance(node, ast.Dict):
                        literal_fields.update(key.value for key in node.keys
                                              if isinstance(key, ast.Constant) and isinstance(key.value, str))
                    if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store):
                        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                            literal_fields.add(node.slice.value)
    assert writers == {"add_insight", "capture_suggestion", "record_hook_prompt", "record_decision"}
    assert literal_fields <= set(capture.INSIGHT_FIELD_POLICIES)
    expanded = make_dataclass("UnclassifiedProposal", [("unclassified", str, field(default="opaque"))],
                              bases=(model.Proposal,), frozen=True)
    with pytest.raises(model.ProposalError) as refusal:
        expanded(id="trap-safe", source="one", kind="correctness", candidate_key="one:safe")
    assert refusal.value.code == "invalid"


@pytest.mark.parametrize("name,policy", _ROUND8_INSIGHT_FIELDS.items())
@pytest.mark.parametrize("control", ["\r", "\x85", "\x1b[31m"], ids=["cr", "nel", "csi"])
def test_round8_each_insight_field_has_a_secret_safe_policy(tmp_path, name, policy, control):
    from aegis_core.insights import capture
    from aegis_core.redaction import RedactionRefusal

    workspace = tmp_path / "ws"
    workspace.mkdir()
    value = "AK" + "IA" + control + "B" * 16
    supplied = ([value] if name in {"paths", "insight_ids"} else
                {value: "0" * 16} if name == "revs" else value)
    if policy == "text":
        shown = capture.clean_insight_row({name: supplied}, workspace=workspace)
        assert "BBBB" not in shown[name] and "[REDACTED" in shown[name]
    elif policy == "path":
        with pytest.raises(PathTraversalError, match="^invalid insight path$"):
            capture.clean_insight_row({name: supplied}, workspace=workspace)
    else:
        with pytest.raises(RedactionRefusal, match="^invalid$") as refusal:
            capture.clean_insight_row({name: supplied}, workspace=workspace)
        assert refusal.value.code == "invalid"


@pytest.mark.parametrize("control", ["\r", "\x85", "\x1b[31m"], ids=["cr", "nel", "csi"])
def test_round8_public_writers_refuse_identities_paths_and_redact_hosts(tmp_path, control):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.redaction import RedactionRefusal

    workspace, home = tmp_path / "ws", tmp_path / "home"
    workspace.mkdir()
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")
    (workspace / ".aegis/rules/traps").mkdir(parents=True)
    _put_rule(workspace, "trap-safe")
    secret = "AK" + "IA" + control + "B" * 16
    for argument in ({"insight_ids": [secret]}, {"insight_ids": ["ins-" + "a" * 12], "rule_id": secret}):
        with pytest.raises(RedactionRefusal, match="^invalid$"):
            record_decision(workspace, decision="confirm", home=home, **argument)
    for write in (add_insight, capture_suggestion):
        with pytest.raises(PathTraversalError, match="^invalid insight path$"):
            write(workspace, "Ordinary note.", paths=[secret], home=home)

    def write(index):
        captured = capture_suggestion(workspace, "Ordinary capture.", paths=["app.py"],
                                      host=secret, home=home)
        beat = record_hook_prompt(secret, {"prompt": "ordinary", "session_id": "session"},
                                  workspace=workspace, home=home)
        prompt = record_hook_prompt(secret, {"prompt": "Never repeat that mistake.", "session_id": "session"},
                                    workspace=workspace, home=home)
        assert all("BBBB" not in row["host"] for row in (captured, beat, prompt))
        row = add_insight(workspace, "Ordinary correction.", paths=["app.py"], home=home)
        decision = record_decision(workspace, decision="confirm", insight_ids=[row["id"]], home=home)
        assert decision["insight_ids"] == [row["id"]]

    write(0)
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(write, range(3)))
    stored = read_insight_rows(workspace, home=home)
    assert {row["event"] for row in stored} >= {"insight", "heartbeat", "decision", "inventory"}
    assert all("BBBB" not in json.dumps(row) for row in stored)


def test_round8_unknown_writer_field_refuses_before_append_then_recovers(tmp_path, monkeypatch):
    from aegis_core.insights import capture
    from aegis_core.redaction import RedactionRefusal

    workspace, home = tmp_path / "ws", tmp_path / "home"
    workspace.mkdir()
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")
    original = capture._build_insight_row

    def extended(*args, **kwargs):
        return dict(original(*args, **kwargs), unclassified="AK" + "IA" + "B" * 16)

    monkeypatch.setattr("aegis_core.insights.capture._build_insight_row", extended)
    for _ in range(2):
        with pytest.raises(RedactionRefusal, match="^invalid$"):
            add_insight(workspace, "Ordinary note.", paths=["app.py"], home=home)
    assert read_insight_rows(workspace, home=home) == []
    monkeypatch.setattr("aegis_core.insights.capture._build_insight_row", original)
    row = add_insight(workspace, "Ordinary note.", paths=["app.py"], home=home)
    assert read_insight_rows(workspace, home=home)[0]["id"] == row["id"]


@pytest.mark.parametrize("control", ["\r", "\x85", "\x1b[31m"], ids=["cr", "nel", "csi"])
def test_round8_each_proposal_field_refuses_or_masks_credentials(control):
    from dataclasses import fields
    from aegis_core.proposals import model

    secret = "AK" + "IA" + control + "B" * 16
    base = dict(id="trap-safe", source="one", kind="correctness", candidate_key="one:safe")
    for item in fields(model.Proposal):
        if not item.init:
            continue  # Derived legacy flag, not an input field.
        value = (secret,) if isinstance(item.default, tuple) else secret
        try:
            proposal = model.Proposal(**dict(base, **{item.name: value}))
        except model.ProposalError as refusal:
            assert refusal.code in {"invalid", "ancestry"}, item.name
            assert "BBBB" not in str(refusal)
        else:
            assert "BBBB" not in proposal.to_bytes().decode("utf-8"), item.name


def test_round8_field_policies_bound_input_before_copy_and_recover(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.insights import capture
    from aegis_core.redaction import RedactionRefusal

    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")
    row = {"v": 1, "ts": "2026-11-18T18:00:00Z", "event": "insight", "id": "ins-" + "a" * 12,
           "level": "cli", "text": "Ordinary note.", "paths": ["app.py"], "psrc": "explicit",
           "host": "cli", "hs": "0" * 32, "source": "cli", "kind": "correctness",
           "approval_code": "unverifiable", "revs": {"trap-safe": "0" * 16},
           "corroborated_by": "ins-" + "b" * 12, "paths_dropped": 0, "cue": False,
           "inv": "0" * 16, "decision": "confirm", "insight_ids": ["ins-" + "a" * 12],
           "reason": "Ordinary reason.", "rule_id": "trap-safe"}
    assert set(row) == set(capture.INSIGHT_FIELD_POLICIES)
    for bad in (None, {"unclassified": "opaque"}, {"text": 3}, {"text": "bad\ud800"},
                {"insight_ids": None}):
        with pytest.raises(RedactionRefusal, match="^invalid$"):
            capture.clean_insight_row(bad, workspace=workspace)
    with pytest.raises(RedactionRefusal, match="^too_large$"):
        capture.clean_insight_row({"paths": ["app.py"] * (capture.MAX_INSIGHT_ITEMS + 1)}, workspace=object())
    with pytest.raises(RedactionRefusal, match="^too_large$"):
        capture.clean_insight_row({"insight_ids": ["ins-" + "a" * 12] * (capture.MAX_INSIGHT_ITEMS + 1)}, workspace=object())
    for bad_path in ("bad\ud800", "../AK" + "IA" + "B" * 16):
        with pytest.raises(PathTraversalError, match="^invalid insight path$"):
            capture.clean_insight_row({"paths": [bad_path]}, workspace=workspace)

    def clean(_index):
        assert capture.clean_insight_row(row, workspace=workspace) == row
        return capture.clean_insight_row(row, workspace=workspace)

    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(clean, range(6))) == [row] * 6


@pytest.mark.parametrize("control", ["\r", "\x85", "\x1b[31m"], ids=["cr", "nel", "csi"])
def test_round8_each_proposal_decision_field_refuses_credentials_then_recovers(tmp_path, control):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.proposals import model
    from tests.unit.core.test_proposals_store import make_store

    store = make_store(tmp_path)
    proposal = model.Proposal(id="trap-safe", source="one", kind="correctness", candidate_key="one:safe")
    store.write(proposal)
    row = store.decide([proposal.id], decision="noise", operation_id="op-safe")
    path, = (store.root / ".aegis/proposals/decisions").glob("*.json")
    original = path.read_bytes()
    secret = "AK" + "IA" + control + "B" * 16
    for name in model.PROPOSAL_DECISION_FIELD_POLICIES:
        value = ([secret] if name in {"proposal_ids", "evidence_ids", "insight_ids"} else
                 {secret: 1} if name == "revisions" else secret)
        changed = dict(row, **{name: value})
        path.write_text(json.dumps(changed), encoding="utf-8")
        for _ in range(2):
            with pytest.raises(model.ProposalError) as refusal:
                store.state(proposal.id)
            assert refusal.value.code == "decision", name
            assert "BBBB" not in str(refusal.value)
        path.write_bytes(original)
        assert store.state(proposal.id) == "rejected"
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _index: store.state(proposal.id), range(6))) == ["rejected"] * 6


def test_round8_inventory_bounds_refuse_before_copy_then_recover(tmp_path, monkeypatch):
    from aegis_core.insights import capture
    from aegis_core.redaction import RedactionRefusal

    workspace, home = tmp_path / "ws", tmp_path / "home"
    (workspace / ".aegis/rules/traps").mkdir(parents=True)
    _put_rule(workspace, "trap-one")
    _put_rule(workspace, "trap-two")
    maximum = capture.MAX_INSIGHT_ITEMS
    monkeypatch.setattr("aegis_core.insights.capture.MAX_INSIGHT_ITEMS", 1)
    for _ in range(2):
        with pytest.raises(RedactionRefusal, match="^too_large$"):
            add_insight(workspace, "Ordinary note.", paths=["app.py"], home=home)
    assert read_insight_rows(workspace, home=home) == []
    monkeypatch.setattr("aegis_core.insights.capture.MAX_INSIGHT_ITEMS", maximum)
    payload = {"prompt": "stop repeating this change", "session_id": "safe-session"}
    record_hook_prompt("cli", payload, workspace=workspace, home=home)
    before = read_insight_rows(workspace, home=home)
    assert any(row.get("event") == "inventory" and len(row["revs"]) == 2 for row in before)
    monkeypatch.setattr("aegis_core.insights.capture.MAX_INSIGHT_ITEMS", 1)
    for _ in range(2):
        with pytest.raises(RedactionRefusal, match="^too_large$"):
            record_hook_prompt("cli", payload, workspace=workspace, home=home)
    assert read_insight_rows(workspace, home=home) == before
    monkeypatch.setattr("aegis_core.insights.capture.MAX_INSIGHT_ITEMS", maximum)
    assert record_hook_prompt("cli", payload, workspace=workspace, home=home)


def _round8h_control_source(split, tail, placement=None, preceding=""):
    prefix = "abcdefghijklm" * 5
    controls = {"cr": "\r", "nel": "\x85", "vt": "\v", "ff": "\f", "esc-parameters": "\x1b[1:2m",
                "esc-intermediates": "\x1b[1:2 !p", "c1-parameters": "\x9b1:2m", "c1-intermediates": "\x9b1:2 !p",
                "esc-spaced": "\x1b[ m", "c1-spaced": "\x9b m"}
    if split.startswith("correctness-"):
        prefix = "a" * 70
        token = prefix + controls[split[len("correctness-"):]] + "z"
        continuation = "K1M2N3P4" + "Q5R6S7T8U9abcd"
        head = preceding + "Never repeat this: " + token
        removed = controls[tail] * 5000
        return head + removed + continuation, head + controls[tail] + continuation, prefix + "z" + continuation
    if split == "mixed":
        pieces = [prefix[index:index + 13] for index in range(0, len(prefix), 13)]
        token = pieces[0] + "\r" + pieces[1] + "\x85" + pieces[2] + "\x1b[1:2 !p" + pieces[3] + "\x9b31m" + pieces[4] + "\rA"
    elif split == "repeated":
        cycle = ("\r", "\x85", "\v", "\f", "\x1b[31m", "\x9b1:2 !p")
        token = "".join(char + cycle[index % len(cycle)] for index, char in enumerate(prefix)) + "A"
    else:
        token = prefix + controls[split] + "A"
    continuation = "k7Qm9pL2xV4n" + "R8wY3tB6cD1fH0aZ"
    if tail in ("vt", "ff"):
        head = preceding + "Never repeat this: " + token
        gap = 4097 if placement is None else 4097 + placement - len(head)
        source, short = head + controls[tail] * gap + continuation, head + controls[tail] + continuation
    else:
        source, short, _raw = _round8g_control_source(tail, placement, preceding=preceding, token=token)
    return source, short, prefix + "A" + continuation


def _round8h_control_pairs():
    splits = ("cr", "nel", "vt", "ff", "esc-parameters", "esc-intermediates", "c1-parameters", "c1-intermediates", "mixed", "repeated")
    tails = ("cr", "nel", "vt", "ff", "esc-parameters", "esc-intermediates", "c1-parameters", "c1-intermediates")
    edges = (None, -1, 0, 1)
    return [pytest.param(split, tail, edges[(left + right) % len(edges)], id=split + "-" + tail)
            for left, split in enumerate(splits) for right, tail in enumerate(tails)] + [
                pytest.param("correctness-" + split, tail, None, id="correctness-" + split + "-" + tail)
                for split in ("cr", "nel", "vt", "ff", "esc-spaced", "c1-spaced") for tail in ("cr", "nel", "esc-spaced")]


@pytest.mark.parametrize("split,tail,placement", _round8h_control_pairs())
def test_round8h_every_insight_writer_withholds_across_earlier_deleted_splits(tmp_path, split, tail, placement):
    from concurrent.futures import ThreadPoolExecutor

    workspace, home = tmp_path / "ws", tmp_path / "home"
    workspace.mkdir()
    source, short, secret = _round8h_control_source(split, tail, placement)
    expected = "Never repeat this: ..."
    member = add_insight(workspace, "Ordinary member.", paths=[], home=home)
    fragments = {secret[index:index + 4] for index in range(len(secret) - 3)}

    def persist(_index):
        rows = [add_insight(workspace, source, kind=source, paths=[], home=home),
                capture_suggestion(workspace, source, paths=[], host=source, home=home),
                record_hook_prompt(source, {"prompt": source, "session_id": "safe-session"}, workspace=workspace, home=home),
                record_hook_prompt(source, {"prompt": "Ordinary prompt.", "session_id": "heartbeat-session"}, workspace=workspace, home=home),
                record_decision(workspace, decision="confirm", insight_ids=[member["id"]], kind=source, reason=source, home=home)]
        assert rows[3]["event"] == "heartbeat" and "text" not in rows[3]
        for row, fields in zip(rows, (("text", "kind"), ("text", "host"), ("text", "host"), ("host",), ("kind", "reason"))):
            for field in fields:
                assert row[field] == expected
                assert not any(fragment in row[field] for fragment in fragments)

    for _ in range(2):
        persist(0)
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(persist, range(3)))
    for row in read_insight_rows(workspace, home=home):
        for field in ("text", "kind", "reason", "host"):
            assert not any(fragment in row.get(field, "") for fragment in fragments)
    if not split.startswith("correctness-"):
        from aegis_core.proposals.model import clean_text
        cleaned = clean_text(short, 300)
        assert "[REDACTED_HIENT]" in cleaned
        assert not any(fragment in cleaned for fragment in fragments)


def _round8g_control_source(control, placement=None, preceding="", token=None, case="security"):
    prefix = {"security": "abcdefghijklm" * 5, "correctness-letters": "abcdefghij" * 6 + "abcde",
              "correctness-symbols": "A=" * 8}[case] if token is None else token
    continuation = ("K1M2N3P4" + "Q5R6S7T8U9" if case == "correctness-letters" else
                    "k7Qm9pL2xV4n" + "R8wY3tB6cD1fH0aZ")
    lead = "Never repeat this: " if case == "security" else "First safe note. "
    head = preceding + lead + prefix
    gap = 4097 if placement is None else 4097 + placement - len(head)
    if control in ("cr", "nel", "nul", "ignored-c1"):
        removed = {"cr": "\r", "nel": "\x85", "nul": "\x00", "ignored-c1": "\x86"}[control] * gap
        short = removed[:1]
    else:
        intro = "\x1b[" if control.startswith("esc") else "\x9b"
        parameter = "1" if control.endswith("parameters") else " "
        if placement is None:
            gap = len(intro) + 5001
        removed = intro + parameter * (gap - len(intro) - 1) + "m"
        short = intro + parameter + "m"
    return head + removed + continuation, head + short + continuation, prefix + continuation


@pytest.mark.parametrize("control", ["cr", "nel", "nul", "ignored-c1", "esc-parameters", "esc-intermediates",
                                     "c1-parameters", "c1-intermediates"])
@pytest.mark.parametrize("placement", [None, -1, 0, 1], ids=["review", "before", "at", "after"])
@pytest.mark.parametrize("case", ["security", "correctness-letters", "correctness-symbols"])
def test_round8g_all_insight_writers_withhold_raw_token_without_detector_threshold(tmp_path, control, placement, case):
    from concurrent.futures import ThreadPoolExecutor

    workspace, home = tmp_path / "ws", tmp_path / "home"
    workspace.mkdir()
    source, _short, secret = _round8g_control_source(control, placement, case=case)
    expected = ("Never repeat this:" if case == "security" else "First safe note.") + " ..."
    hook_source = source if case == "security" else "Never " + source
    member = add_insight(workspace, "Ordinary member.", paths=[], home=home)
    fragments = {secret[index:index + 4] for index in range(len(secret) - 3)}

    def persist(_index):
        rows = [add_insight(workspace, source, kind=source, paths=[], home=home),
                capture_suggestion(workspace, source, paths=[], host=source, home=home),
                record_hook_prompt(source, {"prompt": hook_source, "session_id": "safe-session"}, workspace=workspace, home=home),
                record_decision(workspace, decision="confirm", insight_ids=[member["id"]], kind=source, reason=source, home=home)]
        for index, (row, fields) in enumerate(zip(rows, (("text", "kind"), ("text", "host"), ("text", "host"), ("kind", "reason")))):
            for field in fields:
                wanted = "Never " + expected if case != "security" and index == 2 and field == "text" else expected
                assert row[field] == wanted
                assert not any(fragment in row[field] for fragment in fragments)

    for _ in range(2):
        persist(0)
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(persist, range(3)))
    for row in read_insight_rows(workspace, home=home):
        for field in ("text", "kind", "reason", "host"):
            assert not any(fragment in row.get(field, "") for fragment in fragments)


@pytest.mark.parametrize("control", ["cr", "nel", "esc-parameters", "esc-intermediates", "c1-parameters", "c1-intermediates"])
@pytest.mark.parametrize("field", ["kind", "hypothesis", "prediction", "do", "labels", "guidance"])
@pytest.mark.parametrize("case", ["security", "correctness-letters", "correctness-symbols"])
def test_round8g_proposal_text_writers_refuse_overbound_then_mask_and_retry(tmp_path, control, field, case):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.proposals import model
    from tests.unit.core.test_proposals_store import make_store, snapshot

    source, short, secret = _round8g_control_source(control, case=case)
    base = dict(id="round8g-safe", source="one", kind="correctness", candidate_key="one:safe")
    wrap = lambda text: (text,) if field in ("labels", "guidance") else text
    code = "invalid" if field == "kind" and control == "cr" else "too_large"
    for _ in range(2):
        with pytest.raises(model.ProposalError) as caught:
            model.Proposal(**dict(base, **{field: wrap(source)}))
        assert caught.value.code == code
        assert secret[:4] not in str(caught.value)
    if field == "kind" and control == "cr":
        with pytest.raises(model.ProposalError) as caught:
            model.Proposal(**dict(base, **{field: wrap(short)}))
        assert caught.value.code == "invalid"  # Single-line kind refuses CR before cleaning.
        short = "Ordinary kind."
    proposal = model.Proposal(**dict(base, **{field: wrap(short)}))
    if not (field == "kind" and control == "cr"):
        cleaned = {"kind": proposal.kind, "hypothesis": proposal.hypothesis,
                   "prediction": proposal.prediction, "do": proposal.do,
                   "labels": proposal.labels, "guidance": proposal.guidance}[field]
        assert all("[REDACTED_HIENT]" in value for value in (cleaned if isinstance(cleaned, tuple) else (cleaned,)))
    assert all(secret[index:index + 4] not in proposal.to_bytes().decode("utf-8") for index in range(len(secret) - 3))
    store = make_store(tmp_path)
    saved = store.write(proposal)
    before = snapshot(store.root)
    for _ in range(2):
        assert store.write(proposal).digest == saved.digest
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(lambda _: store.write(proposal).digest, range(3))) == [saved.digest] * 3
    assert snapshot(store.root) == before
    assert store.read(proposal.id).digest == saved.digest


@pytest.mark.parametrize("control", ["cr", "nel", "esc-parameters", "esc-intermediates", "c1-parameters", "c1-intermediates"])
@pytest.mark.parametrize("case", ["security", "correctness-letters", "correctness-symbols"])
def test_round8g_proposal_decision_reason_refuses_before_write_and_recovers(tmp_path, control, case):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.proposals import model
    from tests.unit.core.test_proposals_store import make_store, snapshot

    store = make_store(tmp_path)
    proposal = model.Proposal(id="round8g-safe", source="one", kind="correctness", candidate_key="one:safe")
    store.write(proposal)
    source, short, secret = _round8g_control_source(control, case=case)
    before = snapshot(store.root)
    for _ in range(2):
        with pytest.raises(model.ProposalError) as caught:
            store.decide([proposal.id], decision="noise", operation_id="op-safe", reason=source)
        assert caught.value.code == "too_large"
        assert snapshot(store.root) == before

    def decide(_index):
        row = store.decide([proposal.id], decision="noise", operation_id="op-safe", reason=short)
        assert "[REDACTED_HIENT]" in row["reason"]
        assert all(secret[index:index + 4] not in row["reason"] for index in range(len(secret) - 3))
        return row

    expected = decide(0)
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(decide, range(3))) == [expected] * 3
    assert decide(0) == expected


@pytest.mark.parametrize("control", ["cr", "nel", "esc-parameters", "esc-intermediates", "c1-parameters", "c1-intermediates"])
@pytest.mark.parametrize("field", ["kind", "summary_bullets"])
@pytest.mark.parametrize("case", ["security", "correctness-letters", "correctness-symbols"])
def test_round8g_insight_proposal_writer_refuses_long_fields_and_recovers(tmp_path, control, field, case):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.proposals.model import ProposalError, parse_proposal

    workspace, home = tmp_path / "ws", tmp_path / "home"
    workspace.mkdir()
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")
    member = add_insight(workspace, "Ordinary distinct correction.", kind="correctness", paths=["app.py"], home=home)
    source, short, secret = _round8g_control_source(control, case=case)
    wrap = lambda text: (text,) if field == "summary_bullets" else text
    options = dict(proposal_id="round8g-safe", insight_ids=[member["id"]], home=home)
    for _ in range(2):
        with pytest.raises(ProposalError) as caught:
            write_proposal(workspace, **options, **{field: wrap(source)})
        assert caught.value.code == ("invalid" if field == "kind" and control == "cr" else "too_large")
        assert not (workspace / ".aegis/proposals/round8g-safe.md").exists()
    if field == "kind" and control == "cr":
        short = "Ordinary kind."

    def publish(_index):
        target = write_proposal(workspace, **options, **{field: wrap(short)})
        text = target.read_text(encoding="utf-8")
        parsed = parse_proposal(target.read_bytes(), "round8g-safe")
        free_text = (parsed.kind, parsed.hypothesis, parsed.prediction, parsed.do, *parsed.labels, *parsed.guidance)
        assert all(secret[index:index + 4] not in value for value in free_text for index in range(len(secret) - 3))
        if not (field == "kind" and control == "cr"):
            assert "[REDACTED_HIENT]" in (parsed.kind if field == "kind" else parsed.guidance[-1])
        return text

    expected = publish(0)
    assert publish(0) == expected
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert list(pool.map(publish, range(3))) == [expected] * 3


def _round8e_interrupted_text(value, secret, control, placement):
    split = min(16, max(1, len(secret) // 2))
    offset = value.index(secret) + split
    head, tail = "Never repeat this: " + value[:offset], value[offset:]
    gap = 4097 + placement - len(head)
    removed = "\x1b[" + " " * (gap - 3) + "m" if control == "csi" else control * gap
    return head + removed + tail


def _round8e_detector_families():
    from tests.unit.cli.test_check_ci_push import REDACTION_FAMILY_PROBES

    return REDACTION_FAMILY_PROBES


@pytest.mark.parametrize("family,value,secret,marker", _round8e_detector_families())
@pytest.mark.parametrize("control", ["\r", "\x85", "csi"], ids=["cr", "nel", "csi"])
@pytest.mark.parametrize("placement", [-1, 0, 1], ids=["before", "at", "after"])
def test_round8e_public_writer_bounds_never_persist_credential_fragments(
        tmp_path, family, value, secret, marker, control, placement):
    workspace, home = tmp_path / "ws", tmp_path / "home"
    (workspace / ".aegis/rules/traps").mkdir(parents=True)
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")
    _put_rule(workspace, "trap-safe")
    source = _round8e_interrupted_text(value, secret, control, placement)
    member = add_insight(workspace, "Ordinary member.", paths=["app.py"], home=home)
    fields = []
    for _ in range(2):
        fields.extend((
            add_insight(workspace, source, paths=["app.py"], home=home)["text"],
            capture_suggestion(workspace, source, paths=["app.py"], home=home)["text"],
            record_hook_prompt("cli", {"prompt": source, "session_id": "safe-session"},
                               workspace=workspace, home=home)["text"],
            add_insight(workspace, "Ordinary member.", kind=source, paths=["app.py"], home=home)["kind"],
            record_decision(workspace, decision="confirm", insight_ids=[member["id"]],
                            reason=source, home=home)["reason"],
            capture_suggestion(workspace, "Ordinary quote.", paths=["app.py"],
                               host=source, home=home)["host"],
        ))
    fragments = {secret[index:index + 4] for index in range(len(secret) - 3)}
    for shown in fields:
        assert shown.startswith("Never repeat this:")
        assert not any(fragment in shown for fragment in fragments), (family, control, placement)
    for row in read_insight_rows(workspace, home=home):
        for name in ("text", "kind", "reason", "host"):
            assert not any(fragment in row.get(name, "") for fragment in fragments), (family, name)


@pytest.mark.parametrize("control", ["\r", "\x85", "\x1b[" + " " * 30000 + "m"],
                         ids=["cr", "nel", "csi"])
def test_round8e_inconclusive_writer_fields_retry_and_parallel_calls(tmp_path, control):
    from concurrent.futures import ThreadPoolExecutor

    workspace, home = tmp_path / "ws", tmp_path / "home"
    (workspace / ".aegis/rules/traps").mkdir(parents=True)
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")
    _put_rule(workspace, "trap-safe")
    secret = "k7Qm9pL2xV4nR8wY3tB6cD1fH0aZ"
    removed = control if len(control) > 1 else control * 50000
    source = "Never repeat this: " + secret[:16] + removed + secret[16:]
    member = add_insight(workspace, "Ordinary member.", paths=["app.py"], home=home)

    def persist(_index):
        rows = [
            add_insight(workspace, source, kind=source, paths=["app.py"], home=home),
            capture_suggestion(workspace, source, paths=["app.py"], host=source, home=home),
            record_hook_prompt(source, {"prompt": source, "session_id": "safe-session"},
                               workspace=workspace, home=home),
            record_decision(workspace, decision="confirm", insight_ids=[member["id"]],
                            kind=source, reason=source, home=home),
        ]
        for row in rows:
            for field in ("text", "kind", "reason", "host"):
                assert all(secret[index:index + 4] not in row.get(field, "")
                           for index in range(len(secret) - 3))

    persist(0)
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(persist, range(3)))
    rows = read_insight_rows(workspace, home=home)
    assert {row["event"] for row in rows} >= {"insight", "decision", "heartbeat", "inventory"}
    assert all(secret[:4] not in json.dumps(row) for row in rows)


@pytest.mark.parametrize("intro", ["\x1b[", "\x9b"], ids=["esc", "c1"])
@pytest.mark.parametrize("control", ["\r", "\x85"], ids=["cr", "nel"])
@pytest.mark.parametrize("secret", ["0123456789012345k7Qm9pL2xV4nR8wY3tB6", "0123456789012345@example.test"],
                         ids=["entropy", "privacy"])
def test_round8e_unfinished_header_payload_is_withheld_on_every_writer(tmp_path, intro, control, secret):
    workspace, home = tmp_path / "ws", tmp_path / "home"
    (workspace / ".aegis/rules/traps").mkdir(parents=True)
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")
    _put_rule(workspace, "trap-safe")
    source = "Never repeat this: " + intro + secret[:16] + control * 50000 + secret[16:]
    member = add_insight(workspace, "Ordinary member.", paths=["app.py"], home=home)
    fields = []
    for _ in range(2):
        fields.extend((
            add_insight(workspace, source, paths=["app.py"], home=home)["text"],
            capture_suggestion(workspace, source, paths=["app.py"], home=home)["text"],
            record_hook_prompt("cli", {"prompt": source, "session_id": "safe-session"},
                               workspace=workspace, home=home)["text"],
            add_insight(workspace, "Ordinary member.", kind=source, paths=["app.py"], home=home)["kind"],
            record_decision(workspace, decision="confirm", insight_ids=[member["id"]],
                            reason=source, home=home)["reason"],
            capture_suggestion(workspace, "Ordinary quote.", paths=["app.py"], host=source, home=home)["host"],
        ))
    # ROUND-8h: genuine whitespace before the header preserves this benign cue.
    assert fields == ["Never repeat this: ..."] * 12
    for row in read_insight_rows(workspace, home=home):
        for field in ("text", "kind", "reason", "host"):
            assert secret[:4] not in row.get(field, "")


@pytest.mark.parametrize("control", ["\r", "\x85", "\x00", "\n", "\t", "\x1b[31m", "\x9b31m",
                                     "\x1b[" + "1;" * 5000 + "m", "\x9b" + " " * 5000 + "m"],
                         ids=["cr", "nel", "nul", "lf", "tab", "esc", "c1", "parameters", "intermediates"])
def test_round8e_conservative_tail_rule_applies_to_every_public_writer(tmp_path, control):
    workspace, home = tmp_path / "ws", tmp_path / "home"
    (workspace / ".aegis/rules/traps").mkdir(parents=True)
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")
    _put_rule(workspace, "trap-safe")
    source = "Never repeat this: " + control + " ordinary" * 1000
    member = add_insight(workspace, "Ordinary member.", paths=["app.py"], home=home)
    fields = (
        add_insight(workspace, source, paths=["app.py"], home=home)["text"],
        capture_suggestion(workspace, source, paths=["app.py"], home=home)["text"],
        record_hook_prompt("cli", {"prompt": source, "session_id": "safe-session"},
                           workspace=workspace, home=home)["text"],
        add_insight(workspace, "Ordinary member.", kind=source, paths=["app.py"], home=home)["kind"],
        record_decision(workspace, decision="confirm", insight_ids=[member["id"]],
                        reason=source, home=home)["reason"],
        capture_suggestion(workspace, "Ordinary quote.", paths=["app.py"], host=source, home=home)["host"],
    )
    prefix = "Never repeat this:"
    assert all(shown.startswith(prefix) for shown in fields)
    if len(control) < 10:
        assert all(" ordinary" in shown for shown in fields)
    else:
        # ROUND-8h: header intermediates are removed; preceding space remains.
        assert fields == ("Never repeat this: ...",) * 6
    for row in read_insight_rows(workspace, home=home):
        for field in ("text", "kind", "reason", "host"):
            if row.get(field, "").startswith("Never"):
                assert row[field].startswith(prefix)


def _make_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q")
    (path / ".aegis" / "rules" / "traps").mkdir(parents=True, exist_ok=True)
    (path / ".aegis" / ".gitignore").write_text("state/\n", encoding="utf-8")
    (path / "app.py").write_text("a = 1\n", encoding="utf-8")
    _git(path, "add", "-f", ".")
    _git(path, "commit", "-q", "-m", "init")
    return path


def test_link_key_refuses_symlinks_and_corrupt_sizes(tmp_path: Path):
    home = tmp_path / "home"
    aegis = home / ".aegis"
    aegis.mkdir(parents=True)
    evil = tmp_path / "evil.key"
    evil.write_bytes(b"x" * KEY_SIZE)
    (aegis / "link.key").symlink_to(evil)

    with pytest.raises(PathTraversalError):
        create_link_key(home)
    assert read_link_key(home) is None

    (aegis / "link.key").unlink()
    (aegis / "link.key").write_bytes(b"short")
    with pytest.raises(ValueError, match="corrupt"):
        create_link_key(home)
    assert read_link_key(home) is None


def test_read_link_key_closes_descriptor_when_fdopen_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from aegis_core.insights import keys

    home = tmp_path / "home"
    create_link_key(home)
    descriptors = []

    def fail_fdopen(fd, mode):
        assert mode == "rb"
        descriptors.append(fd)
        raise OSError("fdopen failed")

    local_os = SimpleNamespace(**vars(os))
    local_os.fdopen = fail_fdopen
    monkeypatch.setattr(keys, "os", local_os)

    try:
        assert read_link_key(home) is None
        assert len(descriptors) == 1
        with pytest.raises(OSError) as exc_info:
            os.fstat(descriptors[0])
        assert exc_info.value.errno == errno.EBADF
    finally:
        for fd in descriptors:
            try:
                os.close(fd)
            except OSError as exc:
                assert exc.errno == errno.EBADF


def test_session_hs_rejects_invalid_inputs(tmp_path: Path):
    home = tmp_path / "home"
    home.mkdir()
    create_link_key(home)
    key = read_link_key(home)
    assert key is not None

    assert session_hs("", "valid-id", key) is None
    assert session_hs("claude-code", "", key) is None
    assert session_hs("claude-code", "x" * 129, key) is None
    assert session_hs("claude-code", "bad\x00id", key) is None
    assert session_hs("claude-code", "valid-id", b"short") is None


def test_matches_proposal_and_noise_decision_filtering(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    repo = _make_repo(tmp_path / "repo")

    seed = add_insight(repo, "Hung child processes stalled the nightly job", paths=["app.py"], kind="reliability",
                       home=home)
    write_proposal(
        repo,
        proposal_id="trap-timeout-required",
        insight_ids=[seed["id"]],
        summary_bullets=["Always pass an explicit timeout parameter to subprocess and network requests."],
        home=home,
    )
    record_decision(repo, decision="noise", insight_ids=[seed["id"]], home=home)

    ins1 = add_insight(
        repo,
        "Stop calling subprocess or network requests without an explicit timeout parameter in app.py",
        paths=["app.py"],
        home=home,
    )
    ins_noise = add_insight(
        repo,
        "No, don't add trailing whitespace in unrelated scratch notes",
        paths=["app.py"],
        home=home,
    )

    record_decision(
        repo,
        decision="noise",
        insight_ids=[ins_noise["id"]],
        home=home,
    )

    rev = review_insights(repo, home=home)
    reviewed_ids = [e["id"] for e in rev["insights"] + rev["suppressed"]]
    assert ins_noise["id"] not in reviewed_ids
    assert ins1["id"] in reviewed_ids
    prop_matches = [e for e in rev["insights"] if e["match"]["status"] == "matches_proposal"]
    assert len(prop_matches) == 1
    assert prop_matches[0]["match"]["rule"] == "trap-timeout-required"


def test_hook_counters_only_mode_records_heartbeat_without_excerpt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    repo = _make_repo(tmp_path / "repo")

    res = record_hook_prompt(
        "claude-code",
        {"prompt": "No, stop breaking the build!", "session_id": "s-counters-only", "cwd": str(repo)},
        excerpts=False,
        home=home,
    )
    assert res["event"] == "heartbeat"
    assert res["cue"] is True

    rows = read_insight_rows(repo, home=home)
    assert len(rows) == 1
    assert rows[0]["event"] == "heartbeat"
    assert "text" not in rows[0]


def _neighbours_of(review: dict, insight_id: str) -> list:
    (entry,) = [e for e in review["insights"] if e["id"] == insight_id]
    return entry["neighbours"]


def test_tfidf_neighbours_and_dirty_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = _make_repo(tmp_path / "repo")
    assert dirty_paths(repo) == []
    (repo / "app.py").write_text("a = 2\n", encoding="utf-8")
    (repo / "new_file.py").write_text("b = 3\n", encoding="utf-8")
    assert dirty_paths(repo) == ["app.py", "new_file.py"]

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    texts = ("validate path confinement before deletion", "validate path confinement before deleting",
             "configure oauth2 bearer token refresh")
    same, near, other = (add_insight(repo, t, paths=["app.py"], home=home)["id"] for t in texts)
    (only,) = _neighbours_of(review_insights(repo, home=home), same)  # no shared term: not a neighbour
    assert only["id"] == near and only["similarity"] > 0.3
    assert _neighbours_of(review_insights(repo, home=home), other) == []


def _stat_dirty(path: Path) -> None:
    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))


def test_dirty_paths_never_runs_a_submodule_clean_filter(tmp_path: Path):
    # R-evidence-43: the submodule's own config must not choose a program dirty_paths runs.
    sub_src = tmp_path / "subsrc"
    sub_src.mkdir()
    _git(sub_src, "init", "-q")
    (sub_src / "f.txt").write_text("data\n", encoding="utf-8")
    _git(sub_src, "add", ".")
    _git(sub_src, "commit", "-q", "-m", "sub")
    repo = _make_repo(tmp_path / "repo")
    _git(repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub_src), "sub")
    _git(repo, "commit", "-q", "-m", "add sub")
    marker = tmp_path / "marker"
    script = tmp_path / "filt.py"
    script.write_text(
        f"import sys\nopen({str(marker)!r}, 'w').close()\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    modules = repo / ".git" / "modules" / "sub"
    _git(repo, "config", "-f", str(modules / "config"), "filter.evil.clean",
         f'"{Path(sys.executable).as_posix()}" "{script.as_posix()}"')
    (modules / "info").mkdir(exist_ok=True)
    (modules / "info" / "attributes").write_text("* filter=evil\n", encoding="utf-8")
    _stat_dirty(repo / "sub" / "f.txt")
    (repo / "app.py").write_text("a = 2\n", encoding="utf-8")

    assert dirty_paths(repo) == ["app.py"]
    assert not marker.exists()


def test_dirty_paths_skips_deleted_touched_and_state_files(tmp_path: Path):
    repo = _make_repo(tmp_path / "repo")
    (repo / "gone.py").write_text("g = 1\n", encoding="utf-8")
    (repo / "same.py").write_text("s = 1\n", encoding="utf-8")
    (repo / ".aegis" / "state").mkdir()
    (repo / ".aegis" / "state" / "x.json").write_text("{}\n", encoding="utf-8")
    _git(repo, "add", "-f", ".")
    _git(repo, "commit", "-q", "-m", "more")
    (repo / "gone.py").unlink()
    _stat_dirty(repo / "same.py")
    (repo / ".aegis" / "state" / "x.json").write_text('{"a": 1}\n', encoding="utf-8")

    assert dirty_paths(repo) == []


def test_add_insight_confines_explicit_paths_to_the_workspace(tmp_path: Path):
    home = tmp_path / "home"
    repo = _make_repo(tmp_path / "repo")
    with pytest.raises(PathTraversalError):
        add_insight(repo, "Never touch passwd", paths=["../../etc/passwd"], home=home)
    with pytest.raises(PathTraversalError):
        add_insight(repo, "Never touch passwd", paths=["src/ok.py", str(tmp_path / "outside.py")], home=home)
    assert read_insight_rows(repo, home=home) == []

    row = add_insight(repo, "Keep commas", paths=["src/a,b.py", str(repo.resolve() / "app.py"), " "], home=home)
    assert row["paths"] == ["app.py", "src/a,b.py"]


def test_add_insight_refuses_a_symlink_that_escapes(tmp_path: Path):
    home = tmp_path / "home"
    repo = _make_repo(tmp_path / "repo")
    (tmp_path / "secret.py").write_text("s = 1\n", encoding="utf-8")
    try:
        (repo / "link.py").symlink_to(tmp_path / "secret.py")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(PathTraversalError):
        capture_suggestion(repo, "Do not follow links", paths=["link.py"], home=home)
    assert read_insight_rows(repo, home=home) == []


def test_add_insight_level_h_requires_explicit_commit_and_matching_insight_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    from aegis_core import human_gate
    from tests import helpers_humangate as hg

    if not hg.signing_ok():
        pytest.skip("needs git >= 2.34 and ssh-keygen")

    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)

    human_key, human_pub = hg.keygen(tmp_path / "keys", "human")
    repo = hg.make_repo(tmp_path, human_pub)
    repo.write(".aegis/rules/traps/trap-sample.md", hg.RULE.replace("sample", "updated"))
    repo.commit("update rule")
    gov_hash = human_gate.governance_tree_hash(repo.root, "HEAD")
    gov_sha = repo.commit(
        f"chore: approve gov\n\nAegis-Approve: {gov_hash}\n",
        sign_key=human_key,
        allow_empty=True,
    )

    text_a = "Never call subprocess.run without an explicit timeout parameter"
    text_b = "Never deserialize untrusted pickle payloads from network sockets"

    # 1. Governance approval on branch does NOT grant level="H" (neither commit=None nor commit=gov_sha)
    ins_gov_none = add_insight(repo.root, text_a, paths=["src/app.py"], commit=None, base_ref="main", home=home)
    ins_gov_sha = add_insight(repo.root, text_a, paths=["src/app.py"], commit=gov_sha, base_ref="main", home=home)
    assert ins_gov_none["level"] == "cli"
    assert ins_gov_sha["level"] == "cli"

    # 2. Signed commit with Aegis-Approve-Insight: <insight_text_hash(text_a)> grants level="H" ONLY for text_a with commit=sha
    ins_sha = repo.commit(
        f"chore: approve insight\n\n{human_gate.INSIGHT_APPROVE_TRAILER}: {human_gate.insight_text_hash(text_a)}\n",
        sign_key=human_key,
        allow_empty=True,
    )
    ins_ok = add_insight(repo.root, text_a, paths=["src/app.py"], commit=ins_sha, base_ref="main", home=home)
    ins_wrong_text = add_insight(repo.root, text_b, paths=["src/app.py"], commit=ins_sha, base_ref="main", home=home)
    ins_no_commit = add_insight(repo.root, text_a, paths=["src/app.py"], commit=None, base_ref="main", home=home)
    assert ins_ok["level"] == "H"
    assert ins_wrong_text["level"] == "cli"
    assert ins_no_commit["level"] == "cli"


def _ours(command: str = "python3 -I -m aegis_cli.hooks.insights --host claude-code") -> dict:
    return {"matcher": "", "hooks": [{"type": "command", "command": command}]}


def test_merge_insight_hook_replaces_ours_and_keeps_foreign_entries():
    foreign = {"matcher": "", "hooks": [{"type": "command", "command": "echo mine"}]}
    shared = {"matcher": "", "hooks": [{"type": "command", "command": "echo shared"},
                                       {"type": "command", "command": "/py", "args": ["-c", "aegis_cli.hooks.insights"]}]}
    data = {"model": "x", "hooks": {"UserPromptSubmit": [_ours(), foreign, shared]}}
    handler = {"type": "command", "command": "/py", "args": ["-I", "-c", "from aegis_cli.hooks.insights import main"]}
    core_insights.merge_insight_hook(data, handler)
    assert data == {"model": "x", "hooks": {"UserPromptSubmit": [
        foreign, {"matcher": "", "hooks": [{"type": "command", "command": "echo shared"}]},
        {"matcher": "", "hooks": [handler]}]}}
    assert core_insights.INSIGHT_HOOK_MARKER == "aegis_cli.hooks.insights"


@pytest.mark.parametrize("data, where", [
    ({"hooks": ["x"]}, "hooks"),
    ({"hooks": {"UserPromptSubmit": {}}}, "UserPromptSubmit"),
])
def test_merge_insight_hook_refuses_a_wrong_shape(data, where):
    with pytest.raises(ValueError, match=where):
        core_insights.merge_insight_hook(data, {"type": "command", "command": "/py"})


def test_remove_insight_hook_counts_ours_and_drops_emptied_containers():
    data = {"hooks": {"UserPromptSubmit": [_ours(), _ours("/py -c 'from aegis_cli.hooks.insights import main'")],
                      "Stop": []}}
    assert core_insights.remove_insight_hook("claude-code", data) == 2
    assert data == {"hooks": {"Stop": []}}
    data = {"hooks": {"UserPromptSubmit": [_ours()]}}
    assert core_insights.remove_insight_hook("codex-cli", data) == 1 and data == {}


@pytest.mark.parametrize("data", [
    {}, {"hooks": ["x"]}, {"hooks": {"UserPromptSubmit": {}}}, {"hooks": {"UserPromptSubmit": ["x", {"hooks": 3}]}},
])
def test_remove_insight_hook_never_raises_on_odd_shapes(data):
    before = repr(data)
    assert core_insights.remove_insight_hook("claude-code", data) == 0
    assert repr(data) == before


def test_host_capture_status_ignores_a_relative_config_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / "settings.json").write_text(
        '{"hooks": {"UserPromptSubmit": [{"hooks": [{"command": "/py", "args": ["-c", "aegis_cli.hooks.insights", "--excerpts"]}]}]}}',
        encoding="utf-8")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", "relative/dir")
    assert host_capture_status("claude-code", home=home) == {"status": "enabled_excerpts", "excerpts": True,
                                                             "capture": "excerpts", "capture_source": "host entry"}


# ── One workspace, one insights file, whatever the hook's cwd (R-evidence-39) ──

@pytest.fixture
def hook_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    (home / ".aegis").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for name in ("CLAUDE_PROJECT_DIR", "CLAUDE_CONFIG_DIR", "CODEX_HOME", "AEGIS_WORKSPACE"):
        monkeypatch.delenv(name, raising=False)
    return home


def _insight_texts(workspace: Path, home: Path) -> list:
    return sorted(r["text"] for r in read_insight_rows(workspace, home=home) if r.get("event") == "insight")


def test_a_hook_in_a_subdirectory_writes_the_governed_roots_file(tmp_path: Path, hook_home: Path):
    repo = _make_repo(tmp_path / "repo")
    (repo / "src").mkdir()
    record_hook_prompt("claude-code", {"prompt": "No, stop breaking the parser", "session_id": "s1",
                                       "cwd": str(repo / "src")}, home=hook_home)
    record_hook_prompt("claude-code", {"prompt": "Don't touch the lockfile again", "session_id": "s2",
                                       "cwd": str(repo)}, home=hook_home)
    assert insights_path(repo / "src", home=hook_home) == insights_path(repo, home=hook_home)
    assert _insight_texts(repo, hook_home) == ["Don't touch the lockfile again", "No, stop breaking the parser"]
    assert len(list((hook_home / ".aegis" / "insights").glob("*.jsonl"))) == 1


def test_an_ungoverned_repository_under_home_keeps_the_cwds_own_id(hook_home: Path):
    # A walk-up that went past the git top would reach ~/.aegis, the user plane every user has.
    proj = hook_home / "proj"
    proj.mkdir()
    _git(proj, "init", "-q")
    (proj / "sub").mkdir()
    record_hook_prompt("claude-code", {"prompt": "No, wrong file", "cwd": str(proj / "sub")}, home=hook_home)
    assert insight_workspace_id(proj / "sub") != insight_workspace_id(hook_home)
    assert _insight_texts(proj / "sub", hook_home) == ["No, wrong file"]


@pytest.mark.parametrize("marker", ["directory", "gitfile"])
def test_insight_workspace_id_at_ceiling_ignores_enclosing_repository(tmp_path: Path, monkeypatch, marker):
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"):
        monkeypatch.delenv(name, raising=False)
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    _git(checkout, "init", "-q")
    if marker == "gitfile":
        metadata = tmp_path / "checkout.git"
        (checkout / ".git").rename(metadata)
        (checkout / ".git").write_text("gitdir: " + str(metadata) + "\n", encoding="utf-8")
    start = checkout / "basetemp"
    start.mkdir()
    standalone = hashlib.sha256(start.resolve().as_posix().encode("utf-8", "surrogatepass")).hexdigest()[:16]
    assert insight_workspace_id(start) != standalone

    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(start))

    assert insight_workspace_id(start) == standalone


@pytest.mark.parametrize("boundary", ["start", "inside-ceiling", "above-ceiling"])
def test_insight_workspace_id_honours_explicit_git_layout(tmp_path: Path, monkeypatch, boundary):
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    ceiling = tmp_path / "ceiling"
    top = ceiling / "worktree"
    start = top / "sub"
    start.mkdir(parents=True)
    reported_top = {"start": start, "inside-ceiling": top, "above-ceiling": tmp_path}[boundary]
    monkeypatch.setenv("GIT_DIR", str(repository / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(reported_top))
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(ceiling))
    relative = start.resolve().relative_to(reported_top.resolve()).as_posix()
    canonical = f"{(repository / '.git').resolve().as_posix()}\x00{relative}"
    expected = hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()[:16]

    assert insight_workspace_id(start) == expected


@pytest.mark.parametrize("layout_variable", ["GIT_DIR", "GIT_WORK_TREE"])
def test_single_explicit_git_layout_above_ceiling_keeps_boundary_and_identity(
    tmp_path: Path, monkeypatch, layout_variable
):
    from aegis_core.workspace.binding import git_boundary

    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"):
        monkeypatch.delenv(name, raising=False)
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "core.worktree", str(repository.resolve()))
    start = repository / "basetemp"
    start.mkdir()
    value = repository / ".git" if layout_variable == "GIT_DIR" else repository
    monkeypatch.setenv(layout_variable, str(value))
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(start))
    canonical = f"{(repository / '.git').resolve().as_posix()}\x00basetemp"
    expected = hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()[:16]

    assert git_boundary(start) == repository.resolve()
    assert insight_workspace_id(start) == expected


@pytest.mark.parametrize("layout_variable", ["GIT_DIR", "GIT_WORK_TREE"])
@pytest.mark.parametrize("git_answer", ["off-path", "query-failure", "unresolvable"])
def test_unusable_explicit_git_layout_does_not_supply_insights_identity(
    tmp_path: Path, monkeypatch, layout_variable, git_answer
):
    from aegis_core import gitsafe
    from aegis_core.insights import keys

    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"):
        monkeypatch.delenv(name, raising=False)
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    off_path = tmp_path / "off-path"
    off_path.mkdir()
    _git(repository, "config", "core.worktree", str(off_path.resolve()))
    start = repository / "basetemp"
    start.mkdir()
    value = repository / ".git" if layout_variable == "GIT_DIR" else off_path
    monkeypatch.setenv(layout_variable, str(value))
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(start))
    assert gitsafe.toplevel(start) == off_path.resolve()
    if git_answer != "off-path":
        class UnresolvablePath(type(Path())):
            def resolve(self, *args, **kwargs):
                raise OSError("Git top cannot be resolved")

        reported = UnresolvablePath(off_path) if git_answer == "unresolvable" else None
        git_api = SimpleNamespace(**vars(gitsafe))
        git_api.toplevel = lambda cwd: reported
        monkeypatch.setattr(keys, "gitsafe", git_api)
    standalone = hashlib.sha256(start.resolve().as_posix().encode("utf-8", "surrogatepass")).hexdigest()[:16]

    assert insight_workspace_id(start) == standalone


def test_claude_project_dir_wins_over_the_payload_cwd(tmp_path: Path, hook_home: Path, monkeypatch):
    repo, other = _make_repo(tmp_path / "repo"), _make_repo(tmp_path / "other")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(repo))
    record_hook_prompt("claude-code", {"prompt": "No, revert that", "cwd": str(other)}, home=hook_home)
    assert _insight_texts(repo, hook_home) == ["No, revert that"]
    assert _insight_texts(other, hook_home) == []


def test_a_relative_claude_project_dir_is_ignored(tmp_path: Path, hook_home: Path, monkeypatch):
    repo = _make_repo(tmp_path / "repo")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", "repo")
    record_hook_prompt("claude-code", {"prompt": "No, revert that", "cwd": str(repo)}, home=hook_home)
    assert _insight_texts(repo, hook_home) == ["No, revert that"]


def test_a_cwd_that_does_not_exist_falls_back_to_itself(tmp_path: Path, hook_home: Path):
    missing = _make_repo(tmp_path / "repo") / "gone"
    record_hook_prompt("claude-code", {"prompt": "No, wrong file", "cwd": str(missing)}, home=hook_home)
    assert _insight_texts(missing, hook_home) == ["No, wrong file"]


# ── a heartbeat per identified prompt, revisions through inventory rows (R-evidence-40) ──

_RULE_MD = (
    "---\nid: {rid}\ntype: trap\nenforcement: advisory\nhypothesis: Popen hangs.\n"
    "target_paths:\n  - '*.py'\n---\n# {rid}\n\nNever call subprocess.Popen without a timeout.{extra}\n"
)


def _put_rule(repo: Path, rid: str, extra: str = "") -> None:
    (repo / ".aegis" / "rules" / "traps" / f"{rid}.md").write_text(_RULE_MD.format(rid=rid, extra=extra), encoding="utf-8")


def _prompt(repo: Path, home: Path, text: str = "Please run the tests.", session: str = "s-hb", **kw):
    return record_hook_prompt("claude-code", {"prompt": text, "session_id": session, "cwd": str(repo)}, home=home, **kw)


def _events(repo: Path, home: Path, event: str):
    return [r for r in read_insight_rows(repo, home=home) if r.get("event") == event]


@pytest.fixture
def hb_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


def test_a_session_counts_alive_for_a_rule_created_between_its_prompts(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    _prompt(repo, hb_home)
    _put_rule(repo, "trap-mid")
    _prompt(repo, hb_home)
    rec = measure_recurrence(repo, "trap-mid", home=hb_home)
    assert (rec["sessions"], rec["status"]) == (1, "ok")


def test_counters_only_cue_prompts_store_a_text_free_heartbeat_each(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    for _ in range(2):
        _prompt(repo, hb_home, "No, stop breaking the build!", excerpts=False)
    rows = read_insight_rows(repo, home=hb_home)
    assert [r["event"] for r in rows] == ["heartbeat", "heartbeat"]
    assert all(r["cue"] is True and "text" not in r for r in rows)


def test_an_unchanged_rule_set_writes_one_inventory_row(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    _put_rule(repo, "trap-inv")
    for _ in range(500):
        _prompt(repo, hb_home)
    (inv,) = _events(repo, hb_home, "inventory")
    beats = _events(repo, hb_home, "heartbeat")
    assert len(beats) == 500
    assert all(b["inv"] == inv["inv"] and "revs" not in b for b in beats)
    assert set(inv["revs"]) == {"trap-inv"}
    lines = insights_path(repo, home=hb_home).read_bytes().splitlines()
    assert max(len(line) for line in lines if b'"heartbeat"' in line) <= 200

    _put_rule(repo, "trap-inv", extra=" Revised.")
    _prompt(repo, hb_home)
    assert len(_events(repo, hb_home, "inventory")) == 2


def test_a_heartbeat_whose_inv_has_no_inventory_row_is_not_alive(tmp_path: Path, hb_home: Path):
    from aegis_core.rules import load_rules
    from aegis_core.storage import append_jsonl

    repo = _make_repo(tmp_path / "repo")
    _put_rule(repo, "trap-orphan")
    rev = load_rules(repo).get("trap-orphan").digest[:16]
    base = {"v": 1, "ts": "2026-10-20T00:00:00Z", "event": "heartbeat", "host": "claude-code"}
    path = insights_path(repo, home=hb_home)
    path.parent.mkdir(parents=True)
    append_jsonl(path, [dict(base, hs="a" * 32, cue=False, inv="0" * 16)])
    assert measure_recurrence(repo, "trap-orphan", home=hb_home)["sessions"] == 0
    append_jsonl(path, [dict(base, hs="b" * 32, revs={"trap-orphan": rev})])
    assert measure_recurrence(repo, "trap-orphan", home=hb_home)["sessions"] == 1


def test_a_workspace_without_rule_files_writes_heartbeats_without_inv(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    _prompt(repo, hb_home)
    _prompt(repo, hb_home)
    rows = read_insight_rows(repo, home=hb_home)
    assert [r["event"] for r in rows] == ["heartbeat", "heartbeat"]
    assert all("inv" not in r and "revs" not in r for r in rows)


# ── no session identity, no heartbeat (R-structure-a2) ────────────────────────

def _hook_entry(repo: Path, home: Path, stdin: str):
    import contextlib
    import io

    from aegis_cli.hooks.insights import run_insight_hook

    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = run_insight_hook(["--host", "claude-code", "--excerpts"], stdin=stdin, home=home)
    return rc, out.getvalue(), err.getvalue()


def test_a_prompt_without_a_session_writes_nothing(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    _put_rule(repo, "trap-nosess")
    for stdin in ("", '{"prompt": "Please run the tests."}', '{"prompt": "Run the linter.", "session_id": "  "}'):
        assert _hook_entry(repo, hb_home, stdin) == (0, "", "")
    assert not (hb_home / ".aegis" / "insights").exists()
    assert read_insight_rows(repo, home=hb_home) == []


def test_a_cue_prompt_without_a_session_writes_only_its_insight(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    _put_rule(repo, "trap-nosess")
    record_hook_prompt("claude-code", {"prompt": "No, stop breaking the build!", "cwd": str(repo)}, home=hb_home)
    (row,) = read_insight_rows(repo, home=hb_home)
    assert row["event"] == "insight" and "hs" not in row and set(row["revs"]) == {"trap-nosess"}
    _prompt(repo, hb_home)
    _prompt(repo, hb_home)
    assert len(_events(repo, hb_home, "heartbeat")) == 2


def test_a_corrupt_log_and_no_session_still_exit_zero_silently(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    store = insights_path(repo, home=hb_home)
    store.parent.mkdir(parents=True)
    store.write_bytes(b"\xff{garbage\n")
    assert _hook_entry(repo, hb_home, json.dumps({"prompt": "No, wrong file again", "cwd": str(repo)})) == (0, "", "")
    assert [r["event"] for r in read_insight_rows(repo, home=hb_home)] == ["insight"]


# ── R-evidence-35: the verbatim lint protects human text only, with a 25-character floor ──

@pytest.fixture
def lint_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    return _make_repo(tmp_path / "repo"), home


def _propose(repo: Path, home: Path, bullet: str, pid: str = "trap-lint") -> Path:
    member = add_insight(repo, "Keep this member text apart from every bullet", paths=["app.py"], kind="correctness",
                         home=home)
    return write_proposal(repo, proposal_id=pid, insight_ids=[member["id"]], summary_bullets=[bullet], home=home)


def _hook_prompt(repo: Path, home: Path, text: str, session: str = "s-lint") -> dict:
    row = record_hook_prompt("claude-code", {"prompt": text, "session_id": session, "cwd": str(repo)},
                             workspace=repo, home=home)
    assert row.get("event") == "insight", text
    return row


def test_agent_suggestions_never_block_a_proposal(lint_repo):
    repo, home = lint_repo
    capture_suggestion(repo, "e", paths=["app.py"], host="claude-code", session="agent", home=home)
    capture_suggestion(repo, "Address recurring correction cluster", paths=["app.py"], host="claude-code",
                       session="agent", home=home)
    assert _propose(repo, home, "Address recurring correction cluster cluster-ab12cd.").is_file()


def test_a_short_hook_prompt_blocks_only_an_identical_bullet(lint_repo):
    repo, home = lint_repo
    _hook_prompt(repo, home, "revert")
    assert _propose(repo, home, "Always revert partial writes when the update fails.").is_file()
    with pytest.raises(ValueError, match="verbatim H/cli/W2 prompt text"):
        _propose(repo, home, "Revert", pid="trap-lint-2")


def test_a_4_3_upgraded_w2_capture_does_not_protect_its_text(lint_repo):
    repo, home = lint_repo
    from aegis_core.storage import append_jsonl

    append_jsonl(insights_path(repo, home=home), [{
        "v": 1, "ts": "2026-10-20T00:00:00Z", "event": "insight", "id": "ins-0000000000dd", "level": "W2",
        "text": "revert partial writes when the update fails", "paths": ["app.py"], "psrc": "explicit",
        "host": "claude-code", "hs": "a" * 32, "confirmed_by": "ins-000000000001"}])
    assert _propose(repo, home, "Always revert partial writes when the update fails.").is_file()


@pytest.mark.parametrize("bullet", [
    "No, never call shutil.rmtree on unvalidated user paths in src/app.py!",
    "Remember: no, never call shutil.rmtree on unvalidated user paths in src/app.py! Validate first.",
    "never call rmtree",
], ids=["full", "embedded", "short-exact"])
def test_hook_prompts_still_block_verbatim_bullets(lint_repo, bullet):
    repo, home = lint_repo
    _hook_prompt(repo, home, "No, never call shutil.rmtree on unvalidated user paths in src/app.py!")
    _hook_prompt(repo, home, "never call rmtree", session="s-lint-2")
    with pytest.raises(ValueError, match="verbatim"):
        _propose(repo, home, bullet)


def test_cli_text_of_25_characters_or_more_is_protected(lint_repo):
    repo, home = lint_repo
    text = "Validate symlink confinement before opening state files"
    add_insight(repo, text, paths=["app.py"], home=home)
    with pytest.raises(ValueError, match="verbatim H/cli/W2 prompt text"):
        _propose(repo, home, f"Rule: {text}.")
    assert not (repo / ".aegis" / "proposals" / "trap-lint.md").exists()


# ── R-evidence-45: one hook calling convention, a reachable surface, Rule.applies_to ──

def test_the_old_argument_order_of_record_hook_prompt_is_a_type_error(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    payload = {"prompt": "No, stop breaking the build!", "session_id": "s-old", "cwd": str(repo)}
    with pytest.raises(TypeError):
        record_hook_prompt(repo, "claude-code", payload, home=hb_home)
    with pytest.raises(TypeError):
        record_hook_prompt("claude-code", payload, session="s-typed", home=hb_home)
    assert read_insight_rows(repo, home=hb_home) == []


def test_a_hook_whose_recorder_raises_exits_zero_with_the_error_on_stderr(tmp_path: Path, hb_home: Path,
                                                                           monkeypatch: pytest.MonkeyPatch):
    from aegis_cli.hooks import insights as hook

    repo = _make_repo(tmp_path / "repo")

    def broken(*args, **kwargs):
        raise TypeError("recorder broke")

    monkeypatch.setattr(hook, "record_hook_prompt", broken)
    payload = json.dumps({"prompt": "No, stop breaking the build!", "session_id": "s-err", "cwd": str(repo)})
    rc, out, err = _hook_entry(repo, hb_home, payload)
    assert (rc, out) == (0, "") and "aegis insight hook error: recorder broke" in err
    assert read_insight_rows(repo, home=hb_home) == []


def test_hook_stdin_that_is_not_a_json_object_records_no_insight(tmp_path: Path, hb_home: Path,
                                                                   monkeypatch: pytest.MonkeyPatch):
    repo = _make_repo(tmp_path / "repo")
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    monkeypatch.chdir(repo)
    for stdin in ("stop doing that", '["No, stop doing that"]', '"No, stop doing that"'):
        assert _hook_entry(repo, hb_home, stdin) == (0, "", "")
    assert read_insight_rows(repo, home=hb_home) == []


def test_a_payload_without_the_prompt_key_stores_a_heartbeat_only(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    for alias in ("user_prompt", "text", "message", "input"):
        payload = {alias: "No, stop breaking the build!", "session_id": f"s-{alias}", "cwd": str(repo)}
        assert _hook_entry(repo, hb_home, json.dumps(payload)) == (0, "", "")
    rows = read_insight_rows(repo, home=hb_home)
    assert [r["event"] for r in rows] == ["heartbeat"] * 4
    assert all(r["cue"] is False and "text" not in r for r in rows)


def test_the_hook_takes_its_session_and_workspace_from_the_canonical_keys_only(tmp_path: Path, hb_home: Path):
    repo = _make_repo(tmp_path / "repo")
    payload = {"prompt": "No, stop breaking the build!", "sessionId": "s-alias", "workspace": str(repo),
               "cwd": str(repo)}
    assert _hook_entry(repo, hb_home, json.dumps(payload)) == (0, "", "")
    rows = read_insight_rows(repo, home=hb_home)
    assert [r["event"] for r in rows] == ["insight"] and "hs" not in rows[0]


_REVIEWED_PYTHON_PATHS = reviewed_python_paths(REPO)


def _python_sources(root: Path = REPO, paths=None) -> tuple:
    # Freeze membership, not contents: edited or missing reviewed files still fail.
    root = type(root)(real_path(root))
    return tuple((root / name, (root / name).read_text(encoding="utf-8"))
                 for name in (_REVIEWED_PYTHON_PATHS if paths is None else paths))


def _defined_names_referenced_outside(module_file: Path, sources, skip) -> set:
    """Identifiers in sources mentioning insights before or after NFKC,
    except ``module_file`` (a package's ``__init__.py``: the whole package) and nodes in ``skip``."""
    sources = tuple(sources)
    check_census_rows(sources)
    inside = module_file.resolve().parent if module_file.name == "__init__.py" else module_file.resolve()
    seen = set()
    for path, text in sources:
        if path.resolve() == inside or inside in path.resolve().parents:
            continue
        # Python normalizes identifiers with NFKC before exposing them in the AST.
        if "insights" not in text and (text.isascii() or "insights" not in unicodedata.normalize("NFKC", text)):
            continue
        tree = ast.parse(text, filename=str(path))
        skipped = {id(n) for top in ast.walk(tree) if isinstance(top, ast.FunctionDef) and top.name in skip
                   for n in ast.walk(top)}
        for node in ast.walk(tree):
            if id(node) in skipped:
                continue
            if isinstance(node, ast.Name):
                seen.add(node.id)
            elif isinstance(node, ast.Attribute):
                seen.add(node.attr)
            elif isinstance(node, ast.alias):
                seen.add(node.name.split(".")[-1])
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.isidentifier():
                seen.add(node.value)  # monkeypatch.setattr(insights, "NAME", ...)
    return seen


@pytest.mark.parametrize("irrelevant", [
    "coincidental_name = 1\n", "invalid syntax (\n", "# \u2500\ninvalid syntax (\n", "# \u00e9\ninvalid syntax (\n",
])
def test_insights_name_scan_skips_sources_without_the_needle(tmp_path: Path, irrelevant: str):
    package = tmp_path / "insights"
    package.mkdir()
    module_file = package / "__init__.py"
    module_file.write_text("# insights: invalid syntax (\n", encoding="utf-8")
    (package / "internal.py").write_text("insights internal syntax (\n", encoding="utf-8")
    (tmp_path / "irrelevant.py").write_text(irrelevant, encoding="utf-8")
    (tmp_path / "caller.py").write_text(
        'from aegis_core.insights import used_alias\n'
        'insights.used_attribute(used_name, "patched_name")\n'
        'def excluded_test():\n    ignored_name()\n', encoding="utf-8",
    )

    sources = _python_sources(tmp_path, ("insights/__init__.py", "insights/internal.py", "irrelevant.py", "caller.py"))
    seen = _defined_names_referenced_outside(module_file, sources, {"excluded_test"})

    assert {"used_alias", "used_attribute", "used_name", "patched_name"} <= seen
    assert "coincidental_name" not in seen
    assert "ignored_name" not in seen


def test_insights_name_scan_counts_nfkc_normalized_consumers(tmp_path: Path):
    source = "from aegis_core.\uff49nsights import capture_suggestion\n"
    assert "insights" not in source
    (tmp_path / "caller.py").write_text(source, encoding="utf-8")
    seen = _defined_names_referenced_outside(tmp_path / "insights.py", _python_sources(tmp_path, ("caller.py",)), set())
    assert "capture_suggestion" in seen


@pytest.mark.parametrize("source", ["insights syntax (\n", "# \uff49nsights\ninvalid syntax (\n"])
def test_insights_name_scan_still_rejects_malformed_candidates(tmp_path: Path, source: str):
    (tmp_path / "caller.py").write_text(source, encoding="utf-8")
    with pytest.raises(SyntaxError):
        _defined_names_referenced_outside(tmp_path / "insights.py", _python_sources(tmp_path, ("caller.py",)), set())


@census_guard(REPO, module_file=__file__, absolute_labels=True)
def test_every_name_in_insights_all_is_used_outside_the_module(monkeypatch: pytest.MonkeyPatch, sources=None):
    real_parse = ast.parse
    parse_count = 0
    parsed = []

    def counted_parse(text, filename):
        nonlocal parse_count
        parse_count += 1
        parsed.append(filename)
        return real_parse(text, filename=filename)

    counted_ast = SimpleNamespace(**vars(ast))
    counted_ast.parse = counted_parse
    monkeypatch.setattr(sys.modules[__name__], "ast", counted_ast)
    used = _defined_names_referenced_outside(
        Path(core_insights.__file__), _python_sources() if sources is None else sources,
        {"test_every_name_in_insights_all_is_used_outside_the_module"},
    )
    assert sorted(set(core_insights.__all__) - used) == []
    assert all(hasattr(core_insights, name) for name in core_insights.__all__)
    assert 0 < parse_count <= INSIGHTS_PARSE_CEILING, (
        f"insights parse census: {parse_count} files; reviewed ceiling {INSIGHTS_PARSE_CEILING}. "
        "Review source additions before raising the ceiling. Parsed files:\n" + "\n".join(parsed)
    )


@pytest.mark.parametrize("indexed", [True, False], ids=["git-index", "gitfile-index"])
def test_insights_census_ignores_files_created_after_collection(tmp_path: Path, indexed: bool):
    """Freeze membership, but reread changed or missing reviewed sources on every attempt."""
    module = tmp_path / "tests" / "unit" / "core" / "test_insights.py"
    module.parent.mkdir(parents=True)
    shutil.copyfile(Path(__file__), module)
    reviewed = tmp_path / "aegis_core" / "reviewed source.py"
    reviewed.parent.mkdir()
    reviewed.write_text("insights.reviewed_name\n", encoding="utf-8")
    ignored = tmp_path / "tools"
    ignored.mkdir()
    (ignored / "outside_census.py").write_text("insights syntax (\n", encoding="utf-8")
    cache = reviewed.parent / "__pycache__"
    cache.mkdir()
    (cache / "cached.py").write_text("insights syntax (\n", encoding="utf-8")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "-f", ".")
    assert b"aegis_core/__pycache__/cached.py" in _git(tmp_path, "ls-files", "-z").stdout.split(b"\0")
    if not indexed:
        (tmp_path / ".git").rename(tmp_path / "metadata")
        (tmp_path / ".git").write_text("gitdir: metadata\n", encoding="utf-8")
    for index in range(81):
        (tmp_path / "tests" / f"untracked_{index}.py").write_text(
            "insights.unreviewed_name\n", encoding="utf-8")
    scope = runpy.run_path(str(module))
    scan = scope["_python_sources"]
    references = scope["_defined_names_referenced_outside"]
    initial = scan()
    assert reviewed in {path for path, _ in initial}
    assert not any("untracked_" in path.name for path, _ in initial)
    assert not any("outside_census" in path.name or "__pycache__" in path.parts for path, _ in initial)
    assert references(module, initial, set()) == {"insights", "reviewed_name"}
    during_scan = tmp_path / "tests" / "created_during_scan.py"

    class InterleavedPath(type(tmp_path)):
        def read_text(self, *args, **kwargs):
            during_scan.write_text("insights.late_name\n", encoding="utf-8")
            return super().read_text(*args, **kwargs)

    assert scan(InterleavedPath(tmp_path)) == initial
    assert during_scan.is_file()
    for directory in (reviewed.parent, tmp_path / "tests"):
        late = directory / "late.py"
        for source in ("insights.late_name\n", "insights syntax (\n"):
            late.write_text(source, encoding="utf-8")
            assert scan() == initial
        late.unlink()
        assert scan() == initial
    reviewed.write_text("insights.changed_name\n", encoding="utf-8")
    assert references(module, scan(), set()) == {"insights", "changed_name"}
    reviewed.write_text("insights syntax (\n", encoding="utf-8")
    for _ in range(2):
        with pytest.raises(SyntaxError) as failure:
            references(module, scan(), set())
        assert failure.value.filename == str(reviewed)
    reviewed.unlink()
    for _ in range(2):
        with pytest.raises(FileNotFoundError) as failure:
            scan()
        assert failure.value.filename == str(reviewed)
    reviewed.write_text("insights.restored_name\n", encoding="utf-8")
    assert references(module, scan(), set()) == {"insights", "restored_name"}


@pytest.fixture(scope="module")
def insights_import_path():
    """Use the parent import layout for the census scenarios."""
    return list(sys.path)


@pytest.fixture(scope="module", params=["parent", "competing-tests"])
def insights_bootstrap_import_path(request, tmp_path_factory):
    paths = list(sys.path)
    if request.param == "competing-tests":
        root = tmp_path_factory.mktemp("competing-tests")
        package = root / "tests"
        package.mkdir()
        (package / "__init__.py").write_text("# Installed tests package without repository modules.\n", encoding="utf-8")
        paths.insert(0, str(root))
    return paths


def test_insights_isolated_import_bootstrap_does_not_load_conftest(insights_bootstrap_import_path):
    program = (
        "from pathlib import Path\n"
        "import tests\n"
        "assert Path(tests.__path__[0]) == Path(sys.argv[2])\n"
        "assert 'tests.conftest' not in sys.modules\n"
        "assert 'tests.unit.core.test_insights' not in sys.modules\n"
        "from tests.unit.core import test_insights\n"
        "assert Path(test_insights.__file__).resolve() == Path(sys.argv[3])\n"
    )
    result = _run_isolated(program, REPO / "tests", Path(__file__).resolve(), import_path=insights_bootstrap_import_path)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


@pytest.mark.parametrize("marker", [
    "file", "incomplete", "corrupt-index", "dangling", "missing-head", "corrupt-head",
    "gitfile-missing", "gitfile-not-directory", "gitfile-empty", "gitfile-multiline",
    "gitfile-blank-line", "gitfile-nul", "gitfile-oversized",
])
def test_insights_census_refuses_an_unreadable_index(tmp_path: Path, marker: str, insights_import_path):
    _git(tmp_path, "init", "-q")
    checkout = tmp_path / "checkout"
    module = checkout / "tests" / "unit" / "core" / "test_insights.py"
    module.parent.mkdir(parents=True)
    shutil.copyfile(Path(__file__), module)
    metadata = checkout / ".git"
    if marker == "file":
        metadata.write_text("not a git directory\n", encoding="utf-8")
    elif marker == "incomplete":
        metadata.mkdir()
    elif marker == "dangling":
        symlink_or_skip(checkout / "missing.git", metadata, target_is_directory=True)
    elif marker.startswith("gitfile-"):
        target = tmp_path / ".git"
        if marker == "gitfile-missing":
            target = checkout / "missing.git"
        elif marker == "gitfile-not-directory":
            target = checkout / "ordinary-file"
            target.write_text("not a directory\n", encoding="utf-8")
        pointer = b"gitdir: " + os.fsencode(target)
        contents = {
            "gitfile-empty": b"gitdir: \n",
            "gitfile-multiline": pointer + b"\njunk\n",
            "gitfile-blank-line": pointer + b"\n\n",
            "gitfile-nul": pointer + b"\0ignored\n",
        }
        metadata.write_bytes(pointer + b"\n" * GITFILE_MAX_BYTES if marker == "gitfile-oversized"
                             else contents.get(marker, pointer + b"\n"))
    else:
        _git(checkout, "init", "-q")
        if marker == "corrupt-index":
            (metadata / "index").write_bytes(b"corrupt index\n")
        elif marker == "missing-head":
            (metadata / "HEAD").unlink()
        else:
            (metadata / "HEAD").write_text("corrupt head\n", encoding="utf-8")
    env = _git_environment()
    env.pop("GIT_CEILING_DIRECTORIES", None)
    program = (
        "import runpy, subprocess\n"
        "for attempt in range(2):\n"
        "    try:\n"
        "        runpy.run_path(sys.argv[2])\n"
        "    except subprocess.CalledProcessError as failure:\n"
        "        assert failure.returncode == 128, failure.returncode\n"
        "    else:\n"
        "        raise AssertionError('broken Git marker was not refused')\n"
    )
    result = _run_isolated(program, module, env=env, import_path=insights_import_path)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


@pytest.mark.parametrize("layout,relative,ending", [
    ("linked", False, "\n"), ("linked", True, "\r\n"),
    ("submodule", False, ""), ("submodule", True, "\n"),
], ids=["linked-absolute-lf", "linked-relative-crlf", "submodule-absolute-eof", "submodule-relative-lf"])
def test_insights_census_accepts_gitfiles(tmp_path: Path, layout: str, relative: bool, ending: str,
                                        insights_import_path):
    origin = _make_repo(tmp_path / "origin")
    module = origin / "tests" / "unit" / "core" / "test_insights.py"
    module.parent.mkdir(parents=True)
    shutil.copyfile(Path(__file__), module)
    consumer = origin / "aegis_core" / "consumer.py"
    consumer.parent.mkdir()
    consumer.write_text("insights.gitfile_consumer\n", encoding="utf-8")
    _git(origin, "add", "-f", ".")
    _git(origin, "commit", "-q", "-m", "census fixture")
    if layout == "linked":
        checkout = tmp_path / "linked checkout"
        _git(origin, "worktree", "add", "-q", "-b", "linked", str(checkout))
    else:
        container = _make_repo(tmp_path / "container")
        _git(container, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(origin), "sub checkout")
        checkout = container / "sub checkout"
    marker = checkout / ".git"
    assert marker.is_file()
    pointer = marker.read_text(encoding="utf-8").removeprefix("gitdir: ").rstrip("\r\n")
    git_dir = (checkout / pointer).resolve()
    assert git_dir.is_dir()
    pointer = os.path.relpath(git_dir, checkout) if relative else str(git_dir)
    marker.write_bytes(os.fsencode("gitdir: " + pointer + ending))
    module = checkout / "tests" / "unit" / "core" / "test_insights.py"
    program = (
        "import runpy\n"
        "from pathlib import Path\n"
        "module = Path(sys.argv[2])\n"
        "scope = runpy.run_path(str(module))\n"
        "for attempt in range(2):\n"
        "    sources = scope['_python_sources']()\n"
        "    assert {path.relative_to(scope['REPO']).as_posix() for path, _ in sources} == "
        "{'aegis_core/consumer.py', 'tests/unit/core/test_insights.py'}\n"
        "    seen = scope['_defined_names_referenced_outside'](module, sources, set())\n"
        "    assert seen == {'insights', 'gitfile_consumer'}, seen\n"
        "    result = scope['_git'](scope['REPO'], 'ls-files', '--cached')\n"
        "    assert result.args[1] == '--git-dir=' + sys.argv[3], result.args\n"
        "    assert result.args[2] == '--work-tree=' + str(scope['REPO']), result.args\n"
    )
    result = _run_isolated(program, module, git_dir, import_path=insights_import_path)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


@pytest.mark.parametrize("stage", ["open", "read"])
def test_insights_gitfile_read_failure_is_refused(tmp_path: Path, stage: str):
    repo = _make_repo(tmp_path / "repo")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / ".git").write_text("gitdir: " + str(repo / ".git") + "\n", encoding="utf-8")
    opened = []

    class UnreadableFile:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def read(self, size):
            assert 0 < size <= GITFILE_MAX_BYTES + 1
            raise OSError(errno.EIO, "unreadable Git marker")

    class UnreadablePath(type(tmp_path)):
        def open(self, *args, **kwargs):
            if self.name == ".git":
                if stage == "open":
                    raise PermissionError(errno.EACCES, "unreadable Git marker")
                stream = super().open(*args, **kwargs)
                opened.append(stream)
                return UnreadableFile(stream)
            return super().open(*args, **kwargs)

    for _ in range(2):
        with pytest.raises(subprocess.CalledProcessError) as failure:
            _git(UnreadablePath(checkout), "ls-files", "--cached")
        assert failure.value.returncode == 128
        assert failure.value.stderr == b"invalid Git marker\n"
        assert all(stream.closed for stream in opened)


def test_insights_git_environment_drops_all_inherited_git_controls():
    inherited = {key: "hostile" for name in (*LOCAL_ENV, "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_EXEC_PATH")
                 for key in (name, name.lower())}
    inherited.update({"PATH": "kept", "GIT_CONFIG_NOSYSTEM": "0", "GIT_TERMINAL_PROMPT": "1"})
    before = dict(inherited)
    env = _git_environment(inherited)
    assert inherited == before
    assert env == {"PATH": "kept", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"}


def test_insights_git_fixtures_ignore_ambient_configuration(tmp_path: Path, insights_import_path):
    ignored = tmp_path / "ignore"
    ignored.write_text("__pycache__/\napp.py\n", encoding="utf-8")
    config = tmp_path / "hostile.gitconfig"
    config.write_text("[core]\n\tautocrlf = true\n\tsafecrlf = true\n\texcludesFile = "
                      + ignored.as_posix() + "\n", encoding="utf-8")
    env = _git_environment()
    env.update({"GIT_CONFIG_GLOBAL": str(config), "GIT_CONFIG_SYSTEM": str(config), "GIT_CONFIG_NOSYSTEM": "0",
                "PYTHONSAFEPATH": "1"})
    program = (
        "import runpy\n"
        "from pathlib import Path\n"
        "scope = runpy.run_path(sys.argv[2])\n"
        "for attempt in range(2):\n"
        "    root = Path(sys.argv[3]) / str(attempt)\n"
        "    repo = scope['_make_repo'](root / 'repo')\n"
        "    assert b'app.py' in scope['_git'](repo, 'ls-files').stdout.splitlines()\n"
        "    scope['test_insights_census_ignores_files_created_after_collection'](root / 'census', True)\n"
    )
    result = _run_isolated(program, Path(__file__), tmp_path / "attempts", env=env, import_path=insights_import_path)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


@pytest.mark.parametrize("count", [1, 42, 80])
def test_insights_census_accepts_additions_within_reviewed_ceiling(tmp_path, count):
    text = "from aegis_core.insights import " + ", ".join(core_insights.__all__) + "\n"
    sources = [(f"tests/reviewed_{index}.py", text) for index in range(count)]
    result = run_census_fixture(tmp_path, "test_insights.py", sources)
    assert result.returncode == 0, result.stderr.decode()


def test_insights_census_ceiling_failure_lists_every_parsed_file(tmp_path):
    text = "from aegis_core.insights import " + ", ".join(core_insights.__all__) + "\n"
    sources = [(f"tests/reviewed_{index}.py", text) for index in range(81)]
    result = run_census_fixture(tmp_path, "test_insights.py", sources)
    assert result.returncode != 0
    message = result.stderr.decode()
    assert "insights parse census: 81 files; reviewed ceiling 80." in message
    assert all(str(tmp_path / path) in message for path, _ in sources)


def test_insights_census_ceiling_is_independent_of_working_directory(insights_import_path, tmp_path):
    program = (
        "from pathlib import Path\n"
        "from tests.unit.core import test_insights as module\n"
        "for count in (1, 42, 80):\n"
        "    module.test_insights_census_accepts_additions_within_reviewed_ceiling(Path(sys.argv[2]) / str(count), count)\n"
        "module.test_insights_census_ceiling_failure_lists_every_parsed_file(Path(sys.argv[2]) / 'over')\n"
    )
    result = _run_isolated(program, tmp_path, cwd=REPO / "aegis_core" / "insights", import_path=insights_import_path)
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


def _tree_snapshot(root: Path) -> dict:
    return {path.relative_to(root).as_posix(): path.read_bytes() if path.is_file() else None
            for path in root.rglob("*")}


@pytest.fixture(scope="module")
def insights_selector_checkout(tmp_path_factory):
    """Own index containing a consumer absent from an earlier external index."""
    tmp_path = tmp_path_factory.mktemp("insights-selector")
    checkout = tmp_path / "checkout"
    module = checkout / "tests" / "unit" / "core" / "test_insights.py"
    module.parent.mkdir(parents=True)
    shutil.copyfile(Path(__file__), module)
    package = checkout / "aegis_core"
    package.mkdir()
    (package / "reviewed.py").write_text("# insights\n", encoding="utf-8")
    _git(checkout, "init", "-q")
    _git(checkout, "add", "-f", ".")
    external_index = tmp_path / "external-index"
    shutil.copyfile(checkout / ".git" / "index", external_index)
    (package / "consumer.py").write_text("insights.selector_consumer\n", encoding="utf-8")
    _git(checkout, "add", "-f", "aegis_core/consumer.py")
    external = tmp_path / "external"
    external.mkdir()
    _git(external, "init", "-q")
    _git(external, "config", "core.bare", "true")
    return module, external_index, external, external_index.read_bytes(), _tree_snapshot(external / ".git")


@pytest.mark.parametrize("selector", ["GIT_INDEX_FILE", "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "combined", "all-local"])
@pytest.mark.parametrize("operation", ["census", "fixture"])
def test_insights_census_and_fixture_ignore_inherited_git_selectors(
        tmp_path: Path, insights_selector_checkout, selector: str, operation: str, insights_import_path):
    module, external_index, external, index_before, external_before = insights_selector_checkout
    env = _git_environment()
    if selector == "all-local":
        env.update({key: "invalid-inherited-selector" for key in LOCAL_ENV})
    redirects = {"GIT_INDEX_FILE": str(external_index), "GIT_DIR": str(external / ".git"), "GIT_WORK_TREE": str(external),
                 "GIT_COMMON_DIR": str(external / ".git")}
    if selector != "all-local":
        env.update(redirects if selector == "combined" else {selector: redirects[selector]})
    env["PYTHONSAFEPATH"] = "1"
    assert external_index.read_bytes() == index_before
    assert _tree_snapshot(external / ".git") == external_before
    program = (
        "import runpy\n"
        "from pathlib import Path\n"
        "module = Path(sys.argv[2])\n"
        "scope = runpy.run_path(str(module))\n"
        "for attempt in range(2):\n"
        "    common = scope['_git'](scope['REPO'], 'rev-parse', '--git-common-dir').stdout.decode().strip()\n"
        "    assert Path(common).resolve() == (scope['REPO'] / '.git').resolve(), 'Git common directory leaked'\n"
        "    if sys.argv[4] == 'census':\n"
        "        seen = scope['_defined_names_referenced_outside'](module, scope['_python_sources'](), set())\n"
        "        assert 'selector_consumer' in seen\n"
        "    else:\n"
        "        scope['test_insights_census_ignores_files_created_after_collection'](Path(sys.argv[3]) / str(attempt), True)\n"
    )
    result = _run_isolated(program, module, tmp_path / "attempts", operation, env=env, import_path=insights_import_path)
    assert external_index.read_bytes() == index_before, "fixture changed the caller's external index"
    assert _tree_snapshot(external / ".git") == external_before, "fixture changed the external Git directory"
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


def test_dead_insight_names_are_gone():
    for name in ("INSIGHT_LEVELS", "tfidf_cosine", "MAX_EXCERPT_CHARS"):
        assert name not in core_insights.__all__
        assert not hasattr(core_insights, name), name
    assert "hook" not in core_insights.COUNTABLE_LEVELS


_OVERLAP_TEXT = "Stop touching yaml settings in the release scheduler worker"
_YAML_BODY = "Never call yaml.load on configuration files; use yaml.safe_load for parsing settings."


def _overlap_repo(tmp_path: Path, frontmatter: str) -> Path:
    repo = _make_repo(tmp_path / "repo")
    (repo / ".aegis" / "rules" / "traps" / "trap-no-yaml-load.md").write_text(
        f"---\nid: trap-no-yaml-load\ntype: trap\nenforcement: advisory\n{frontmatter}"
        f"hypothesis: Prevent recurring defect in trap-no-yaml-load.\n---\n# trap-no-yaml-load\n\n{_YAML_BODY}\n",
        encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "rule")
    return repo


def _match_of(review: dict, insight_id: str) -> tuple:
    """(matched rule or None, similarity to the closest rule) of one insight in a review."""
    for entry in review["insights"] + review["suppressed"]:
        if entry["id"] == insight_id:
            return entry["match"]["rule"], entry["match"]["similarity"]
    raise AssertionError(f"{insight_id} is not in the review")


def _similarity(repo: Path, home: Path, text: str) -> float:
    """The similarity the review reports for ``text`` against the one rule when it matches."""
    import shutil

    probe = home.parent / "probe-home"
    shutil.rmtree(probe, ignore_errors=True)
    probe.mkdir()
    row = add_insight(repo, text, paths=["src/x.py"], home=probe)
    return _match_of(review_insights(repo, home=probe), row["id"])[1]


def test_a_forbid_ast_rule_does_not_match_an_insight_about_a_test_file(tmp_path: Path, hb_home: Path):
    repo = _overlap_repo(tmp_path, "target_paths:\n  - '**/*.py'\nforbid_ast:\n  calls: [eval]\n")
    s = _similarity(repo, hb_home, _OVERLAP_TEXT)
    assert 0.15 <= s < 0.30, s  # a shared path is needed for this similarity to match
    src = add_insight(repo, _OVERLAP_TEXT, paths=["src/x.py"], home=hb_home)
    test = add_insight(repo, _OVERLAP_TEXT, paths=["tests/x.py"], home=hb_home)
    review = review_insights(repo, home=hb_home)
    assert _match_of(review, src["id"])[0] == "trap-no-yaml-load"
    assert _match_of(review, test["id"])[0] is None


def test_a_rule_without_target_paths_overlaps_no_insight_path(tmp_path: Path, hb_home: Path):
    repo = _overlap_repo(tmp_path, "")
    from aegis_core.rules import load_rules

    assert load_rules(repo).get("trap-no-yaml-load").target_paths == ()
    probe = add_insight(repo, _OVERLAP_TEXT, paths=[], home=hb_home)  # no paths: overlaps every rule
    row = add_insight(repo, _OVERLAP_TEXT, paths=["src/x.py"], home=hb_home)
    review = review_insights(repo, home=hb_home)
    assert _match_of(review, probe["id"])[0] == "trap-no-yaml-load"
    assert 0.15 <= _match_of(review, probe["id"])[1] < 0.30
    assert _match_of(review, row["id"])[0] is None


def test_a_rule_scoped_to_src_does_not_overlap_an_insight_about_tests(tmp_path: Path, hb_home: Path):
    repo = _overlap_repo(tmp_path, "target_paths:\n  - 'src/*.py'\n")
    s = _similarity(repo, hb_home, _OVERLAP_TEXT)
    assert 0.15 <= s < 0.30, s
    row = add_insight(repo, _OVERLAP_TEXT, paths=["tests/x.py"], home=hb_home)
    assert _match_of(review_insights(repo, home=hb_home), row["id"])[0] is None


def test_an_insight_without_paths_overlaps_every_rule(tmp_path: Path, hb_home: Path):
    repo = _overlap_repo(tmp_path, "target_paths:\n  - 'src/*.py'\n")
    row = add_insight(repo, _OVERLAP_TEXT, home=hb_home)  # a clean tree: no dirty paths
    assert row["paths"] == []
    match = _match_of(review_insights(repo, home=hb_home), row["id"])
    assert match[0] == "trap-no-yaml-load" and 0.15 <= match[1] < 0.30


# ── X-w8-carry j: the private directories get their mode through a descriptor ──

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX symlinks and mode bits")


@posix_only
def test_a_link_swapped_in_after_the_check_is_never_chmodded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Given ~/.aegis a directory, When a link to another directory replaces it at the first look
    before its mode is set (the mkdir that finds it, an lstat or the descriptor open), Then the
    link is refused and its target keeps its mode."""
    home = tmp_path / "home"
    aegis = home / ".aegis"
    aegis.mkdir(parents=True, mode=0o755)
    victim = tmp_path / "victim"
    victim.mkdir()
    os.chmod(victim, 0o755)
    real_mkdir, real_lstat, real_open, swapped = Path.mkdir, os.lstat, os.open, []

    def swap(path) -> None:
        if os.fspath(path) == str(aegis) and not swapped:
            swapped.append(True)
            os.rename(aegis, tmp_path / "moved")
            os.symlink(victim, aegis)

    def mkdir_then_swap(self, *args, **kwargs):
        try:
            return real_mkdir(self, *args, **kwargs)
        finally:
            swap(self)

    def lstat_then_swap(path, *args, **kwargs):
        found = real_lstat(path, *args, **kwargs)
        swap(path)
        return found

    def swap_then_open(path, *args, **kwargs):
        swap(path)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", mkdir_then_swap)
    monkeypatch.setattr(os, "lstat", lstat_then_swap)
    monkeypatch.setattr(os, "open", swap_then_open)
    refused = False
    try:
        create_link_key(home)
    except PathTraversalError:
        refused = True
    assert swapped, "no link was swapped in: the test no longer reaches the step that sets the mode"
    assert stat.S_IMODE(os.stat(victim).st_mode) == 0o755
    assert not (victim / "link.key").exists() and refused


@posix_only
def test_the_private_directories_end_0o700_and_a_linked_one_is_refused(tmp_path: Path):
    home = tmp_path / "home"
    (home / ".aegis").mkdir(parents=True, mode=0o755)
    os.chmod(home / ".aegis", 0o755)
    create_link_key(home)
    assert stat.S_IMODE(os.stat(home / ".aegis").st_mode) == 0o700
    other = tmp_path / "other"
    victim = tmp_path / "victim"
    victim.mkdir()
    os.chmod(victim, 0o755)
    other.mkdir()
    (other / ".aegis").symlink_to(victim)
    with pytest.raises(PathTraversalError):
        create_link_key(other)
    assert stat.S_IMODE(os.stat(victim).st_mode) == 0o755 and list(victim.iterdir()) == []


# ── R-evidence-b2: the similarity thresholds are named once (hand-set, not measured) ──

def test_the_similarity_thresholds_are_named_constants():
    from aegis_core.insights import RECURRENCE_SIM, RULE_MATCH_SIM, RULE_MATCH_SIM_WITH_PATH

    assert (RULE_MATCH_SIM_WITH_PATH, RULE_MATCH_SIM, RECURRENCE_SIM) == (0.15, 0.30, 0.12)


def test_rule_matching_flips_at_the_shared_path_threshold(tmp_path: Path, hb_home: Path,
                                                           monkeypatch: pytest.MonkeyPatch):
    repo = _overlap_repo(tmp_path, "target_paths:\n  - 'src/*.py'\n")
    row = add_insight(repo, _OVERLAP_TEXT, paths=["src/x.py"], home=hb_home)
    rule, s = _match_of(review_insights(repo, home=hb_home), row["id"])
    assert rule == "trap-no-yaml-load" and 0 < s < core_insights.RULE_MATCH_SIM
    monkeypatch.setattr(core_insights.review, "RULE_MATCH_SIM_WITH_PATH", s + 0.001)
    assert _match_of(review_insights(repo, home=hb_home), row["id"])[0] is None
    monkeypatch.setattr(core_insights.review, "RULE_MATCH_SIM_WITH_PATH", s - 0.001)
    assert _match_of(review_insights(repo, home=hb_home), row["id"])[0] == "trap-no-yaml-load"


def test_rule_matching_flips_at_the_no_shared_path_threshold(tmp_path: Path, hb_home: Path,
                                                              monkeypatch: pytest.MonkeyPatch):
    repo = _overlap_repo(tmp_path, "target_paths:\n  - 'src/*.py'\n")
    row = add_insight(repo, _OVERLAP_TEXT, paths=["docs/x.md"], home=hb_home)
    assert _match_of(review_insights(repo, home=hb_home), row["id"])[0] is None
    monkeypatch.setattr(core_insights.review, "RULE_MATCH_SIM", 0.0001)
    rule, s = _match_of(review_insights(repo, home=hb_home), row["id"])
    assert rule == "trap-no-yaml-load" and s > 0.0001
    monkeypatch.setattr(core_insights.review, "RULE_MATCH_SIM", s + 0.001)
    assert _match_of(review_insights(repo, home=hb_home), row["id"])[0] is None
    monkeypatch.setattr(core_insights.review, "RULE_MATCH_SIM", s - 0.001)
    assert _match_of(review_insights(repo, home=hb_home), row["id"])[0] == "trap-no-yaml-load"


def test_recurrence_counts_an_insight_at_the_recurrence_threshold(tmp_path: Path, hb_home: Path,
                                                                   monkeypatch: pytest.MonkeyPatch):
    repo = _make_repo(tmp_path / "repo")
    _put_rule(repo, "trap-rec")
    _prompt(repo, hb_home, session="s-rec")
    (repo / "app.py").write_text("a = 2\n", encoding="utf-8")  # the hook's paths are the dirty set
    _prompt(repo, hb_home, "No, stop adding a scheduler loop around Popen in app.py", session="s-rec")
    monkeypatch.setattr(core_insights.recurrence, "RECURRENCE_SIM", 0.0001)
    assert measure_recurrence(repo, "trap-rec", home=hb_home)["recurrences"] == 1
    monkeypatch.setattr(core_insights.recurrence, "RECURRENCE_SIM", 1.01)
    assert measure_recurrence(repo, "trap-rec", home=hb_home)["recurrences"] == 0


def test_an_insight_without_tokens_matches_nothing_and_raises_nothing(tmp_path: Path, hb_home: Path):
    repo = _overlap_repo(tmp_path, "")
    row = add_insight(repo, "the and of", paths=[], home=hb_home)
    review = review_insights(repo, home=hb_home)
    assert _match_of(review, row["id"]) == (None, 0.0)
    assert {e["id"]: e["neighbours"] for e in review["insights"]} == {row["id"]: []}


# ── R-structure-32: insights is a package of four modules with the module's surface ──

# aegis_core.insights.__all__ on the w14 merge commit (e7e61536), when insights was one module. One
# string: listed names would count as uses in test_every_name_in_insights_all_is_used_outside_the_module.
W14_ALL = tuple("""
    CaptureLimitReached INSIGHT_HOOK_MARKER JOIN_WINDOW_S KEY_SIZE MAX_CAPTURES_PER_SESSION RECURRENCE_DENOMINATOR
    RECURRENCE_SIM RULE_MATCH_SIM RULE_MATCH_SIM_WITH_PATH SUPPORTED_INSIGHT_HOSTS add_insight capture_suggestion
    create_link_key dirty_paths effective_capture has_correction_cue host_capture_status insight_born_rules
    insight_status insight_status_lines insight_workspace_id insights_path measure_recurrence merge_insight_hook
    read_insight_rows read_link_key record_decision record_hook_prompt redact_insight_text remove_insight_hook
    review_insights session_hs write_proposal
""".split())
# The public names that module defined outside __all__ (the names it imported are not kept).
W14_DEFINED = tuple("""
    BURST_WINDOW_SECONDS COUNTABLE_LEVELS DECISIONS INSIGHT_SCHEMA_VERSION MAX_CAPTURE_PATHS MAX_CAPTURE_PATH_CHARS
    RECURRENCE_ALARM_COUNT REJECTION_RESURFACE_COUNT
""".split())
# Each module may import only the ones before it; none imports the package itself.
INSIGHT_MODULES = ("keys", "capture", "review", "recurrence")


def unresolved_exports(module) -> list:
    """The names in ``module.__all__`` that ``module`` does not bind."""
    return [name for name in getattr(module, "__all__", ()) if not hasattr(module, name)]


def test_the_package_exports_every_name_the_module_exported():
    assert sorted(core_insights.__all__) == sorted(W14_ALL)
    assert unresolved_exports(core_insights) == []
    assert [name for name in W14_DEFINED if not hasattr(core_insights, name)] == []


def test_an_export_the_module_does_not_bind_is_named(tmp_path: Path):
    import importlib.util

    pkg = tmp_path / "fixture_exports"
    pkg.mkdir()
    (pkg / "__init__.py").write_bytes(b'__all__ = ["present", "missing"]\npresent = 1\n')
    spec = importlib.util.spec_from_file_location("fixture_exports", pkg / "__init__.py",
                                                  submodule_search_locations=[str(pkg)])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert unresolved_exports(module) == ["missing"]


def test_insights_is_a_package_of_four_modules():
    assert not (REPO / "aegis_core" / "insights.py").exists()
    names = [Path(name).name for name in reviewed_python_paths(REPO)
             if Path(name).parent.as_posix() == "aegis_core/insights"]
    assert sorted(names) == sorted(["__init__.py", *(f"{m}.py" for m in INSIGHT_MODULES)])
    assert hasattr(core_insights, "__path__")


def _insight_imports(source: str) -> set:
    """The insights modules ``source`` imports, anywhere in it; "__init__" for the package itself."""
    found = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = ("aegis_core.insights" + (f".{node.module}" if node.module else "")) if node.level else node.module
            names = [f"{base}.{a.name}" if base == "aegis_core.insights" else str(base) for a in node.names]
        else:
            continue
        for name in names:
            parts = name.split(".")
            if parts[:2] == ["aegis_core", "insights"]:
                found.add(parts[2] if len(parts) > 2 and parts[2] in INSIGHT_MODULES else "__init__")
    return found


def _import_path(edges: dict, start: str, goal: str):
    paths = [[start]]
    while paths:
        path = paths.pop(0)
        if path[-1] == goal:
            return path
        paths += [path + [nxt] for nxt in sorted(edges.get(path[-1], ())) if nxt not in path]
    return None


def layering_violations(sources: dict) -> list:
    """Each import of a later insights module, or of the package, with the cycle it closes."""
    edges = {name: sorted(_insight_imports(src) - {name}) for name, src in sources.items()}
    edges["__init__"] = list(INSIGHT_MODULES)  # the package imports every module
    found = []
    for name in INSIGHT_MODULES:
        for target in edges.get(name, ()):
            if target == "__init__" or INSIGHT_MODULES.index(target) > INSIGHT_MODULES.index(name):
                back = _import_path(edges, target, name)
                cycle = f" (cycle: {' -> '.join([name, *back])})" if back else ""
                found.append(f"aegis_core.insights.{name} imports {target}{cycle}")
    return found


def _module_tricks(source: str) -> list:
    tree = ast.parse(source)
    found = [n.name for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ("__getattr__", "__dir__")]
    for node in ast.walk(tree):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(
            node, (ast.AugAssign, ast.AnnAssign)) else []
        found += [ast.unparse(t) for t in targets if (isinstance(t, ast.Attribute) and t.attr == "__class__")
                  or (isinstance(t, ast.Subscript) and isinstance(t.value, ast.Attribute) and t.value.attr == "modules")]
    return found


def test_the_package_is_layered_and_its_init_is_plain():
    """Given the package, When its modules are parsed, Then keys imports no sibling, capture only
    keys, review only those two and recurrence only those three, none imports the package; the
    __init__ has an __all__, and no file serves names lazily or swaps a module object."""
    pkg = REPO / "aegis_core" / "insights"
    sources = {name: (pkg / f"{name}.py").read_text(encoding="utf-8") for name in INSIGHT_MODULES}
    assert layering_violations(sources) == []
    init = (pkg / "__init__.py").read_text(encoding="utf-8")
    assert "__all__" in {t.id for n in ast.parse(init).body if isinstance(n, ast.Assign)
                         for t in n.targets if isinstance(t, ast.Name)}
    assert {name: _module_tricks(src) for name, src in {**sources, "__init__": init}.items()
            if _module_tricks(src)} == {}


def test_an_import_against_the_layering_is_named_with_its_cycle():
    keys_up = {"keys": "from aegis_core.insights.capture import has_correction_cue\n",
               "capture": "from aegis_core.insights.keys import insights_path\n", "review": "", "recurrence": ""}
    assert layering_violations(keys_up) == [
        "aegis_core.insights.keys imports capture (cycle: keys -> capture -> keys)"]
    via_package = {"keys": "", "capture": "def cap():\n    from aegis_core.insights import MAX_CAPTURES_PER_SESSION\n",
                   "review": "", "recurrence": ""}
    assert layering_violations(via_package) == [
        "aegis_core.insights.capture imports __init__ (cycle: capture -> __init__ -> capture)"]
    assert _module_tricks("import sys\nsys.modules[__name__] = 1\ndef __getattr__(name):\n    pass\n") == [
        "__getattr__", "sys.modules[__name__]"]


# Aegis modules a fresh interpreter held on the w14 merge commit (e7e61536) after
# `import aegis_core.insights`, then one plain hook prompt, then one cue prompt with excerpts
# (a workspace without rule files). The cue prompt loaded the scanner stack for redaction.
_S0_IMPORT = frozenset({
    "aegis_core", "aegis_core._version", "aegis_core.atomicio", "aegis_core.errors", "aegis_core.gitsafe",
    "aegis_core.insights", "aegis_core.pathlookup", "aegis_core.primitives", "aegis_core.rule_inventory",
    "aegis_core.storage", "aegis_core.taxonomy", "aegis_core.workspace", "aegis_core.workspace.binding",
    "aegis_core.workspace.layout",
})
S0 = {
    "import": _S0_IMPORT,
    "prompt": _S0_IMPORT | {"aegis_core.config"},
    "cue": _S0_IMPORT | {"aegis_core.config", "aegis_core.verification", "aegis_core.verification.scanners",
                         "aegis_core.verification.test_runner"},
}
# The storage split accompanies storage at all three hook stages.
NEW_MODULES = frozenset({
    "aegis_core.pathlookup_gitcache",
    "aegis_core.redaction", "aegis_core.storage_shared",
    # Reviewed PROPOSAL-CLEAN-DELETED-VIEW round 3c: coordinator importtime measured
    # 3.6-6.4 ms of regex compilation moved from redaction.py into this leaf.
    "aegis_core.redaction_patterns",
                         "aegis_core.gitsafe_run",
                         "aegis_core.gitsafe_policy",
                         *(f"aegis_core.insights.{m}" for m in INSIGHT_MODULES),
    "aegis_core.team_supervisor_start",
    })
REVIEW_ONLY = frozenset({"aegis_core.credit", "aegis_core.human_gate", "aegis_core.rules",
                         "aegis_core.scan_compliance", "aegis_core.telemetry_engine.ledger"})
_HOOK_PATH = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
from pathlib import Path

def loaded():
    return sorted(m for m in sys.modules if m.split(".")[0] in ("aegis_cli", "aegis_core", "aegis_mcp", "aegis_sdk"))

import aegis_core.insights as insights
found = {"import": loaded()}
ws, home = sys.argv[2], Path(sys.argv[3])
insights.record_hook_prompt("claude-code", {"prompt": "Please run the tests.", "session_id": "s1", "cwd": ws},
                            workspace=ws, home=home)
found["prompt"] = loaded()
row = insights.record_hook_prompt("claude-code", {"prompt": "No, stop breaking the build again.", "session_id": "s1",
                                                  "cwd": ws}, workspace=ws, excerpts=True, home=home)
assert row.get("event") == "insight", row
found["cue"] = loaded()
sys.stdout.write(json.dumps(found))
"""


def _child_env(home: Path) -> dict:
    env = {"HOME": str(home), "USERPROFILE": str(home), "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""), "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(home / ".gitconfig")}
    if "GIT_CEILING_DIRECTORIES" in os.environ:
        env["GIT_CEILING_DIRECTORIES"] = os.environ["GIT_CEILING_DIRECTORIES"]
    return env


def unexpected_modules(loaded, before) -> list:
    return sorted(set(loaded) - set(before) - NEW_MODULES)


def test_the_hook_path_loads_no_module_it_did_not_load_before(tmp_path: Path, hb_home: Path):
    """Given a fresh interpreter, When it imports aegis_core.insights and records a plain and a cue
    prompt, Then each step loads only what it loaded on the w14 tree, the redaction module and the
    four insights modules, and never a review-only module."""
    ws = tmp_path / "ws"
    (ws / ".aegis").mkdir(parents=True)
    proc = subprocess.run([sys.executable, "-I", "-c", _HOOK_PATH, str(REPO), str(ws), str(hb_home)], input=b"",
                          capture_output=True, env=_child_env(hb_home), cwd=str(ws), timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    found = json.loads(proc.stdout.decode("utf-8"))
    assert {step: unexpected_modules(found[step], S0[step]) for step in S0} == {step: [] for step in S0}
    assert {step: sorted(REVIEW_ONLY & set(found[step])) for step in S0} == {step: [] for step in S0}


def test_a_heavy_module_on_the_hook_path_is_named():
    loaded = S0["prompt"] | {"aegis_core.insights.capture", "aegis_core.human_gate"}
    assert unexpected_modules(loaded, S0["prompt"]) == ["aegis_core.human_gate"]


def test_round8b_empty_path_cues_keep_the_fresh_hook_import_set(tmp_path: Path, hb_home: Path):
    workspace = tmp_path / "ws"
    (workspace / ".aegis").mkdir(parents=True)
    program = r"""
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from aegis_core import insights
from aegis_core.errors import PathTraversalError
from aegis_core.insights.capture import clean_insight_row

workspace, home = Path(sys.argv[2]), Path(sys.argv[3])
module = "aegis_core.workspace.confinement"
def loaded():
    return sorted(name for name in sys.modules if name.startswith("aegis_"))

found = {"import": loaded()}
insights.record_hook_prompt("claude-code", {"prompt": "Please run the tests.", "session_id": "safe"},
                            workspace=workspace, home=home)
found["prompt"] = loaded()
def cue(_index):
    row = insights.record_hook_prompt("claude-code", {"prompt": "No, stop repeating the same edit.", "session_id": "safe"},
                                      workspace=workspace, home=home)
    assert row["event"] == "insight" and row["paths"] == []
for attempt in range(2):
    cue(attempt)
    found["cue" + str(attempt)] = loaded()
with ThreadPoolExecutor(max_workers=3) as pool:
    list(pool.map(cue, range(6)))
found["parallel"] = loaded()
assert clean_insight_row({}, workspace=object()) == {}
assert clean_insight_row({"paths": []}, workspace=workspace) == {"paths": []}
assert clean_insight_row({"paths": ()}, workspace=workspace) == {"paths": []}
found["empty"] = loaded()
for attempt in range(2):
    try:
        clean_insight_row({"paths": ["../outside"]}, workspace=workspace)
    except PathTraversalError as refusal:
        assert str(refusal) == "invalid insight path"
    else:
        raise AssertionError("nonempty paths bypassed confinement")
assert clean_insight_row({"paths": ["app.py"]}, workspace=workspace) == {"paths": ["app.py"]}
found["nonempty"] = loaded()
sys.stdout.write(json.dumps(found))
"""
    result = _run_isolated(program, workspace, hb_home, env=_child_env(hb_home))
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    found = json.loads(result.stdout)
    confinement = "aegis_core.workspace.confinement"
    assert all(confinement not in found[step] for step in ("import", "prompt", "cue0", "cue1", "parallel", "empty"))
    assert {step: sorted(set(found[step]) - set(found["prompt"]))
            for step in ("cue0", "cue1", "parallel", "empty")} == {
                step: [] for step in ("cue0", "cue1", "parallel", "empty")}
    assert confinement in found["nonempty"]


_APPEND = r"""
import sys
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from aegis_core.insights import record_hook_prompt

ws, home, tag = sys.argv[2], Path(sys.argv[3]), sys.argv[4]
sys.stdin.buffer.read(1)  # both processes start appending together
for i in range(50):
    record_hook_prompt("claude-code", {"prompt": "Please run the tests.", "session_id": f"{tag}-{i}", "cwd": ws},
                       workspace=ws, excerpts=False, home=home)
"""


def test_two_processes_appending_at_once_leave_100_whole_rows(tmp_path: Path, hb_home: Path):
    """Sad path: Given two processes with one HOME, each recording 50 prompts of 50 sessions, When
    both finish, Then the log holds 100 heartbeats (one per prompt without rule files), every line
    a JSON object, no skipped line and no torn tail."""
    from aegis_core.storage import read_jsonl

    ws = tmp_path / "ws"
    (ws / ".aegis").mkdir(parents=True)
    create_link_key(hb_home)  # made here: what two first prompts do to a missing key is another matter
    procs = [subprocess.Popen([sys.executable, "-I", "-c", _APPEND, str(REPO), str(ws), str(hb_home), tag],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=_child_env(hb_home), cwd=str(ws))
             for tag in ("a", "b")]
    for proc in procs:
        proc.stdin.write(b"g")
        proc.stdin.flush()
    for proc in procs:
        _, err = proc.communicate(timeout=120)
        assert proc.returncode == 0, err.decode("utf-8", "replace")
    path = insights_path(ws, home=hb_home)
    lines = path.read_bytes().splitlines()
    assert len(lines) == 100 and all(isinstance(json.loads(line), dict) for line in lines)
    read = read_jsonl(path)
    assert (len(read.rows), read.skipped_lines, read.torn_tail) == (100, [], False)
    assert {r["event"] for r in read.rows} == {"heartbeat"} and len({r["hs"] for r in read.rows}) == 100


_HOLD = r"""
import sys, time
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from aegis_core.storage import file_lock

with file_lock(Path(sys.argv[2])):
    sys.stdout.reconfigure(newline=sys.argv[4])
    sys.stdout.write("held\n")
    sys.stdout.flush()
    time.sleep(float(sys.argv[3]))
"""


@pytest.mark.timing
@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
def test_a_prompt_waits_out_a_lock_held_past_5s_and_keeps_its_row(tmp_path: Path, hb_home: Path, newline):
    """Sad path, deterministic stand-in for the two-process race above (which once lost a row to
    a 5 s LockTimeoutError under suite load): Given another process holding the insight log's
    lock for 6 s, longer than file_lock's generic 5 s, When a prompt is recorded, Then it waits
    for the lock instead of raising, and its heartbeat is appended whole."""
    import time

    from aegis_core.storage import read_jsonl

    ws = tmp_path / "ws"
    (ws / ".aegis").mkdir(parents=True)
    create_link_key(hb_home)
    prompt = {"prompt": "Please run the tests.", "cwd": str(ws)}
    record_hook_prompt("claude-code", {**prompt, "session_id": "s-0"}, workspace=ws, excerpts=False, home=hb_home)
    path = insights_path(ws, home=hb_home)
    holder = subprocess.Popen([sys.executable, "-I", "-c", _HOLD, str(REPO), str(path.with_suffix(".lock")), "6", newline],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=_child_env(hb_home), cwd=str(ws))
    try:
        assert holder.stdout.readline() in (b"held\n", b"held\r\n"), holder.stderr.read().decode("utf-8", "replace")
        started = time.monotonic()
        record_hook_prompt("claude-code", {**prompt, "session_id": "s-1"}, workspace=ws, excerpts=False, home=hb_home)
        assert time.monotonic() - started > 5.0  # it really waited past the generic budget
    finally:
        _, err = holder.communicate(timeout=60)
    assert holder.returncode == 0, err.decode("utf-8", "replace")
    read = read_jsonl(path)
    assert (len(read.rows), read.skipped_lines, read.torn_tail) == (2, [], False)
    assert [r["event"] for r in read.rows] == ["heartbeat", "heartbeat"]
