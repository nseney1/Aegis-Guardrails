"""`aegis sync` (ADR 0005 D1, D3): the one writer of derived state, .aegis/state/derived.json.

sync rebuilds the derived view of every rule from the rule files and the ledger
under the one lock and suggests lifecycle transitions; only `--apply` moves a rule.
The sha256 index it records is LF-normalized and is used only to report rules edited
since the last sync: it never excludes a rule.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aegis_core import sync
from aegis_core.fitness import MIN_N, wilson_lower_bound
from aegis_core.rules import lf_digest, load_rules
from aegis_core.telemetry_engine import ledger

OLD = "2026-01-01"  # created long enough ago to be promotable


def _rule(ws: Path, rule_type: str, rule_id: str, created: str = OLD, eol: str = "\n") -> Path:
    directory = {"trap": "traps", "invariant": "invariants", "gate": "gates", "persona": "personas"}[rule_type]
    path = ws / ".aegis" / "rules" / directory / f"{rule_id}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    enforcement = "gate" if rule_type in ("invariant", "gate") else "advisory"
    text = (
        f"---\nid: {rule_id}\ntype: {rule_type}\nenforcement: {enforcement}\nhypothesis: h\n"
        f"created: '{created}'\ntarget_paths:\n  - src/*.py\n---\nBody.\n"
    )
    path.write_bytes(text.replace("\n", eol).encode("utf-8"))
    return path


def _report(ws: Path, rule_id: str, outcome: str, n: int) -> None:
    ledger.append(ws, [
        {"rule": rule_id, "outcome": outcome, "source": "ci", "key": f"{rule_id}-{outcome}-{i}"} for i in range(n)
    ])


def _rule_bytes(ws: Path) -> dict:
    root = ws / ".aegis" / "rules"
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    _rule(tmp_path, "trap", "trap-good")       # 25 tp: promote
    _rule(tmp_path, "invariant", "inv-noisy")  # MIN_N fp: demote
    _rule(tmp_path, "trap", "trap-noisy")      # MIN_N fp, no lower tier: archive
    _rule(tmp_path, "persona", "persona-new")  # no evidence: nothing
    _report(tmp_path, "trap-good", "tp", 25)
    _report(tmp_path, "inv-noisy", "fp", MIN_N)
    _report(tmp_path, "trap-noisy", "fp", MIN_N)
    return tmp_path


def test_sync_writes_the_derived_view_of_every_rule(ws: Path) -> None:
    before = _rule_bytes(ws)

    result = sync.sync(ws)

    path = ws / ".aegis" / "state" / "derived.json"
    assert result.path == path and result.applied == [] and result.refused is None
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc == result.derived
    assert (doc["v"], doc["norm"]) == (1, "lf")
    assert set(doc["rules"]) == {"trap-good", "inv-noisy", "trap-noisy", "persona-new"}
    good = doc["rules"]["trap-good"]
    assert good["path"] == ".aegis/rules/traps/trap-good.md"
    assert good["sha256"] == lf_digest((ws / good["path"]).read_bytes())
    assert (good["type"], good["triggers"], good["tp"], good["fp"]) == ("trap", 25, 25, 0)
    assert good["fitness"] == pytest.approx(wilson_lower_bound(25, 25), abs=1e-4)
    assert isinstance(good["last_ts"], str)
    assert {rid: e["suggestion"] for rid, e in doc["rules"].items()} == {
        "trap-good": "promote", "inv-noisy": "demote", "trap-noisy": "archive", "persona-new": None,
    }
    assert doc["errors"] == [] and doc["ignored"] == []
    # A dry sync never touches a rule file.
    assert _rule_bytes(ws) == before


def test_apply_moves_rules_through_the_lifecycle_functions_and_records_the_result(ws: Path) -> None:
    rows_before = len(ledger.read(ws).rows)

    result = sync.sync(ws, apply=True)

    actions = {a["rule"]: (a["action"], a["status"]) for a in result.applied}
    assert actions == {
        "trap-good": ("promote", "promoted"),
        "inv-noisy": ("demote", "demoted"),
        "trap-noisy": ("archive", "archived"),
    }
    rules = ws / ".aegis" / "rules"
    assert (rules / "invariants" / "trap-good.md").is_file() and not (rules / "traps" / "trap-good.md").exists()
    assert (rules / "traps" / "inv-noisy.md").is_file()
    assert (rules / ".archive" / "trap-noisy.md").is_file()
    # The view is rebuilt after the moves, and the ledger is never rewritten.
    doc = result.derived
    assert doc["rules"]["trap-good"]["path"] == ".aegis/rules/invariants/trap-good.md"
    assert "trap-noisy" not in doc["rules"]
    assert json.loads((ws / ".aegis" / "state" / "derived.json").read_text(encoding="utf-8")) == doc
    assert len(ledger.read(ws).rows) == rows_before


def test_apply_refuses_while_any_rule_cannot_be_loaded(ws: Path) -> None:
    broken = ws / ".aegis" / "rules" / "traps" / "broken.md"
    broken.write_text("---\nid: [unterminated\n---\nb\n", encoding="utf-8")
    before = _rule_bytes(ws)

    result = sync.sync(ws, apply=True)

    assert result.applied == []
    assert result.refused and "broken.md" in result.refused
    assert _rule_bytes(ws) == before
    assert result.derived["errors"] == [
        {"path": ".aegis/rules/traps/broken.md", "error": "malformed YAML frontmatter: unterminated flow sequence"},
    ]
    assert "broken" not in result.derived["rules"]


def test_ignored_files_are_recorded(ws: Path) -> None:
    (ws / ".aegis" / "rules" / "notes.md").write_text("# notes\n", encoding="utf-8")
    doc = sync.sync(ws).derived
    assert doc["ignored"] == [{"path": ".aegis/rules/notes.md", "reason": "not a rule: it is not in a rule type directory"}]


def test_stale_rules_report_what_changed_since_the_last_sync(ws: Path) -> None:
    assert sync.stale_rules(load_rules(ws), sync.read_derived(ws)) == []  # never synced: nothing to compare
    sync.sync(ws)
    assert sync.stale_rules(load_rules(ws), sync.read_derived(ws)) == []

    edited = ws / ".aegis" / "rules" / "traps" / "trap-good.md"
    edited.write_text(edited.read_text(encoding="utf-8").replace("Body.", "Edited body."), encoding="utf-8")
    _rule(ws, "trap", "trap-added")
    (ws / ".aegis" / "rules" / "personas" / "persona-new.md").unlink()

    stale = sync.stale_rules(load_rules(ws), sync.read_derived(ws))

    assert stale == [
        {"id": "trap-added", "path": ".aegis/rules/traps/trap-added.md", "change": "new"},
        {"id": "trap-good", "path": ".aegis/rules/traps/trap-good.md", "change": "edited"},
        {"id": "persona-new", "path": ".aegis/rules/personas/persona-new.md", "change": "removed"},
    ]


def test_a_line_ending_flip_is_not_an_edit(tmp_path: Path) -> None:
    """The index is LF-normalized: a CRLF checkout of the same rule is not stale."""
    path = _rule(tmp_path, "trap", "eol")
    sync.sync(tmp_path)
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))

    assert sync.stale_rules(load_rules(tmp_path), sync.read_derived(tmp_path)) == []


def test_an_unreadable_derived_file_counts_as_never_synced(tmp_path: Path) -> None:
    _rule(tmp_path, "trap", "t")
    state = tmp_path / ".aegis" / "state"
    state.mkdir(parents=True)
    for garbage in (b"not json", b"[1, 2]", b'{"v": 1, "rules": []}', b"\xff\xfe"):
        (state / "derived.json").write_bytes(garbage)
        assert sync.read_derived(tmp_path) is None
        assert sync.stale_rules(load_rules(tmp_path), sync.read_derived(tmp_path)) == []


def test_a_derived_file_reached_through_a_symlink_is_not_read(tmp_path: Path) -> None:
    from tests.conftest import symlink_or_skip

    _rule(tmp_path, "trap", "t")
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text(json.dumps(sync.build(tmp_path)), encoding="utf-8")
    (tmp_path / ".aegis" / "state").mkdir(parents=True)
    symlink_or_skip(elsewhere, tmp_path / ".aegis" / "state" / "derived.json")

    assert sync.read_derived(tmp_path) is None


def test_an_expired_rule_is_recorded_as_expired(tmp_path: Path) -> None:
    _rule(tmp_path, "trap", "current")
    retired = _rule(tmp_path, "trap", "retired")
    retired.write_text(retired.read_text(encoding="utf-8").replace("hypothesis: h\n", "hypothesis: h\nexpired_at: '2026-01-01'\n"), encoding="utf-8")

    rules = sync.build(tmp_path)["rules"]

    assert rules["retired"]["expired"] is True
    assert "expired" not in rules["current"]


def test_a_crlf_rule_is_recorded_by_its_lf_digest(tmp_path: Path) -> None:
    """Recorded from a CRLF checkout, the rule is not stale once the line endings flip back."""
    path = _rule(tmp_path, "trap", "eol", eol="\r\n")

    doc = sync.sync(tmp_path).derived

    assert doc["rules"]["eol"]["sha256"] == hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n"))
    assert sync.stale_rules(load_rules(tmp_path), sync.read_derived(tmp_path)) == []


def test_a_rule_moved_with_unchanged_bytes_is_reported_edited(tmp_path: Path) -> None:
    text = b"---\nid: moved\nhypothesis: h\ntarget_paths:\n  - src/*.py\n---\nBody.\n"
    old = tmp_path / ".aegis" / "rules" / "traps" / "moved.md"
    old.parent.mkdir(parents=True)
    old.write_bytes(text)
    sync.sync(tmp_path)
    new = tmp_path / ".aegis" / "rules" / "invariants" / "moved.md"
    new.parent.mkdir(parents=True)
    old.replace(new)

    assert sync.stale_rules(load_rules(tmp_path), sync.read_derived(tmp_path)) == [
        {"id": "moved", "path": ".aegis/rules/invariants/moved.md", "change": "edited"},
    ]


def test_a_rule_that_stopped_loading_is_reported_unloadable_not_removed(ws: Path) -> None:
    sync.sync(ws)
    (ws / ".aegis" / "rules" / "traps" / "trap-good.md").write_text("---\nid: [unterminated\n---\nb\n", encoding="utf-8")

    stale = sync.stale_rules(load_rules(ws), sync.read_derived(ws))

    assert stale == [{
        "id": "trap-good",
        "path": ".aegis/rules/traps/trap-good.md",
        "change": "unloadable",
        "error": "malformed YAML frontmatter: unterminated flow sequence",
    }]


def test_rules_that_apply_to_no_file_are_recorded(ws: Path) -> None:
    """A served rule without target_paths (or with a scope key v4 does not read) matches
    nothing: sync says so instead of indexing it as if it applied somewhere."""
    rules = ws / ".aegis" / "rules"
    (rules / "traps" / "trap-unscoped.md").write_text("---\nid: trap-unscoped\nhypothesis: h\n---\nB\n", encoding="utf-8")
    (rules / "invariants" / "inv-scope.md").write_text(
        "---\nid: inv-scope\nenforcement: gate\nscope: src\nhypothesis: h\n---\nB\n", encoding="utf-8"
    )

    doc = sync.sync(ws).derived

    assert doc["untargeted"] == [
        {"id": "inv-scope", "path": ".aegis/rules/invariants/inv-scope.md"},
        {"id": "trap-unscoped", "path": ".aegis/rules/traps/trap-unscoped.md"},
    ]
    assert {"trap-unscoped", "inv-scope"} <= set(doc["rules"])  # still indexed: never excluded


# ── An incomplete ledger: fitness is shown, but nothing moves on partial evidence ──

CLEAN_LEDGER = {"skipped_lines": [], "unusable_rows": 0, "error": None, "torn_tail": False}


def _garble(ws: Path, rule_id: str, outcome: str) -> list:
    """Overwrite the rule's ``outcome`` rows with unreadable lines; their line numbers."""
    path = ledger.ledger_path(ws)
    lines = path.read_bytes().split(b"\n")
    hit = []
    for index, line in enumerate(lines):
        row = json.loads(line) if line else {}
        if row.get("rule") == rule_id and row.get("outcome") == outcome:
            lines[index] = b'{"v": 2, "rule": garbled'
            hit.append(index + 1)
    path.write_bytes(b"\n".join(lines))
    return hit


def test_the_ledger_read_is_recorded_with_the_derived_view(ws: Path) -> None:
    assert sync.sync(ws).derived["ledger"] == CLEAN_LEDGER


def test_apply_refuses_when_unreadable_ledger_lines_hide_evidence(tmp_path: Path) -> None:
    """20 tp and 4 fp: no suggestion. With the tp lines unreadable the 4 fp alone say
    archive; applying that would park a good rule on partial evidence."""
    _rule(tmp_path, "trap", "good")
    _report(tmp_path, "good", "tp", 20)
    _report(tmp_path, "good", "fp", 4)
    assert sync.sync(tmp_path).derived["rules"]["good"]["suggestion"] is None
    garbled = _garble(tmp_path, "good", "tp")
    assert len(garbled) == 20
    before = _rule_bytes(tmp_path)

    result = sync.sync(tmp_path, apply=True)

    assert result.applied == []
    assert result.refused == (
        "not applied: the ledger is incomplete (20 unreadable line(s)); "
        "fitness and suggestions are computed over partial evidence"
    )
    assert _rule_bytes(tmp_path) == before
    assert result.derived["ledger"] == dict(CLEAN_LEDGER, skipped_lines=garbled)
    assert json.loads((tmp_path / ".aegis" / "state" / "derived.json").read_text(encoding="utf-8"))["ledger"] == result.derived["ledger"]


def _unusable_row(ws: Path) -> str:
    with ledger.ledger_path(ws).open("ab") as fh:
        fh.write(b'{"v": 2, "rule": "trap-good", "outcome": "tp", "weight": "lots"}\n')
    return "1 unusable row(s)"


def _unreadable_ledger(ws: Path) -> str:
    path = ledger.ledger_path(ws)
    path.unlink()
    path.mkdir()
    return "cannot read"


@pytest.mark.parametrize("damage", [_unusable_row, _unreadable_ledger], ids=["unusable-row", "unreadable"])
def test_apply_refuses_on_any_ledger_damage(ws: Path, damage) -> None:
    reason = damage(ws)
    before = _rule_bytes(ws)

    result = sync.sync(ws, apply=True)

    assert result.applied == [] and _rule_bytes(ws) == before
    assert result.refused.startswith("not applied: the ledger is incomplete (") and reason in result.refused
    assert result.derived["ledger"] != CLEAN_LEDGER


def test_a_torn_last_line_is_a_write_in_progress_and_does_not_block_apply(ws: Path) -> None:
    with ledger.ledger_path(ws).open("ab") as fh:
        fh.write(b'{"v": 2, "rule": "trap-go')

    result = sync.sync(ws, apply=True)

    assert result.refused is None
    assert {a["rule"] for a in result.applied} == {"trap-good", "inv-noisy", "trap-noisy"}
    assert result.derived["ledger"] == dict(CLEAN_LEDGER, torn_tail=True)


def test_a_young_rule_is_not_promoted_however_good_its_evidence(tmp_path: Path) -> None:
    created = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%d")
    _rule(tmp_path, "trap", "young", created=created)
    _report(tmp_path, "young", "tp", 40)
    assert sync.sync(tmp_path).derived["rules"]["young"]["suggestion"] is None
