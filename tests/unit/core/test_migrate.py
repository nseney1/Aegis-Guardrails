"""Supported migration plans preserve modern files and refuse retired state."""
import json
import os
from pathlib import Path
import stat

import pytest

from aegis_core import migrate


def test_a_modern_workspace_needs_no_conversion(tmp_path):
    rules = tmp_path / ".aegis" / "rules" / "traps"
    rules.mkdir(parents=True)
    rule = rules / "trap-x.md"
    rule.write_text("---\nid: trap-x\ntype: trap\n---\nBody\n", encoding="utf-8")
    before = rule.read_bytes()
    planned = migrate.plan(tmp_path)
    assert planned.to_dict()["status"] == "up_to_date"
    assert migrate.apply(planned).written == []
    assert rule.read_bytes() == before


@pytest.mark.parametrize("marker", ["manifest.json", "evidence/signals.jsonl", "slots.yaml", "keys/key", "receipt_key", "evidence/fitness.jsonl", "evidence/sessions_processed.jsonl"])
def test_retired_state_is_refused_without_conversion(tmp_path, marker):
    path = tmp_path / ".aegis" / marker
    path.parent.mkdir(parents=True)
    path.write_text("retained", encoding="utf-8")
    planned = migrate.plan(tmp_path)
    assert ".aegis/" + (marker if marker != "keys/key" else "keys") in planned.refusal
    assert "Archive these paths outside the workspace" in planned.refusal
    with pytest.raises(migrate.MigrationRefused, match="Archive these paths outside the workspace"):
        migrate.apply(planned)
    assert path.read_text(encoding="utf-8") == "retained"


def test_a_symlinked_workspace_is_refused_without_reading_it(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".aegis").symlink_to(outside, target_is_directory=True)
    planned = migrate.plan(root)
    assert planned.refusal == ".aegis is a symlink; aegis migrate reads and writes only inside the workspace"
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("folder,declared", [("invariants", "Invariant"), ("Invariants", "invariant")])
def test_v4_rule_names_are_normalized_and_become_servable(tmp_path, folder, declared):
    from aegis_core.rules import load_rules

    source = tmp_path / ".aegis" / "rules" / folder / "no-eval.md"
    source.parent.mkdir(parents=True)
    source.write_text(f"---\nid: no-eval\ntype: {declared}\nenforcement: gate\n---\nBody\n")
    assert load_rules(tmp_path).errors
    planned = migrate.plan(tmp_path)
    assert planned.pending
    migrate.apply(planned)
    assert load_rules(tmp_path).errors == ()
    assert (tmp_path / ".aegis/rules/invariants/no-eval.md").read_text() == (
        "---\nid: no-eval\ntype: invariant\nenforcement: gate\n---\nBody\n"
    )
    assert not migrate.plan(tmp_path).pending


def test_a_rule_edited_after_planning_is_not_overwritten(tmp_path):
    source = tmp_path / ".aegis/rules/traps/t.md"
    source.parent.mkdir(parents=True)
    source.write_text("---\nid: t\ntype: trap\nscore: 0.4\n---\nBody\n")
    planned = migrate.plan(tmp_path)
    source.write_text(source.read_text() + "An editor saved this.\n")
    before = source.read_bytes()
    assert not (tmp_path / ".aegis/state").exists()
    with pytest.raises(migrate.MigrationRefused) as refusal:
        migrate.apply(planned)
    assert str(refusal.value) == (
        ".aegis/rules/traps/t.md changed since the plan was made; "
        "no rule, config.json or .aegis/.gitignore was changed. Run aegis migrate again."
    )
    assert source.read_bytes() == before
    assert not (tmp_path / ".aegis/config.json").exists()
    assert not (tmp_path / ".aegis/.gitignore").exists()
    assert (tmp_path / ".aegis/state/.gitignore").read_text() == "# Aegis machine-local state; never committed.\n*\n"
    assert (tmp_path / ".aegis/state/lock").is_file()
    assert not list((tmp_path / ".aegis/state").glob("migrate-backup-*"))


def test_customized_drivers_left_by_v4_are_supported(tmp_path):
    from aegis_core.workspace.discovery import unmigrated_state

    driver = tmp_path / ".aegis/drivers/custom.py"
    driver.parent.mkdir(parents=True)
    driver.write_text("# User changes retained by v4\n", encoding="utf-8")
    assert unmigrated_state(tmp_path) == []
    assert migrate.plan(tmp_path).to_dict()["status"] == "up_to_date"


def test_retired_markers_do_not_report_both_a_file_and_its_parent(tmp_path):
    from aegis_core.workspace.discovery import unmigrated_state

    marker = tmp_path / ".aegis/evidence/signals.jsonl"
    marker.parent.mkdir(parents=True)
    marker.write_bytes(b"")
    assert unmigrated_state(tmp_path) == [".aegis/evidence/signals.jsonl"]


@pytest.mark.parametrize("when", ["before_plan", "after_plan"])
def test_oversized_config_refuses_apply_before_allocating_its_contents(tmp_path, when):
    import tracemalloc
    from aegis_core.config import MAX_CONFIG_BYTES

    source = tmp_path / ".aegis/rules/traps/t.md"
    source.parent.mkdir(parents=True)
    original = b"---\nid: t\ntype: trap\nscore: 0.4\n---\nBody\n"
    source.write_bytes(original)
    config = tmp_path / ".aegis/config.json"
    if when == "after_plan":
        planned = migrate.plan(tmp_path)
    with config.open("wb") as stream:
        stream.truncate(16 * 1024 * 1024)
    if when == "before_plan":
        planned = migrate.plan(tmp_path)
        assert planned.unreadable == [".aegis/config.json"]
    tracemalloc.start()
    try:
        with pytest.raises(migrate.MigrationRefused) as refusal:
            migrate.apply(planned)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert str(refusal.value) == (
        f".aegis/config.json exceeds {MAX_CONFIG_BYTES} bytes; "
        "no rule, config.json or .aegis/.gitignore was changed"
    )
    assert peak < 2 * 1024 * 1024
    assert source.read_bytes() == original
    assert config.stat().st_size == 16 * 1024 * 1024
    assert not (tmp_path / ".aegis/.gitignore").exists()


def test_a_normalization_destination_conflict_is_reported_and_skipped(tmp_path):
    for folder in ("Invariant", "invariants"):
        path = tmp_path / ".aegis/rules" / folder / "same.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"---\nid: same\ntype: invariant\n---\n{folder}\n")
    planned = migrate.plan(tmp_path)
    assert planned.refusal is None
    assert planned.to_dict()["conflicts"] == [{"path": ".aegis/rules/Invariant/same.md", "to": ".aegis/rules/invariants/same.md"}]
    migrate.apply(planned)
    assert (tmp_path / ".aegis/rules/Invariant/same.md").is_file()


def test_a_noncanonical_directory_moves_by_declared_type(tmp_path):
    source = tmp_path / ".aegis/rules/trap/t.md"
    source.parent.mkdir(parents=True)
    source.write_text("---\nid: t\ntype: invariant\nenforcement: gate\n---\nBody\n", encoding="utf-8")
    planned = migrate.plan(tmp_path)
    assert planned.to_dict()["rules"] == [{"from": ".aegis/rules/trap/t.md", "to": ".aegis/rules/invariants/t.md", "type": "invariant"}]
    migrate.apply(planned)
    assert not source.exists()
    assert (tmp_path / ".aegis/rules/invariants/t.md").is_file()


def test_a_linked_rule_is_reported_without_blocking_a_ledger_merge(tmp_path):
    from tests import helpers_humangate as hg
    from tests.conftest import symlink_or_skip

    repo = hg.make_repo(tmp_path)
    outside = tmp_path / "outside.md"
    outside.write_text("---\nid: t\ntype: trap\nscore: 1\n---\nBody\n", encoding="utf-8")
    link = repo.root / ".aegis/rules/traps/t.md"
    link.parent.mkdir(parents=True, exist_ok=True)
    symlink_or_skip(outside, link)
    local = repo.root / ".aegis/state/ledger.jsonl"
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_text(json.dumps({"v": 2, "seq": 1, "ts": "2026-10-01T00:00:00Z", "rule": "t", "outcome": "tp", "source": "ci", "key": "k1"}) + "\n")
    planned = migrate.plan(repo.root)
    assert planned.refusal is None
    assert planned.to_dict()["skipped"][0]["path"] == ".aegis/rules/traps/t.md"
    assert migrate.apply(planned).merged == 1
    assert outside.read_text(encoding="utf-8").endswith("Body\n") and link.is_symlink()


@pytest.mark.parametrize("keep_note", [False, True])
def test_hardlinked_case_variant_directories_converge_once(tmp_path, capsys, keep_note):
    from aegis_cli.cli import main
    from aegis_core.rules import load_rules

    old_dir = tmp_path / ".aegis/rules/Invariants"
    target_dir = tmp_path / ".aegis/rules/invariants"
    old_dir.mkdir(parents=True)
    target_dir.mkdir(exist_ok=True)
    if os.path.samefile(old_dir, target_dir):
        pytest.skip("requires distinct case-sensitive directories")
    source, target = old_dir / "t.md", target_dir / "t.md"
    if keep_note:
        (old_dir / "notes.txt").write_text("Keep these notes", encoding="utf-8")
    source.write_text("---\nid: t\ntype: invariant\nscore: 0.4\n---\nBody\n", encoding="utf-8")
    os.link(source, target)
    assert main(["migrate", "--json", "--workspace", str(tmp_path), "--apply"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "applied" and len(report["rules"]) == 1
    assert not source.exists() and old_dir.exists() is keep_note
    assert target.read_text(encoding="utf-8") == "---\nid: t\ntype: invariant\n---\nBody\n"
    assert load_rules(tmp_path).errors == ()
    assert not migrate.plan(tmp_path).pending


def test_a_cleanup_error_is_reported_in_json_with_a_nonzero_exit(tmp_path, capsys, monkeypatch):
    from aegis_cli.cli import main

    source = tmp_path / ".aegis/rules/Invariant/t.md"
    source.parent.mkdir(parents=True)
    source.write_text("---\nid: t\ntype: invariant\n---\nBody\n", encoding="utf-8")
    real_rmdir = Path.rmdir

    def blocked_directory(path):
        if path == source.parent:
            raise OSError("directory cleanup denied")
        return real_rmdir(path)

    monkeypatch.setattr(Path, "rmdir", blocked_directory)
    assert main(["migrate", "--json", "--workspace", str(tmp_path), "--apply"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["skipped"] == [{"path": ".aegis/rules/Invariant/t.md", "reason": "directory cleanup denied"}]
    assert (tmp_path / ".aegis/rules/invariants/t.md").is_file()


def test_a_concurrent_v4_config_is_preserved_when_applying(tmp_path):
    from aegis_core.config import update_repo_config

    source = tmp_path / ".aegis/rules/traps/t.md"
    source.parent.mkdir(parents=True)
    source.write_text("---\nid: t\ntype: trap\nscore: 0.4\n---\nBody\n", encoding="utf-8")
    planned = migrate.plan(tmp_path)
    update_repo_config(tmp_path, lambda data: data.update(hosts=["codex-cli"]))
    before = (tmp_path / ".aegis/config.json").read_bytes()
    migrate.apply(planned)
    assert (tmp_path / ".aegis/config.json").read_bytes() == before
    assert "score:" not in source.read_text(encoding="utf-8")


def test_an_already_canonical_destination_is_not_rewritten(tmp_path):
    source = tmp_path / ".aegis/rules/trap/t.md"
    target = tmp_path / ".aegis/rules/traps/t.md"
    source.parent.mkdir(parents=True)
    target.parent.mkdir()
    text = "---\nid: t\ntype: trap\n---\nBody\n"
    source.write_text(text, encoding="utf-8")
    target.write_text(text, encoding="utf-8")
    target.chmod(0o600)
    os.utime(target, (1000000000, 1000000000))
    before = target.stat()
    planned = migrate.plan(tmp_path)
    assert planned.to_dict()["already_moved"] == [".aegis/rules/trap/t.md"]
    assert planned.to_dict()["rules"] == []
    migrate.apply(planned)
    assert not source.exists() and target.read_text(encoding="utf-8") == text
    assert target.stat().st_mtime_ns == before.st_mtime_ns
    assert stat.S_IMODE(target.stat().st_mode) == stat.S_IMODE(before.st_mode)


def test_a_new_normalization_destination_is_not_overwritten(tmp_path):
    source = tmp_path / ".aegis/rules/Invariant/t.md"
    source.parent.mkdir(parents=True)
    source.write_text("---\nid: t\ntype: invariant\n---\nBody\n")
    planned = migrate.plan(tmp_path)
    target = tmp_path / ".aegis/rules/invariants/t.md"
    target.parent.mkdir()
    target.write_text("new content\n")
    with pytest.raises(migrate.MigrationRefused, match="changed since the plan"):
        migrate.apply(planned)
    assert target.read_text() == "new content\n"
    assert source.exists()


def test_stripping_keeps_every_other_byte_and_hoists_impact_weight(tmp_path: Path):
    root = tmp_path / "ws"
    rule = root / ".aegis" / "rules" / "traps" / "trap-crlf.md"
    rule.parent.mkdir(parents=True)
    original = (
        "---\r\nid: trap-crlf\r\ntype: trap\r\nscore: 0.5\r\nfitness:\r\n  triggers: 3\r\n"
        "  impact_weight: 1.2\r\n  true_positives: 1\r\nlast_trigger_date: '2026-01-01'\r\n"
        "hypothesis: keep me\r\n---\r\nBody\r\n"
    )
    rule.write_bytes(original.encode("utf-8"))

    plan = migrate.plan(root)
    assert {s["path"]: s["keys"] for s in plan.to_dict()["strip"]} == {
        ".aegis/rules/traps/trap-crlf.md": ["fitness", "last_trigger_date", "score"],
    }
    migrate.apply(plan)

    assert rule.read_bytes() == (
        "---\r\nid: trap-crlf\r\ntype: trap\r\nimpact_weight: 1.2\r\nhypothesis: keep me\r\n---\r\nBody\r\n"
    ).encode("utf-8")
    # applying completes the D12 layout around the rules
    assert json.loads((root / ".aegis" / "config.json").read_text(encoding="utf-8")) == {"v": 1}
    assert (root / ".aegis" / ".gitignore").read_text(encoding="utf-8").splitlines()[-1] == "state/"

def test_trigger_keyword_lists_are_rule_content_not_counters(tmp_path: Path):
    root = tmp_path / "ws"
    rule = root / ".aegis" / "rules" / "traps" / "trap-doc.md"
    rule.parent.mkdir(parents=True)
    original = (
        "---\nid: trap-doc\ntype: trap\ntriggers:\n  - documentation_edit\n  - readme_modification\n"
        "score: high\nfitness:\n  score: 0.3333\n  triggers: 63\n---\nBody\n"
    )
    rule.write_text(original, encoding="utf-8")

    plan = migrate.plan(root)
    assert {s["path"]: s["keys"] for s in plan.to_dict()["strip"]} == {".aegis/rules/traps/trap-doc.md": ["fitness"]}
    migrate.apply(plan)

    assert rule.read_text(encoding="utf-8") == (
        "---\nid: trap-doc\ntype: trap\ntriggers:\n  - documentation_edit\n  - readme_modification\n"
        "score: high\n---\nBody\n"
    )

def test_a_rule_with_a_bom_keeps_it(tmp_path: Path):
    root = tmp_path / "ws"
    rule = root / ".aegis" / "rules" / "traps" / "trap-bom.md"
    rule.parent.mkdir(parents=True)
    rule.write_bytes("﻿---\nid: trap-bom\nscore: 0.4\n---\nBody\n".encode("utf-8"))

    migrate.apply(migrate.plan(root))

    assert rule.read_bytes() == "﻿---\nid: trap-bom\n---\nBody\n".encode("utf-8")


@pytest.mark.parametrize("entry", ["state", "config.json"])
def test_v4_state_and_config_links_are_refused(tmp_path, entry):
    from tests.conftest import symlink_or_skip

    outside = tmp_path / "outside"
    outside.mkdir()
    aegis = tmp_path / "repo/.aegis"
    aegis.mkdir(parents=True)
    symlink_or_skip(outside, aegis / entry, target_is_directory=True)
    planned = migrate.plan(aegis.parent)
    assert planned.refusal == f".aegis/{entry} is a symlink; aegis migrate reads and writes only inside the workspace"
    with pytest.raises(migrate.MigrationRefused, match="is a symlink"):
        migrate.apply(planned)
    assert list(outside.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
@pytest.mark.parametrize("mode", [0o600, 0o640])
def test_v4_backups_keep_modes_and_original_bytes(tmp_path, mode):
    source = tmp_path / ".aegis/rules/traps/t.md"
    source.parent.mkdir(parents=True)
    original = b"---\nid: t\ntype: trap\nscore: 0.4\n---\nBody\n"
    source.write_bytes(original)
    source.chmod(mode)
    result = migrate.apply(migrate.plan(tmp_path))
    assert stat.S_IMODE(result.backup.stat().st_mode) == 0o700
    saved = result.backup / ".aegis/rules/traps/t.md"
    assert saved.read_bytes() == original
    assert stat.S_IMODE(saved.stat().st_mode) == mode


def test_an_unreadable_rule_does_not_block_v4_worktree_merge(tmp_path):
    from tests import helpers_humangate as hg
    from aegis_core.telemetry_engine import ledger

    repo = hg.make_repo(tmp_path)
    bad = repo.root / ".aegis/rules/traps/cp1252.md"
    bad.parent.mkdir(parents=True, exist_ok=True)
    raw = b"---\nid: cp1252\ntype: trap\n---\ncaf\xe9\n"
    bad.write_bytes(raw)
    local = repo.root / ".aegis/state/ledger.jsonl"
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_text(json.dumps({"v": 2, "seq": 1, "ts": "2026-10-01T00:00:00Z", "rule": "trap-x", "outcome": "tp", "source": "ci", "key": "k1"}) + "\n")
    planned = migrate.plan(repo.root)
    assert planned.refusal is None
    assert planned.to_dict()["unreadable"] == [".aegis/rules/traps/cp1252.md"]
    assert planned.worktree_pending == 1
    assert migrate.apply(planned).merged == 1
    assert [row["key"] for row in ledger.read(repo.root).rows] == ["k1"]
    assert bad.read_bytes() == raw


def test_strip_only_apply_does_not_touch_the_shared_ledger(tmp_path):
    from tests import helpers_humangate as hg
    from aegis_core import storage

    repo = hg.make_repo(tmp_path)
    path = repo.root / ".aegis/rules/traps/t.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("---\nid: t\ntype: trap\nscore: 0.4\n---\nBody\n")
    planned = migrate.plan(repo.root)
    assert planned.pending and planned.worktree_pending == 0
    shared = storage.ledger_site(repo.root, create=False).path
    assert not shared.exists()
    assert not shared.parent.exists()
    migrate.apply(planned)
    assert not shared.exists()
    assert not shared.parent.exists()
    assert "score:" not in path.read_text()


def test_a_state_entry_link_refuses_a_nothing_pending_plan(tmp_path):
    from tests.conftest import symlink_or_skip

    state = tmp_path / "repo/.aegis/state"
    state.mkdir(parents=True)
    victim = tmp_path / "outside"
    victim.write_text("unchanged")
    symlink_or_skip(victim, state / "entry")
    planned = migrate.plan(state.parent.parent)
    assert planned.to_dict()["status"] == "refused"
    assert ".aegis/state/entry is a symlink" in planned.refusal
    assert victim.read_text() == "unchanged"


def test_a_malformed_config_is_reported_as_unreadable(tmp_path):
    config = tmp_path / ".aegis/config.json"
    config.parent.mkdir()
    config.write_text("{broken")
    planned = migrate.plan(tmp_path)
    assert planned.refusal is None
    assert planned.to_dict()["unreadable"] == [".aegis/config.json"]
    assert config.read_text() == "{broken"
