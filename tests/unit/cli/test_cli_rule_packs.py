"""`aegis rule export` and `aegis rule import`: unsigned rule packs at the command line (v4.2 #3).

The core contract is tested in tests/unit/core/test_packs.py. Here: arguments, exit codes
(0 done, 1 refused with nothing written, 2 usage), the machine-readable envelope, the
unsigned notice, a terminal that never receives a pack's control sequences, and the
hermetic HOME every CLI test runs with (tests/unit/cli/conftest.py).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List

import pytest

from aegis_cli.cli import main
from aegis_core import events, packs
from aegis_core.taxonomy import RULE_TYPE_DIRS
from aegis_core.yaml_engine.serializer import dump_frontmatter
from tests.helpers_rule import write_evidence

TS = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


def _text(rule_id: str, rule_type: str = "trap", **extra: Any) -> str:
    meta: Dict[str, Any] = {
        "id": rule_id, "type": rule_type,
        "enforcement": "gate" if rule_type in ("invariant", "gate") else "advisory",
        "hypothesis": f"Test rule {rule_id}", "target_paths": ["src/**/*.py"],
    }
    meta.update(extra)
    return dump_frontmatter(meta, body=f"# {rule_id}\nBody.\n")


def _workspace(root: Path, **rules: str) -> Path:
    """A workspace holding the named rules: ``name`` is ``<type>:<id>``."""
    (root / ".aegis" / "rules").mkdir(parents=True)
    for spec in rules:
        rule_type, rule_id = spec.split("__", 1)
        path = root / ".aegis" / "rules" / RULE_TYPE_DIRS[rule_type] / f"{rule_id}.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_text(rule_id, rule_type), encoding="utf-8")
    return root.resolve()


@pytest.fixture
def src(tmp_path: Path) -> Path:
    return _workspace(tmp_path / "src", trap__one="", invariant__two="")


@pytest.fixture
def dst(tmp_path: Path) -> Path:
    return _workspace(tmp_path / "dst")


def _tree(root: Path) -> List[str]:
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames:
            found.append(os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/") + "/")
        for name in filenames:
            full = os.path.join(dirpath, name)
            found.append(f"{os.path.relpath(full, root).replace(os.sep, '/')}:{hashlib.sha256(Path(full).read_bytes()).hexdigest()[:12]}")
    return sorted(found)


def _run(capsys, *argv: str):
    rc = main(list(argv))
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def _export(capsys, ws: Path, out: Path, *extra: str):
    return _run(capsys, "rule", "export", str(out), "--workspace", str(ws), *extra)


def _write_pack(path: Path, *entries: Dict[str, Any]) -> Path:
    rules = list(entries)
    pack = {"v": 1, "rules": rules, "sha256": packs.bundle_digest(rules)}
    path.write_bytes(json.dumps(pack).encode("utf-8"))
    return path


def _entry(path: str, text: str) -> Dict[str, Any]:
    return {"path": path, "text": text, "sha256": packs.text_digest(text)}


def _envelope_ok(doc: Dict[str, Any], source: str, ws: Path) -> None:
    from aegis_core._version import __version__

    assert doc["source"] == source
    assert doc["aegis_version"] == __version__
    assert TS.match(doc["checked_at"])
    assert doc["scope"]["workspace"] == str(ws)


# ── export ───────────────────────────────────────────────────────────────────

def test_export_writes_a_pack_that_load_pack_accepts_and_says_it_is_unsigned(src, tmp_path, capsys):
    out = tmp_path / "pack.json"
    rc, stdout, stderr = _export(capsys, src, out)
    assert (rc, stderr) == (0, "")
    pack = packs.load_pack(out.read_bytes())
    assert [e["path"] for e in pack["rules"]] == ["invariants/two.md", "traps/one.md"]
    assert f"Exported 2 rules to {out}" in stdout
    assert "invariants/two.md" in stdout and "traps/one.md" in stdout
    assert f"The pack is unsigned: its sha256 ({pack['sha256'][:12]}) shows it was not altered after export" in stdout
    assert "not who made it" in stdout


def test_export_json_carries_the_envelope_and_the_rules(src, tmp_path, capsys):
    out = tmp_path / "pack.json"
    rc, stdout, _ = _export(capsys, src, out, "--json")
    doc = json.loads(stdout)
    assert rc == 0
    _envelope_ok(doc, "aegis rule export", src)
    assert doc["scope"] == {"workspace": str(src), "types": [], "min_fitness": None}
    pack = packs.load_pack(out.read_bytes())
    assert doc["status"] == "exported" and doc["signed"] is False
    assert doc["out"] == str(out) and doc["sha256"] == pack["sha256"]
    assert doc["rules"] == [
        {"path": "invariants/two.md", "id": "two", "type": "invariant", "sha256": pack["rules"][0]["sha256"]},
        {"path": "traps/one.md", "id": "one", "type": "trap", "sha256": pack["rules"][1]["sha256"]},
    ]
    assert doc["skipped"] == []


def test_export_changes_nothing_in_the_workspace_and_records_no_event(src, tmp_path, capsys):
    before = _tree(src)
    _export(capsys, src, tmp_path / "pack.json")
    assert _tree(src) == before
    assert events.read(src).rows == []


def test_export_filters_by_type_and_records_the_filter_in_scope(src, tmp_path, capsys):
    out = tmp_path / "pack.json"
    rc, stdout, _ = _export(capsys, src, out, "--type", "trap", "--json")
    assert rc == 0
    assert [e["path"] for e in packs.load_pack(out.read_bytes())["rules"]] == ["traps/one.md"]
    assert json.loads(stdout)["scope"]["types"] == ["trap"]


def test_export_takes_several_types(src, tmp_path, capsys):
    out = tmp_path / "pack.json"
    rc, _, _ = _export(capsys, src, out, "--type", "trap", "--type", "invariant")
    assert rc == 0 and len(packs.load_pack(out.read_bytes())["rules"]) == 2


def test_export_filters_by_fitness(src, tmp_path, capsys):
    write_evidence(src, "two", triggers=40, tp=40)
    out = tmp_path / "pack.json"
    rc, stdout, _ = _export(capsys, src, out, "--min-fitness", "0.5", "--json")
    assert rc == 0
    assert [e["path"] for e in packs.load_pack(out.read_bytes())["rules"]] == ["invariants/two.md"]
    assert json.loads(stdout)["scope"]["min_fitness"] == 0.5


def test_export_rejects_an_unknown_type_as_a_usage_error(src, tmp_path, capsys):
    with pytest.raises(SystemExit) as info:
        main(["rule", "export", str(tmp_path / "p.json"), "--workspace", str(src), "--type", "unsupported"])
    assert info.value.code == 2
    assert "invalid choice: 'unsupported'" in capsys.readouterr().err


def test_export_reports_skipped_expired_rules(src, tmp_path, capsys):
    (src / ".aegis/rules/traps/gone.md").write_text(_text("gone", expired_at="2026-01-01"), encoding="utf-8")
    rc, stdout, _ = _export(capsys, src, tmp_path / "pack.json")
    assert rc == 0 and "Skipped: gone (expired)" in stdout
    rc, stdout, _ = _export(capsys, src, tmp_path / "pack2.json", "--json")
    assert json.loads(stdout)["skipped"] == [{"id": "gone", "reason": "expired"}]


def test_export_with_nothing_to_export_writes_no_file(tmp_path, capsys):
    ws = _workspace(tmp_path / "empty")
    out = tmp_path / "pack.json"
    rc, stdout, stderr = _export(capsys, ws, out)
    assert (rc, stdout) == (1, "")
    assert stderr == "Error: no rules to export: none matches the type and fitness filters\n"
    assert not out.exists()


def test_export_refuses_a_broken_rule_and_writes_no_file(src, tmp_path, capsys):
    (src / ".aegis/rules/traps/broken.md").write_text(_text("other"), encoding="utf-8")
    out = tmp_path / "pack.json"
    rc, stdout, stderr = _export(capsys, src, out)
    assert (rc, stdout) == (1, "")
    assert ".aegis/rules/traps/broken.md: id 'other' does not match the file name 'broken'" in stderr
    assert not out.exists()


def test_export_refuses_a_rule_with_derived_keys_and_names_migrate(src, tmp_path, capsys):
    (src / ".aegis/rules/traps/stale.md").write_text(_text("stale", fitness=0.9), encoding="utf-8")
    out = tmp_path / "pack.json"
    rc, _, stderr = _export(capsys, src, out)
    assert rc == 1 and "traps/stale.md still has derived or retired keys (fitness): run aegis migrate --apply" in stderr
    assert not out.exists()


def test_export_json_refusal_is_an_enveloped_document_on_stdout(src, tmp_path, capsys):
    (src / ".aegis/rules/traps/broken.md").write_text(_text("other"), encoding="utf-8")
    rc, stdout, stderr = _export(capsys, src, tmp_path / "pack.json", "--json")
    doc = json.loads(stdout)
    assert (rc, stderr) == (1, "")
    _envelope_ok(doc, "aegis rule export", src)
    assert doc["status"] == "refused"
    assert doc["problems"] == [".aegis/rules/traps/broken.md: id 'other' does not match the file name 'broken'; "
                               "fix or move it, then export again"]
    assert doc["error"] == doc["problems"][0]


def test_export_refuses_an_output_that_is_a_directory_or_has_no_parent(src, tmp_path, capsys):
    rc, _, stderr = _export(capsys, src, tmp_path)
    assert rc == 1 and stderr == f"Error: cannot write the pack: {tmp_path} is a directory\n"
    missing = tmp_path / "nope" / "pack.json"
    rc, _, stderr = _export(capsys, src, missing)
    assert rc == 1 and stderr == f"Error: cannot write the pack: the directory {missing.parent} does not exist\n"
    assert not missing.parent.exists()


def test_export_never_writes_through_a_symlink(src, tmp_path, capsys):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep\n", encoding="utf-8")
    link = tmp_path / "pack.json"
    try:
        os.symlink(str(victim), str(link))
    except (OSError, NotImplementedError):
        if os.name != "nt":
            raise
        pytest.skip("symlinks are unavailable")
    rc, _, stderr = _export(capsys, src, link)
    assert rc == 1 and stderr == f"Error: cannot write the pack: {link} is a symlink\n"
    assert victim.read_text(encoding="utf-8") == "keep\n"


def test_export_replaces_a_pack_file_it_wrote_before(src, tmp_path, capsys):
    out = tmp_path / "pack.json"
    out.write_text("old\n", encoding="utf-8")
    rc, _, _ = _export(capsys, src, out)
    assert rc == 0 and packs.load_pack(out.read_bytes())["v"] == 1


def test_export_outside_a_workspace_is_refused(tmp_path, capsys):
    plain = tmp_path / "plain"
    plain.mkdir()
    rc, stdout, stderr = _export(capsys, plain, tmp_path / "pack.json")
    assert (rc, stdout) == (1, "")
    assert stderr.startswith("Error: ") and "not an Aegis workspace" in stderr


# ── import ───────────────────────────────────────────────────────────────────

def _packed(src: Path, tmp_path: Path, capsys) -> Path:
    out = tmp_path / "pack.json"
    assert _export(capsys, src, out)[0] == 0
    return out


def _import(capsys, ws: Path, pack: Path, *extra: str):
    return _run(capsys, "rule", "import", str(pack), "--workspace", str(ws), *extra)


def test_a_pack_exported_from_one_workspace_imports_into_another_byte_for_byte(src, dst, tmp_path, capsys):
    pack = _packed(src, tmp_path, capsys)
    rc, stdout, stderr = _import(capsys, dst, pack)
    assert (rc, stderr) == (0, "")
    for rel in ("invariants/two.md", "traps/one.md"):
        assert (dst / ".aegis/rules" / rel).read_bytes() == (src / ".aegis/rules" / rel).read_bytes()
    digest = packs.load_pack(pack.read_bytes())["sha256"]
    assert f"Imported 2 rules from {pack} (sha256 {digest[:12]}):" in stdout
    assert "  .aegis/rules/invariants/two.md" in stdout and "  .aegis/rules/traps/one.md" in stdout
    assert "The pack is unsigned: review the imported rules (git diff) before you rely on them, then run aegis sync." in stdout


def test_import_json_carries_the_envelope_and_the_rules(src, dst, tmp_path, capsys):
    pack = _packed(src, tmp_path, capsys)
    rc, stdout, _ = _import(capsys, dst, pack, "--json")
    doc = json.loads(stdout)
    assert rc == 0
    _envelope_ok(doc, "aegis rule import", dst)
    assert doc["scope"] == {"workspace": str(dst), "pack": str(pack), "rename": False, "dry_run": False}
    assert doc["status"] == "imported" and doc["signed"] is False
    assert doc["pack_sha256"] == packs.load_pack(pack.read_bytes())["sha256"]
    assert [(r["path"], r["id"], r["type"], r["renamed_from"]) for r in doc["rules"]] == [
        (".aegis/rules/invariants/two.md", "two", "invariant", None),
        (".aegis/rules/traps/one.md", "one", "trap", None),
    ]
    assert doc["warnings"] == []


def test_import_records_one_pack_import_event(src, dst, tmp_path, capsys):
    _import(capsys, dst, _packed(src, tmp_path, capsys))
    (row,) = events.read(dst, "pack_import").rows
    assert row["result"] == "imported" and row["detail"]["rules"] == 2


def test_import_dry_run_writes_nothing(src, dst, tmp_path, capsys):
    pack = _packed(src, tmp_path, capsys)
    before = _tree(dst)
    rc, stdout, _ = _import(capsys, dst, pack, "--dry-run")
    assert rc == 0 and _tree(dst) == before
    assert f"Dry run: would import 2 rules from {pack}" in stdout and "Nothing was written." in stdout
    rc, stdout, _ = _import(capsys, dst, pack, "--dry-run", "--json")
    doc = json.loads(stdout)
    assert doc["status"] == "dry_run" and doc["scope"]["dry_run"] is True and len(doc["rules"]) == 2
    assert _tree(dst) == before


def test_import_refuses_a_collision_and_names_rename(src, dst, tmp_path, capsys):
    pack = _packed(src, tmp_path, capsys)
    (dst / ".aegis/rules/traps").mkdir()
    (dst / ".aegis/rules/traps/one.md").write_text(_text("one"), encoding="utf-8")
    before = _tree(dst)
    rc, stdout, stderr = _import(capsys, dst, pack)
    assert (rc, stdout) == (1, "")
    assert stderr == ("Error: the pack was not imported:\n"
                      "  rules[1] (traps/one.md): the id 'one' is already used by .aegis/rules/traps/one.md; "
                      "import with --rename to keep both\n")
    assert _tree(dst) == before


def test_import_rename_keeps_both(src, dst, tmp_path, capsys):
    pack = _packed(src, tmp_path, capsys)
    (dst / ".aegis/rules/traps").mkdir()
    (dst / ".aegis/rules/traps/one.md").write_text(_text("one"), encoding="utf-8")
    rc, stdout, _ = _import(capsys, dst, pack, "--rename")
    assert rc == 0
    assert "  .aegis/rules/traps/one-imported.md (renamed from 'one')" in stdout
    assert (dst / ".aegis/rules/traps/one-imported.md").is_file()


def test_import_json_refusal_lists_every_problem(src, dst, tmp_path, capsys):
    pack = _write_pack(tmp_path / "evil.json", _entry("../../x.md", "a"), _entry("unsupported/y.md", "b"))
    rc, stdout, stderr = _import(capsys, dst, pack, "--json")
    doc = json.loads(stdout)
    assert (rc, stderr) == (1, "")
    _envelope_ok(doc, "aegis rule import", dst)
    assert doc["status"] == "refused" and len(doc["problems"]) == 2
    assert doc["problems"][0].startswith("rules[0] ('../../x.md'): the path must be exactly <type dir>/<id>.md")
    assert doc["error"] == "the pack was not imported: 2 problems"


def test_a_pack_with_traversal_paths_writes_nothing_anywhere(src, dst, tmp_path, capsys):
    pack = _write_pack(tmp_path / "evil.json", _entry("../../../evil.md", _text("evil")),
                       _entry("/etc/cron.d/x.md", "y"), _entry(".github/workflows/x.yml", "z"))
    before = _tree(tmp_path)
    rc, _, stderr = _import(capsys, dst, pack)
    assert rc == 1 and "the pack was not imported:" in stderr
    assert _tree(tmp_path) == before


def test_import_prints_at_most_ten_problems_and_counts_the_rest(dst, tmp_path, capsys):
    pack = _write_pack(tmp_path / "evil.json", *[_entry(f"../x{i}.md", "a") for i in range(14)])
    rc, _, stderr = _import(capsys, dst, pack)
    assert rc == 1
    assert stderr.count("rules[") == 10 and stderr.rstrip().endswith("... and 4 more problems")


def test_a_path_with_control_sequences_is_shown_escaped(dst, tmp_path, capsys):
    pack = _write_pack(tmp_path / "evil.json", _entry("traps/\x1b[2Jx.md", "t"))
    rc, stdout, stderr = _import(capsys, dst, pack)
    assert rc == 1 and "the pack was not imported" in stderr
    assert "\\x1b[2J" in stderr  # the escape is shown as text
    for stream in (stdout, stderr):
        assert "\x1b" not in stream


def test_whatever_the_core_says_the_terminal_gets_no_control_sequences(dst, tmp_path, capsys, monkeypatch):
    """The printing layer strips terminal controls from every problem and warning on its own,
    not only because today's messages happen to be escaped."""
    hostile = "bad \x1b]0;pwned\x07\x1b[31mred\x1b[0m text"

    def refuse(*args, **kwargs):
        raise packs.PackError([hostile])

    monkeypatch.setattr(packs, "import_pack", refuse)
    pack = _write_pack(tmp_path / "ok.json", _entry("traps/one.md", _text("one")))
    rc, stdout, stderr = _import(capsys, dst, pack)
    assert rc == 1 and "bad red text" in stderr
    for stream in (stdout, stderr):
        assert "\x1b" not in stream and "\x07" not in stream

    def warn(*args, **kwargs):
        return packs.ImportResult((), False, "0" * 64, (hostile,))

    monkeypatch.setattr(packs, "import_pack", warn)
    rc, stdout, stderr = _import(capsys, dst, pack)
    assert rc == 0 and "bad red text" in stdout + stderr
    for stream in (stdout, stderr):
        assert "\x1b" not in stream and "\x07" not in stream


def test_import_a_missing_file_is_a_clear_refusal(dst, tmp_path, capsys):
    rc, stdout, stderr = _import(capsys, dst, tmp_path / "nope.json")
    assert (rc, stdout) == (1, "")
    assert stderr == f"Error: cannot read the pack: {tmp_path / 'nope.json'} does not exist\n"


def test_import_a_directory_is_a_clear_refusal(dst, tmp_path, capsys):
    rc, _, stderr = _import(capsys, dst, tmp_path)
    assert rc == 1 and stderr == f"Error: cannot read the pack: {tmp_path} is not a regular file\n"


def test_import_reads_at_most_the_size_limit(dst, tmp_path, capsys):
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (packs.MAX_PACK_BYTES + 1))
    rc, _, stderr = _import(capsys, dst, big)
    assert rc == 1 and f"the pack exceeds {packs.MAX_PACK_BYTES} bytes" in stderr


def test_import_not_json_is_a_refusal_not_a_traceback(dst, tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{nope", encoding="utf-8")
    rc, _, stderr = _import(capsys, dst, bad)
    assert rc == 1 and "the pack is not valid JSON" in stderr and "Traceback" not in stderr


def test_import_into_a_directory_that_is_not_a_workspace_is_refused(src, tmp_path, capsys):
    plain = tmp_path / "plain"
    plain.mkdir()
    rc, _, stderr = _import(capsys, plain, _packed(src, tmp_path, capsys))
    assert rc == 1 and "not an Aegis workspace" in stderr
    assert not (plain / ".aegis").exists()


def test_import_json_outside_a_workspace_is_an_enveloped_error(src, tmp_path, capsys):
    pack = _packed(src, tmp_path, capsys)
    plain = tmp_path / "plain"
    plain.mkdir()
    rc, stdout, _ = _import(capsys, plain, pack, "--json")
    doc = json.loads(stdout)
    assert rc == 1 and doc["status"] == "error" and doc["scope"]["workspace"] is None
    assert doc["source"] == "aegis rule import" and "not an Aegis workspace" in doc["error"]


def test_the_home_directory_is_never_touched_by_an_import(src, dst, tmp_path, capsys):
    home = Path(os.environ["HOME"])
    before = _tree(home)
    _import(capsys, dst, _packed(src, tmp_path, capsys))
    assert _tree(home) == before


def test_import_requires_the_workspace_exactly_not_a_walk_up(src, tmp_path, capsys):
    pack = _packed(src, tmp_path, capsys)
    ws = _workspace(tmp_path / "outer")
    inner = ws / "sub"
    inner.mkdir()
    rc, _, stderr = _import(capsys, inner, pack)
    assert rc == 1 and "not an Aegis workspace" in stderr
    assert not (ws / ".aegis/rules/traps").exists()


def test_the_export_and_import_help_say_the_pack_is_unsigned(capsys):
    for action in ("export", "import"):
        with pytest.raises(SystemExit) as info:
            main(["rule", action, "--help"])
        assert info.value.code == 0
        assert "unsigned" in capsys.readouterr().out.lower()
