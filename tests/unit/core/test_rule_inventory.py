"""Regression tests for the rule inventory, the byte snapshot the one loader projects (#19)."""
import os
import time
from types import SimpleNamespace

import pytest

import aegis_core.rule_inventory as rule_inventory_module


def _write_rule(path, rule_id="rule-a"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "---\n"
        f"id: {rule_id}\n"
        "domain: testing\n"
        "type: invariant\n"
        "enforcement: gate\n"
        "target_paths: ['src/*.py']\n"
        "---\n"
        "# Rule\n",
        encoding="utf-8",
    )


def test_inventory_is_stable_and_captures_exact_bytes(tmp_path):
    from aegis_core.rule_inventory import inventory_rules

    first_path = tmp_path / ".aegis" / "rules" / "invariants" / "b.md"
    second_path = tmp_path / ".aegis" / "rules" / "traps" / "a.md"
    _write_rule(first_path, "b")
    _write_rule(second_path, "a")

    first = inventory_rules(str(tmp_path))
    second = inventory_rules(str(tmp_path))

    assert [entry.relative_path for entry in first.entries] == [
        ".aegis/rules/invariants/b.md",
        ".aegis/rules/traps/a.md",
    ]
    assert first.fingerprint == second.fingerprint
    assert first.entries == second.entries
    for entry in first.entries:
        assert os.path.isabs(entry.absolute_path)
        assert entry.size == len(entry.content)
        assert len(entry.digest) == 64
        assert entry.content == open(entry.absolute_path, "rb").read()


def test_rule_edited_after_creation_is_inventoried(tmp_path):
    """BUG-035: on Windows os.stat reports st_ctime as creation time but
    os.fstat reports it as last-change time, so any rule edited after it was
    created was rejected as 'changed before it was opened'."""
    from aegis_core.rule_inventory import inventory_rules

    rule = tmp_path / ".aegis" / "rules" / "invariants" / "edited.md"
    _write_rule(rule, "edited")
    time.sleep(0.05)
    with open(rule, "a", encoding="utf-8") as f:
        f.write("Edited after creation.\n")

    inventory = inventory_rules(str(tmp_path))
    assert [entry.relative_path for entry in inventory.entries] == [
        ".aegis/rules/invariants/edited.md"
    ]
    assert inventory.entries[0].content == rule.read_bytes()
    assert b"Edited after creation." in inventory.entries[0].content


def test_missing_rules_directory_has_stable_empty_inventory(tmp_path):
    from aegis_core.rule_inventory import inventory_rules

    inventory = inventory_rules(str(tmp_path))
    assert inventory.entries == ()
    assert len(inventory.fingerprint) == 64


@pytest.mark.parametrize("alias_root", [False, True], ids=["ancestor", "root"])
def test_inventory_accepts_a_trusted_symlinked_workspace_path(tmp_path, alias_root):
    from aegis_core.rules import load_rules
    from tests.conftest import symlink_or_skip

    root = tmp_path / "trusted" / "workspace"
    _write_rule(root / ".aegis/rules/invariants/rule-a.md")
    alias = tmp_path / "alias"
    symlink_or_skip(root if alias_root else root.parent, alias, target_is_directory=True)
    selected = alias if alias_root else alias / "workspace"
    for _ in range(2):
        ruleset = load_rules(selected)
        assert len(ruleset.rules) == 1
        assert ruleset.rules[0].ok, ruleset.rules[0].error
        assert ruleset.rules[0].id == "rule-a"


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory permissions")
def test_inventory_accepts_a_trusted_execute_only_ancestor(tmp_path):
    from aegis_core.rules import load_rules

    if os.geteuid() == 0:
        pytest.skip("root bypasses directory permissions")
    ancestor = tmp_path / "trusted"
    root = ancestor / "workspace"
    _write_rule(root / ".aegis/rules/invariants/rule-a.md")
    original_mode = ancestor.stat().st_mode
    try:
        ancestor.chmod(0o100)
        for _ in range(2):
            ruleset = load_rules(root)
            assert len(ruleset.rules) == 1
            assert ruleset.rules[0].ok, ruleset.rules[0].error
    finally:
        ancestor.chmod(original_mode)


@pytest.mark.skipif(os.name != "posix" or not hasattr(os, "O_PATH"), reason="requires POSIX O_PATH")
@pytest.mark.parametrize("component", ["workspace", "aegis"])
@pytest.mark.parametrize("oversized", [False, True], ids=["bounded", "oversized"])
def test_inventory_traverses_execute_only_parents(tmp_path, component, oversized):
    from concurrent.futures import ThreadPoolExecutor
    from aegis_core.rules import load_rules

    if os.geteuid() == 0 or not rule_inventory_module.descriptor_supported():
        pytest.skip("requires non-root descriptor traversal")
    root = tmp_path / "workspace"
    path = root / ".aegis/rules/invariants/rule-a.md"
    _write_rule(path)
    if oversized:
        with path.open("ab") as stream:
            stream.write(b"x" * rule_inventory_module.MAX_RULE_BYTES)
    parent = root if component == "workspace" else root / ".aegis"
    original_mode = parent.stat().st_mode

    def read(_):
        ruleset = load_rules(root)
        assert len(ruleset.rules) == 1
        rule = ruleset.rules[0]
        assert rule.id == "rule-a"
        if oversized:
            assert not rule.ok and "too_large" in rule.error
            assert rule.raw == b"" and rule.body == ""
        else:
            assert rule.ok, rule.error
        return ruleset

    try:
        parent.chmod(0o100)
        first = read(None)
        with ThreadPoolExecutor(max_workers=3) as pool:
            assert list(pool.map(read, range(3), timeout=15)) == [first] * 3
        assert read(None) == first
    finally:
        parent.chmod(original_mode)
    assert read(None) == first


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory permissions")
@pytest.mark.parametrize("component", ["readable", "workspace", "aegis"])
def test_inventory_without_o_path_keeps_the_typed_permission_refusal(tmp_path, monkeypatch, component):
    from aegis_core.rules import load_rules

    if os.geteuid() == 0 or not rule_inventory_module.descriptor_supported():
        pytest.skip("requires non-root descriptor traversal")
    root = tmp_path / "workspace"
    _write_rule(root / ".aegis/rules/invariants/rule-a.md")
    capabilities = SimpleNamespace(**{**vars(os)})
    if hasattr(capabilities, "O_PATH"):
        del capabilities.O_PATH
    monkeypatch.setattr(rule_inventory_module, "os", capabilities)
    parent = root / ".aegis" if component == "aegis" else root
    original_mode = parent.stat().st_mode
    try:
        if component != "readable":
            parent.chmod(0o100)
            with pytest.raises(rule_inventory_module.RuleInventoryError) as caught:
                load_rules(root)
            assert caught.value.operation == "open"
        else:
            assert load_rules(root).rules[0].ok
    finally:
        parent.chmod(original_mode)
    assert load_rules(root).rules[0].ok


def test_symlinked_rule_is_rejected(tmp_path):
    from aegis_core.rule_inventory import RuleInventoryError, inventory_rules

    outside = tmp_path / "outside.md"
    _write_rule(outside, "outside")
    link = tmp_path / ".aegis" / "rules" / "invariants" / "linked.md"
    link.parent.mkdir(parents=True)
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")

    with pytest.raises(RuleInventoryError, match="symlink"):
        inventory_rules(str(tmp_path))


def test_symlinked_directory_that_would_feed_the_scan_fails_it_closed(tmp_path):
    from aegis_core.rules import RuleCache
    import aegis_core.scan as scan_service

    outside = tmp_path / "outside" / "invariants"
    _write_rule(outside / "external.md", "external")
    rules_dir = tmp_path / "workspace" / ".aegis" / "rules"
    rules_dir.mkdir(parents=True)
    link = rules_dir / "invariants"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")

    previous = scan_service.RULE_CACHE
    scan_service.RULE_CACHE = RuleCache()
    try:
        result = scan_service.scan(str(tmp_path / "workspace"), changed_files=["src/app.py"])
    finally:
        scan_service.RULE_CACHE = previous
    assert result["status"] == "FAIL"
    assert "symlinked directory is not allowed" in result["error"]
    assert "relevant_rules" not in result


def test_rules_are_matched_to_changed_files(tmp_path):
    from aegis_core.outcomes.engine import match_rules_to_changes

    _write_rule(tmp_path / ".aegis" / "rules" / "invariants" / "test-invariant.md", "test-invariant")

    matches = match_rules_to_changes(tmp_path, ["src/index.py"])
    assert [(m["_name"], m["_matched_files"]) for m in matches] == [("test-invariant", ["src/index.py"])]
    assert match_rules_to_changes(tmp_path, ["other/file.txt"]) == []
    assert match_rules_to_changes(tmp_path, []) == []
    assert match_rules_to_changes(tmp_path / "nonexistent", ["src/index.py"]) == []


def test_inventory_covers_the_workspace_rules_directory(tmp_path):
    from aegis_core.rule_inventory import inventory_rules

    rule = tmp_path / ".aegis" / "rules" / "invariants" / "inv1.md"
    _write_rule(rule, "inv1")
    inventory = inventory_rules(str(tmp_path))
    assert [e.relative_path for e in inventory.entries] == [".aegis/rules/invariants/inv1.md"]


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs POSIX permissions that apply to this user")
def test_an_unlistable_rule_directory_fails_closed_naming_it(tmp_path):
    from aegis_core.rule_inventory import RuleInventoryError, inventory_rules

    _write_rule(tmp_path / ".aegis" / "rules" / "traps" / "a.md")
    sealed = tmp_path / ".aegis" / "rules" / "invariants"
    _write_rule(sealed / "hidden.md", "hidden")
    sealed.chmod(0)
    try:
        with pytest.raises(RuleInventoryError) as caught:
            inventory_rules(str(tmp_path))
    finally:
        sealed.chmod(0o755)

    assert (caught.value.operation, caught.value.path) == ("list", str(sealed))
    assert str(caught.value).startswith(f"rule inventory list failed for {sealed}: ")


@pytest.mark.parametrize("consumer", ["inventory", "lint"])
@pytest.mark.parametrize("extra_bytes", [0, 1, 262144])
def test_rule_consumers_bound_inventory_reads_before_allocation(
    tmp_path, monkeypatch, consumer, extra_bytes,
):
    from aegis_core.packs import MAX_RULE_BYTES
    from aegis_core import rule_lint
    from aegis_core.storage_confined import descriptor_supported

    if consumer == "lint" and not descriptor_supported():
        pytest.skip("descriptor-confined lint is unavailable")
    path = tmp_path / ".aegis" / "rules" / "invariants" / "rule-a.md"
    _write_rule(path)
    with path.open("ab") as stream:
        stream.write(b"x" * (MAX_RULE_BYTES + extra_bytes - path.stat().st_size))

    consumed = []

    def bounded_read(fd, count):
        remaining = MAX_RULE_BYTES + 1 - sum(consumed)
        assert 0 < count <= remaining, "inventory requested bytes beyond the rule cap"
        data = os.read(fd, count)
        consumed.append(len(data))
        return data

    # Replace the consumer's OS reference, never the process-wide os.read.
    monkeypatch.setattr(rule_inventory_module, "os", SimpleNamespace(**{**vars(os), "read": bounded_read}))
    for _ in range(2):
        consumed.clear()
        if consumer == "inventory":
            snapshot = rule_inventory_module.inventory_rules(str(tmp_path))
            assert len(snapshot.entries) == 1
        else:
            results = rule_lint.lint_workspace(
                tmp_path, [".aegis/rules/invariants/rule-a.md"],
            )
            if extra_bytes:
                assert len(results) == 1
                assert {finding.code for finding in results[0].findings} == {"too_large"}
        assert sum(consumed) <= MAX_RULE_BYTES + 1


def test_oversized_inventory_entry_retains_size_without_content(tmp_path):
    from aegis_core.packs import MAX_RULE_BYTES
    from aegis_core.rule_inventory import inventory_rules

    path = tmp_path / ".aegis" / "rules" / "invariants" / "rule-a.md"
    _write_rule(path)
    with path.open("ab") as stream:
        stream.write(b"x" * MAX_RULE_BYTES)

    snapshot = inventory_rules(str(tmp_path))
    assert len(snapshot.entries) == 1
    entry = snapshot.entries[0]
    assert entry.size == path.stat().st_size > MAX_RULE_BYTES
    assert not entry.content, "oversized entries must not expose content to parsers"


def test_loader_does_not_serve_an_oversized_inventory_rule(tmp_path):
    from aegis_core.packs import MAX_RULE_BYTES
    from aegis_core.rules import load_rules

    path = tmp_path / ".aegis" / "rules" / "invariants" / "rule-a.md"
    _write_rule(path)
    with path.open("ab") as stream:
        stream.write(b"x" * MAX_RULE_BYTES)

    rules = load_rules(tmp_path).rules
    assert len(rules) == 1
    assert not rules[0].ok, "the loader must refuse an oversized rule"


def test_oversized_fingerprint_uses_size_and_prefix_not_tail_or_stat_identity(tmp_path):
    from aegis_core.packs import MAX_RULE_BYTES

    path = tmp_path / ".aegis/rules/invariants/rule-a.md"
    _write_rule(path)
    with path.open("ab") as stream:
        stream.write(b"x" * (MAX_RULE_BYTES + 10))
    first = rule_inventory_module.inventory_rules(str(tmp_path))
    entry = first.entries[0]
    assert entry.content == b""
    assert len(entry.prefix) == MAX_RULE_BYTES + 1
    assert entry.stat_identity is not None
    with path.open("r+b") as stream:
        stream.seek(-1, os.SEEK_END)
        stream.write(b"y")
    tail = rule_inventory_module.inventory_rules(str(tmp_path))
    assert tail.fingerprint == first.fingerprint
    with path.open("ab") as stream:
        stream.write(b"z")
    larger = rule_inventory_module.inventory_rules(str(tmp_path))
    assert larger.fingerprint != first.fingerprint
    with path.open("r+b") as stream:
        stream.write(b"!")
    assert rule_inventory_module.inventory_rules(str(tmp_path)).fingerprint != larger.fingerprint


def test_normal_and_empty_fingerprint_contract_is_unchanged(tmp_path):
    import hashlib

    empty_digest = hashlib.sha256(b"aegis-rule-inventory-v1\0").hexdigest()
    assert rule_inventory_module.inventory_rules(str(tmp_path)).fingerprint == empty_digest
    path = tmp_path / ".aegis/rules/invariants/rule-a.md"
    _write_rule(path)
    expected = hashlib.sha256(b"aegis-rule-inventory-v1\0" + b".aegis/rules/invariants/rule-a.md\0"
                              + hashlib.sha256(path.read_bytes()).digest() + b"\0").hexdigest()
    assert rule_inventory_module.inventory_rules(str(tmp_path)).fingerprint == expected


@pytest.mark.parametrize("failure", ["read", "fstat", "growth", "deletion", "special"])
def test_inventory_failure_closes_descriptors_and_retry_succeeds(tmp_path, monkeypatch, failure):
    if failure == "special" and (os.name != "posix" or not hasattr(os, "mkfifo")):
        pytest.skip("requires POSIX FIFOs")
    path = tmp_path / ".aegis/rules/invariants/rule-a.md"
    _write_rule(path)
    opened, closed, triggered = [], [], []

    def tracked_open(*args, **kwargs):
        if failure == "special" and os.fspath(args[0]) in {str(path), path.name} and not triggered:
            # Refuse safely before creating a FIFO if nonblocking protection regresses.
            assert args[1] & os.O_NONBLOCK
            path.unlink()
            os.mkfifo(path)
            triggered.append(True)
        fd = os.open(*args, **kwargs)
        opened.append(fd)
        return fd

    def tracked_close(fd):
        closed.append(fd)
        return os.close(fd)

    def failed_read(fd, count):
        if not triggered:
            triggered.append(True)
            if failure == "read":
                raise OSError("injected read failure")
            if failure == "growth":
                with path.open("ab") as stream:
                    stream.write(b"changed")
            if failure == "deletion":
                path.unlink()
        return os.read(fd, count)

    def failed_stat(fd):
        if failure == "fstat" and not triggered:
            triggered.append(True)
            raise OSError("injected stat failure")
        return os.fstat(fd)

    monkeypatch.setattr(rule_inventory_module, "os", SimpleNamespace(**{
        **vars(os), "open": tracked_open, "close": tracked_close, "read": failed_read, "fstat": failed_stat,
    }))
    with pytest.raises(rule_inventory_module.RuleInventoryError) as caught:
        rule_inventory_module.inventory_rules(str(tmp_path))
    assert caught.value.operation in {"read", "stat"}
    assert sorted(opened) == sorted(closed)
    if failure == "special":
        path.unlink()
    _write_rule(path)
    assert len(rule_inventory_module.inventory_rules(str(tmp_path)).entries) == 1
    assert sorted(opened) == sorted(closed)


def test_inventory_bounded_reader_without_descriptor_capability(tmp_path, monkeypatch):
    from aegis_core.packs import MAX_RULE_BYTES

    path = tmp_path / ".aegis/rules/invariants/rule-a.md"
    _write_rule(path)
    with path.open("ab") as stream:
        stream.write(b"x" * MAX_RULE_BYTES)
    monkeypatch.setattr(rule_inventory_module, "descriptor_supported", lambda: False)
    entry = rule_inventory_module.inventory_rules(str(tmp_path)).entries[0]
    assert entry.content == b"" and len(entry.prefix) == MAX_RULE_BYTES + 1


def test_inventory_ancestor_swap_cannot_read_outside_the_captured_parent(tmp_path, monkeypatch):
    from aegis_core.storage_confined import descriptor_supported

    if not descriptor_supported():
        pytest.skip("requires descriptor-confined opens")
    path = tmp_path / "workspace/.aegis/rules/invariants/rule-a.md"
    outside = tmp_path / "outside/rule-a.md"
    _write_rule(path)
    _write_rule(outside, "outside")
    # Probe symlink support before injecting the concurrent rename.
    probe = tmp_path / "probe"
    try:
        probe.symlink_to(outside.parent, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    probe.unlink()
    moved = path.parent.with_name("moved")
    observed, swapped = [], []

    def raced_open(target, *args, **kwargs):
        if os.fspath(target) in {str(path), path.name} and not swapped:
            path.parent.rename(moved)
            path.parent.symlink_to(outside.parent, target_is_directory=True)
            swapped.append(True)
        return os.open(target, *args, **kwargs)

    def watched_read(fd, count):
        data = os.read(fd, count)
        observed.append(data)
        return data

    monkeypatch.setattr(rule_inventory_module, "os", SimpleNamespace(**{
        **vars(os), "open": raced_open, "read": watched_read,
    }))
    try:
        with pytest.raises(rule_inventory_module.RuleInventoryError):
            rule_inventory_module.inventory_rules(str(tmp_path / "workspace"))
        assert b"id: outside" not in b"".join(observed)
    finally:
        if swapped:
            path.parent.unlink()
            moved.rename(path.parent)
    assert len(rule_inventory_module.inventory_rules(str(tmp_path / "workspace")).entries) == 1


def test_inventory_workspace_rename_cannot_redirect_reads_after_listing(tmp_path, monkeypatch):
    from aegis_core.storage_confined import descriptor_supported

    if not descriptor_supported():
        pytest.skip("requires descriptor-confined opens")
    root, outside, moved = (tmp_path / name for name in ("workspace", "outside", "moved"))
    relative = ".aegis/rules/invariants/rule-a.md"
    _write_rule(root / relative)
    _write_rule(outside / relative, "outside")
    swapped, observed = [], []

    def raced_stat(target, *args, **kwargs):
        if os.fspath(target) == str(root / relative) and not swapped:
            root.rename(moved)
            outside.rename(root)
            swapped.append(True)
        return os.stat(target, *args, **kwargs)

    def watched_read(fd, count):
        data = os.read(fd, count)
        observed.append(data)
        return data

    monkeypatch.setattr(rule_inventory_module, "os", SimpleNamespace(**{
        **vars(os), "stat": raced_stat, "read": watched_read,
    }))
    try:
        with pytest.raises(rule_inventory_module.RuleInventoryError):
            rule_inventory_module.inventory_rules(str(root))
        assert b"id: outside" not in b"".join(observed)
    finally:
        if swapped:
            root.rename(outside)
            moved.rename(root)
    assert len(rule_inventory_module.inventory_rules(str(root)).entries) == 1


@pytest.mark.parametrize("consumer", ["scan", "pack", "checkpoint", "sdk", "mcp", "status"])
def test_public_rule_readers_refuse_oversized_rules(tmp_path, monkeypatch, capsys, consumer):
    from aegis_core.packs import MAX_RULE_BYTES

    path = tmp_path / ".aegis/rules/invariants/rule-a.md"
    _write_rule(path)
    with path.open("ab") as stream:
        stream.write(b"x" * MAX_RULE_BYTES)
    if consumer == "scan":
        from aegis_core.scan import scan

        result = scan(str(tmp_path), changed_files=["src/app.py"])
        assert result["status"] == "FAIL" and "too_large" in result["error"]
    elif consumer == "pack":
        from aegis_core.packs import PackError, build_pack
        from aegis_core.rules import load_rules

        with pytest.raises(PackError, match="bytes exceeds"):
            build_pack(load_rules(tmp_path).rules)
    elif consumer == "checkpoint":
        from aegis_core.verification.checkpoint_checks import check_rule_conventions

        issues = check_rule_conventions(tmp_path)
        assert len(issues) == 1 and issues[0]["check"] == "rule_load"
        assert "too_large" in issues[0]["message"]
    elif consumer == "sdk":
        from aegis_sdk.governance import Governance

        records = Governance(project_root=tmp_path).list_rules()
        assert len(records) == 1 and "too_large" in records[0]["_error"]
    elif consumer == "mcp":
        from aegis_core.workspace.base import Workspace
        from aegis_mcp.handlers.governance import list_rules

        result = list_rules(Workspace(tmp_path))
        assert len(result["rules"]) == 1 and "too_large" in result["rules"][0]["_error"]
    else:
        from aegis_cli.cli import main

        assert main(["status", "--workspace", str(tmp_path), "--plain", "--json"]) == 1
        assert "too_large" in capsys.readouterr().out
