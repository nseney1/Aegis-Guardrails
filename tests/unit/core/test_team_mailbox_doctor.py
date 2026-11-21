"""Read-only product doctor: legacy observations, secure refusal and retry."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import errno
import json
import hashlib
import os
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import symlink_or_skip
from aegis_core import team_mailbox as mailbox_module
from aegis_core import team_mailbox_store as storage
from aegis_core import team_mailbox_doctor as module
from aegis_core.team_mailbox_primitives import MailboxRefusal, RoleTables
from tools import hierarchy_mailbox as legacy
from tools import hierarchy_mailbox_doctor as legacy_doctor


OPTIONS = dict(clock=lambda: datetime(2026, 11, 19, tzinfo=timezone.utc), roles=RoleTables(),
               hosts={"primary": object()}, process_status=lambda pid: "alive")


def doctor():
    return module


def make_store(tmp_path):
    if not storage.descriptor_supported():
        pytest.skip("descriptor-relative no-follow storage required")
    root = tmp_path / "mailbox"
    manifest = {"schema": "aegis.hierarchy-pilot/v1", "writer_limit": 2,
                "endpoints": {"a/front-door": {}, "a/orchestrator": {}}, "counterparts": []}
    legacy.initialize(root, manifest)
    box = legacy.Mailbox(root)
    for endpoint in manifest["endpoints"]:
        box.bind({"endpoint": endpoint, "host": "primary", "session": endpoint, "expected_generation": 0})
    box.publish({"message_id": "seed", "from": "a/front-door", "to": "a/orchestrator", "host": "primary",
                 "session": "a/front-door", "binding_generation": 1, "type": "info", "body": "hello"})
    return root


def snapshot(root):
    return {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in root.rglob("*") if p.is_file()}


def test_healthy_legacy_parity_and_no_side_effects(tmp_path):
    root = make_store(tmp_path)
    before = snapshot(root)
    assert doctor().inspect_mailbox(root, **OPTIONS) == legacy_doctor.inspect_mailbox(root)
    assert snapshot(root) == before


@pytest.mark.parametrize("damage", ["message", "duplicate", "binding", "pending", "lock"])
def test_problem_report_matches_legacy_then_retry(tmp_path, damage):
    root = make_store(tmp_path)
    source = next((root / "a/orchestrator").glob("*.md"))
    path, raw = {
        "message": (source.parent / "broken.md", b"broken"),
        "duplicate": (source.parent / "duplicate.md", source.read_bytes()),
        "binding": (root / "bindings/a/front-door/000001.json", b"{}"),
        "pending": (source.parent / ".pending-orphan", b"pending"),
        "lock": (root / ".write.lock", b"{}"),
    }[damage]
    previous = path.read_bytes() if path.exists() else None
    path.write_bytes(raw)
    before = snapshot(root)
    actual = doctor().inspect_mailbox(root, **OPTIONS)
    assert actual == legacy_doctor.inspect_mailbox(root)
    assert not actual["healthy"] and snapshot(root) == before
    if previous is None:
        path.unlink()
    else:
        path.write_bytes(previous)
    assert doctor().inspect_mailbox(root, **OPTIONS)["healthy"]


def test_unsupported_probe_has_fixed_refusal_on_every_platform(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "descriptor_reads_supported", lambda: False)
    with pytest.raises(module.Refusal, match="^secure mailbox diagnostics require") as caught:
        module.inspect_mailbox(tmp_path / "absent", **OPTIONS)
    assert caught.value.code == "MD_PLATFORM" and caught.value.next_action


def test_symlink_and_oversized_refusals_are_read_only(tmp_path):
    root = make_store(tmp_path)
    path = root / "extra"
    path.write_bytes(b"x" * (262144 + 1))
    with pytest.raises(doctor().Refusal) as caught:
        doctor().inspect_mailbox(root, **OPTIONS)
    assert caught.value.code == "MD_LIMIT"
    path.unlink()
    symlink_or_skip(root / "manifest.json", path)
    with pytest.raises(doctor().Refusal) as caught:
        doctor().inspect_mailbox(root, **OPTIONS)
    assert caught.value.code == "MD_PATH"


def test_display_is_canonicalized_redacted_then_truncated(tmp_path):
    root = make_store(tmp_path)
    path = root / "a/orchestrator" / ("token=PRIVATE" + "x" * 40 + ".md")
    path.write_bytes(b"bad")
    result = doctor().inspect_mailbox(root, **OPTIONS)
    assert "PRIVATE" not in json.dumps(result)
    assert all(len(issue["path"]) <= 259 for issue in result["issues"])


@pytest.mark.parametrize("limit", ["MAX_FILES", "MAX_TOTAL_BYTES", "MAX_BYTES", "MAX_NAME_BYTES"])
def test_all_limits_are_checked_before_manifest_validation(tmp_path, monkeypatch, limit):
    root = make_store(tmp_path)
    (root / "manifest.json").write_bytes(b"{")
    if limit == "MAX_FILES":
        monkeypatch.setattr(module, "MAX_FILES", 1)
    elif limit == "MAX_TOTAL_BYTES":
        monkeypatch.setattr(module, "MAX_TOTAL_BYTES", 1)
    elif limit == "MAX_BYTES":
        monkeypatch.setattr(module, "MAX_BYTES", 1)
    else:
        monkeypatch.setattr(module, "MAX_NAME_BYTES", 1)

    with pytest.raises(module.Refusal) as caught:
        module.inspect_mailbox(root, **OPTIONS)
    assert caught.value.code == "MD_LIMIT"


@pytest.mark.parametrize("damage,code", [("missing", "MD_IO"), ("manifest", "MD_DATA")])
def test_missing_or_malformed_manifest_is_fixed(tmp_path, damage, code):
    root = make_store(tmp_path)
    path = root / "manifest.json"
    if damage == "missing":
        path.unlink()
    else:
        path.write_bytes(b"{}")
    before = snapshot(root)
    with pytest.raises(doctor().Refusal) as caught:
        doctor().inspect_mailbox(root, **OPTIONS)
    assert caught.value.code == code and caught.value.next_action
    assert snapshot(root) == before


def test_process_timeout_is_a_fixed_refusal(tmp_path):
    root = make_store(tmp_path)
    (root / ".write.lock").write_text(json.dumps({"pid": 42, "created_at": "2026-11-19T00:00:00Z"}))

    def timeout(pid):
        raise TimeoutError("PRIVATE")

    before = snapshot(root)
    with pytest.raises(doctor().Refusal) as caught:
        doctor().inspect_mailbox(root, **{**OPTIONS, "process_status": timeout})
    assert caught.value.code == "MD_IO" and "PRIVATE" not in str(caught.value)
    assert snapshot(root) == before


def test_parent_symlink_swap_cannot_read_external_bytes(tmp_path, monkeypatch):
    root = make_store(tmp_path)
    source = root / "a/orchestrator"
    held = root / "a/held"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "SECRET.md").write_bytes(b"outside data")
    swapped = []

    def observed_stat(name, *args, **kwargs):
        info = os.stat(name, *args, **kwargs)
        if name == "orchestrator" and not swapped:
            source.rename(held)
            symlink_or_skip(outside, source, target_is_directory=True)
            swapped.append(True)
        return info

    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "stat": observed_stat}))
    with pytest.raises(module.Refusal) as caught:
        module.inspect_mailbox(root, **OPTIONS)
    assert swapped == [True] and caught.value.code == "MD_IO"
    source.unlink()
    held.rename(source)
    monkeypatch.setattr(module, "os", os)
    assert module.inspect_mailbox(root, **OPTIONS)["healthy"]


@pytest.mark.parametrize("mutation", ["ancestor-symlink", "ancestor-file", "ancestor-unsafe"])
def test_r1d_enumeration_walk_checks_its_admitted_directory(tmp_path, monkeypatch, mutation):
    root = make_store(tmp_path)
    path = next((root / "a/orchestrator").glob("*.md"))
    apply, restore, changed, canary = replacement_mutation(path, mutation, tmp_path)
    parent = path.parent.parent.stat()
    before, attempts, live = snapshot(tmp_path), [], set()

    def observe_open(name, flags, *args, **kwargs):
        if name == path.parent.name and flags & os.O_DIRECTORY and "dir_fd" in kwargs:
            info = os.fstat(kwargs["dir_fd"])
            if (info.st_dev, info.st_ino) == (parent.st_dev, parent.st_ino) and not changed:
                attempts.append(name)
                apply()
        fd = os.open(name, flags, *args, **kwargs)
        live.add(fd)
        return fd

    def observe_dup(fd):
        duplicate = os.dup(fd)
        live.add(duplicate)
        return duplicate

    def observe_close(fd):
        os.close(fd)
        live.remove(fd)

    monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "open": observe_open,
                                                        "dup": observe_dup, "close": observe_close}))
    try:
        with pytest.raises(module.Refusal) as caught:
            module.inspect_mailbox(root, **OPTIONS)
    finally:
        monkeypatch.setattr(storage, "os", os)
        restore()
    assert changed == [True] and attempts == [path.parent.name]
    assert caught.value.code == "MD_IO" and not live
    assert str(caught.value) == module.REFUSALS["MD_IO"]
    assert caught.value.next_action == module.NEXT_ACTIONS["MD_IO"]
    assert snapshot(tmp_path) == before
    assert module.inspect_mailbox(root, **OPTIONS)["healthy"]


def replacement_record(root, target):
    if target != "brief":
        return limit_record(root, target)
    directory = root / "checkpoint"
    directory.mkdir(mode=0o700)
    path = directory / "brief.md"
    path.write_bytes(b"a brief\n")
    checkpoint = {"outgoing_stopped": True, "briefs": [{"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}],
                  "sources": [], "lease_refs": [], "completed_checks": [], "pending_message_ids": [], "last_acknowledgment_ids": []}
    legacy.Mailbox(root).bind({"endpoint": "a/front-door", "host": "primary", "session": "replacement",
                              "expected_generation": 1, "checkpoint": checkpoint})
    return path


def replacement_mutation(path, mutation, tmp_path):
    if mutation == "leaf-fifo" and (os.name != "posix" or not hasattr(os, "mkfifo")):
        pytest.skip("POSIX FIFO required")
    target = path.parent if mutation.startswith("ancestor-") else path
    held, changed = tmp_path / "held", []
    original_mode = target.stat().st_mode & 0o777
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    canary = outside / path.name
    canary.write_bytes(b"PRIVATE_OUTSIDE")
    size = path.stat().st_size

    def apply():
        changed.append(True)
        if mutation == "ancestor-unsafe":
            target.chmod(original_mode | 0o020)
            return
        target.rename(held)
        if mutation == "leaf-symlink":
            symlink_or_skip(canary, target)
        elif mutation == "leaf-dangling":
            symlink_or_skip(outside / "absent", target)
        elif mutation == "leaf-fifo":
            os.mkfifo(target, 0o600)
        elif mutation == "leaf-regular":
            target.write_bytes(b"x" * size)
        elif mutation == "ancestor-symlink":
            symlink_or_skip(outside, target, target_is_directory=True)
        elif mutation == "ancestor-file":
            target.write_bytes(b"not a directory")
        else:
            assert mutation == "leaf-removed"

    def restore():
        if not changed:
            return
        if mutation == "ancestor-unsafe":
            target.chmod(original_mode)
        else:
            if target.is_symlink() or target.exists():
                target.unlink()
            held.rename(target)

    return apply, restore, changed, canary


@pytest.mark.parametrize("target", ["manifest", "message", "binding", "acknowledgment", "brief", "lock"])
@pytest.mark.parametrize("mutation", ["leaf-symlink", "leaf-dangling", "leaf-fifo", "leaf-removed", "leaf-regular",
                                     "ancestor-symlink", "ancestor-file", "ancestor-unsafe"])
@pytest.mark.parametrize("window", ["before-open", "after-refusal"])
def test_r1d_admitted_replacement_is_io_on_every_read_path(tmp_path, monkeypatch, target, mutation, window):
    root = make_store(tmp_path)
    path = replacement_record(root, target)
    apply, restore, changed, canary = replacement_mutation(path, mutation, tmp_path)
    parent, outside = path.parent.stat(), canary.stat()
    before, attempts, outside_reads, live = snapshot(tmp_path), [], [], set()
    assert module.inspect_mailbox(root, **OPTIONS)["healthy"]

    def observe_open(name, flags, *args, **kwargs):
        if name == path.name and not flags & os.O_DIRECTORY and "dir_fd" in kwargs:
            info = os.fstat(kwargs["dir_fd"])
            if (info.st_dev, info.st_ino) == (parent.st_dev, parent.st_ino):
                attempts.append(name)
                if window == "before-open":
                    apply()
                else:
                    raise OSError(errno.ELOOP, "PRIVATE")
        fd = os.open(name, flags, *args, **kwargs)
        live.add(fd)
        return fd

    def observe_dup(fd):
        if window == "after-refusal" and attempts and not changed:
            apply()
        duplicate = os.dup(fd)
        live.add(duplicate)
        return duplicate

    def observe_close(fd):
        os.close(fd)
        live.remove(fd)

    def observe_read(fd, size):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == (outside.st_dev, outside.st_ino):
            outside_reads.append(fd)
        return os.read(fd, size)

    monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "open": observe_open, "dup": observe_dup,
                                                        "close": observe_close, "read": observe_read}))
    try:
        with pytest.raises(module.Refusal) as caught:
            module.inspect_mailbox(root, **OPTIONS)
    finally:
        monkeypatch.setattr(storage, "os", os)
        restore()
    assert changed == [True] and attempts == [path.name]
    assert not live
    assert caught.value.code == "MD_IO"
    assert str(caught.value) == module.REFUSALS["MD_IO"]
    assert caught.value.next_action == module.NEXT_ACTIONS["MD_IO"]
    assert not outside_reads and snapshot(tmp_path) == before
    assert module.inspect_mailbox(root, **OPTIONS)["healthy"]


@pytest.mark.parametrize("error_number", [errno.EACCES, errno.EIO, errno.ELOOP, errno.ENOENT, errno.ENOTDIR])
def test_r1d_failed_observation_of_admitted_input_is_io_then_retry(tmp_path, monkeypatch, error_number):
    root = make_store(tmp_path)
    path = replacement_record(root, "brief")
    before, opened, failures = snapshot(tmp_path), [], []

    def observe_open(name, flags, *args, **kwargs):
        fd = os.open(name, flags, *args, **kwargs)
        if name == path.name and not flags & os.O_DIRECTORY:
            opened.append(True)
        return fd

    def refuse_stat(name, *args, **kwargs):
        if name == path.name and opened:
            failures.append(True)
            raise OSError(error_number, "PRIVATE")
        return os.stat(name, *args, **kwargs)

    monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "open": observe_open}))
    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "stat": refuse_stat}))
    try:
        with pytest.raises(module.Refusal) as caught:
            module.inspect_mailbox(root, **OPTIONS)
    finally:
        monkeypatch.setattr(storage, "os", os)
        monkeypatch.setattr(module, "os", os)
    assert caught.value.code == "MD_IO" and opened == [True] and failures
    assert str(caught.value) == module.REFUSALS["MD_IO"]
    assert caught.value.next_action == module.NEXT_ACTIONS["MD_IO"]
    assert snapshot(tmp_path) == before
    assert module.inspect_mailbox(root, **OPTIONS)["healthy"]


@pytest.mark.parametrize("target", ["manifest", "message", "binding", "acknowledgment", "brief", "lock"])
@pytest.mark.parametrize("mutation", ["leaf-symlink", "ancestor-unsafe"])
def test_r1d_initially_unsafe_input_keeps_path_refusal_then_retry(tmp_path, target, mutation):
    root = make_store(tmp_path)
    path = replacement_record(root, target)
    apply, restore, changed, canary = replacement_mutation(path, mutation, tmp_path)
    before = snapshot(tmp_path)
    try:
        apply()
        with pytest.raises(module.Refusal) as caught:
            module.inspect_mailbox(root, **OPTIONS)
    finally:
        restore()
    assert caught.value.code == "MD_PATH" and changed == [True]
    assert caught.value.next_action == module.NEXT_ACTIONS["MD_PATH"]
    assert snapshot(tmp_path) == before
    assert module.inspect_mailbox(root, **OPTIONS)["healthy"]


def limit_record(root, target):
    if target in ("brief", "acknowledgment"):
        brief = root.parent / "brief.md"
        brief.write_bytes(b"a brief\n".ljust(module.MAX_BYTES, b" ") if target == "brief" else b"a brief\n")
        checkpoint = {"outgoing_stopped": True, "briefs": [{"path": str(brief), "sha256": hashlib.sha256(brief.read_bytes()).hexdigest()}],
                      "sources": [], "lease_refs": [], "completed_checks": [], "pending_message_ids": [], "last_acknowledgment_ids": []}
        box = legacy.Mailbox(root)
        binding = box.bind({"endpoint": "a/front-door", "host": "primary", "session": "replacement",
                            "expected_generation": 1, "checkpoint": checkpoint})
        if target == "brief":
            return brief
        box.acknowledge_handoff({key: binding[key] for key in ("endpoint", "generation", "session", "checkpoint_sha256")})
        path = root / "bindings/a/front-door/000002.ack"
    elif target == "lock":
        path = root / ".write.lock"
        path.write_text(json.dumps({"pid": 42, "created_at": "2026-11-19T00:00:00Z"}))
    elif target == "manifest":
        path = root / "manifest.json"
    elif target == "binding":
        path = root / "bindings/a/front-door/000001.json"
    else:
        path = next((root / "a/orchestrator").glob("*.md"))
    raw = path.read_bytes()
    padding = b" " * (module.MAX_BYTES - len(raw))
    path.write_bytes(raw.replace(b"\n---\n\n", padding + b"\n---\n\n", 1) if target == "message" else raw + padding)
    return path


@pytest.mark.parametrize("target", ["manifest", "message", "binding", "acknowledgment", "brief", "lock"])
@pytest.mark.parametrize("window", ["before-fstat", "during-read", "unchanged-oversize", "second-fstat"])
def test_r1c_limit_crossing_is_io_only_for_changed_input_then_retry(tmp_path, monkeypatch, target, window):
    root = make_store(tmp_path)
    path = limit_record(root, target)
    original, identity = path.read_bytes(), path.stat()
    assert len(original) == module.MAX_BYTES
    assert module.inspect_mailbox(root, **OPTIONS)["healthy"]
    if window == "unchanged-oversize":
        path.write_bytes(original + b" ")
    before = snapshot(root.parent)
    changed, fstats = [], []

    def grow():
        with path.open("ab") as stream:
            stream.write(b" ")
        changed.append(True)

    def observe_fstat(fd):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
            fstats.append(fd)
            if (window == "before-fstat" and len(fstats) == 1
                    or window == "second-fstat" and len(fstats) == 2):
                grow()
                return os.fstat(fd)
        return info

    def observe_read(fd, size):
        chunk = os.read(fd, size)
        info = os.fstat(fd)
        if window == "during-read" and not changed and chunk and (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
            grow()
        return chunk

    monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "fstat": observe_fstat, "read": observe_read}))
    with pytest.raises(module.Refusal) as caught:
        module.inspect_mailbox(root, **OPTIONS)
    expected = "MD_LIMIT" if window == "unchanged-oversize" else "MD_IO"
    assert caught.value.code == expected
    assert str(caught.value) == module.REFUSALS[expected]
    assert caught.value.next_action == module.NEXT_ACTIONS[expected]
    assert changed == ([] if window == "unchanged-oversize" else [True])
    if window in ("before-fstat", "during-read"):
        assert len(fstats) == 1
    elif window == "second-fstat":
        assert len(fstats) == 2
    else:
        assert not fstats
    after = snapshot(root.parent)
    assert set(after) == set(before)
    relative = str(path.relative_to(root.parent))
    for name in before:
        if name == relative and changed:
            assert after[name][0] == original + b" "
        else:
            assert after[name] == before[name]
    monkeypatch.setattr(storage, "os", os)
    path.write_bytes(original)
    assert module.inspect_mailbox(root, **OPTIONS)["healthy"]


@pytest.mark.parametrize("changed", [False, True])
def test_r1c_non_size_read_refusal_reprobes_before_classification(tmp_path, monkeypatch, changed):
    root = make_store(tmp_path)
    path = limit_record(root, "brief")
    original = path.read_bytes()
    before, attempts = snapshot(root.parent), []

    def refuse_open(name, flags, *args, **kwargs):
        if name == path.name:
            attempts.append(name)
            if changed:
                with path.open("ab") as stream:
                    stream.write(b" ")
            raise OSError(errno.ELOOP, "PRIVATE")
        return os.open(name, flags, *args, **kwargs)

    monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "open": refuse_open}))
    with pytest.raises(module.Refusal) as caught:
        module.inspect_mailbox(root, **OPTIONS)
    expected = "MD_IO" if changed else "MD_PATH"
    assert caught.value.code == expected and attempts == [path.name]
    assert str(caught.value) == module.REFUSALS[expected]
    assert caught.value.next_action == module.NEXT_ACTIONS[expected]
    after = snapshot(root.parent)
    assert set(after) == set(before)
    for name in before:
        if name == str(path.relative_to(root.parent)) and changed:
            assert after[name][0] == original + b" "
        else:
            assert after[name] == before[name]
    monkeypatch.setattr(storage, "os", os)
    path.write_bytes(original)
    assert module.inspect_mailbox(root, **OPTIONS)["healthy"]


def bulk_messages(root, count, full_size=False):
    source = next((root / "a/orchestrator").glob("*.md"))
    header, body = source.read_text().removeprefix("---\n").split("\n---\n\n", 1)
    template = json.loads(header)
    source.unlink()
    for index in range(count):
        encoded = json.dumps({**template, "message_id": "m%04d" % index}, sort_keys=True).encode("utf-8")
        padding = b" " * (module.MAX_BYTES - len(encoded) - len(body.encode("utf-8")) - 10) if full_size else b""
        (source.parent / ("m%04d.md" % index)).write_bytes(b"---\n" + encoded + padding + b"\n---\n\n" + body.encode("utf-8"))


@pytest.mark.parametrize("shape", ["large-manifest", "large-messages"])
def test_r1b_doctor_charges_each_file_once_with_legacy_sized_inputs(tmp_path, monkeypatch, shape):
    root = make_store(tmp_path)
    if shape == "large-manifest":
        path = root / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["endpoints"].update({"a/lane/" + "x" * 56 + "%03d" % i: {"kind": "implementer"} for i in range(254)})
        path.write_text(json.dumps(manifest), encoding="utf-8")
        (root / "a/lane").mkdir(mode=0o700)
        bulk_messages(root, 3000)
    else:
        bulk_messages(root, 65, full_size=True)
    opened = Counter()

    def observe_open(path, flags, *args, **kwargs):
        if str(path).endswith(".md") or str(path) == "manifest.json":
            opened[str(path)] += 1
        return os.open(path, flags, *args, **kwargs)

    monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "open": observe_open}))
    validations = []

    class ObservedRoles(RoleTables):
        def validate_manifest(self, manifest):
            validations.append(True)
            return super().validate_manifest(manifest)

    report = module.inspect_mailbox(root, **{**OPTIONS, "roles": ObservedRoles()})
    assert report["healthy"] and report["cap"]["count"] == (3000 if shape == "large-manifest" else 65)
    assert opened and set(opened.values()) == {1}
    assert validations == [True]


@pytest.mark.parametrize("target", ["manifest", "message"])
def test_r1b_cached_input_changed_before_reuse_is_io_then_retry(tmp_path, monkeypatch, target):
    root = make_store(tmp_path)
    path = root / "manifest.json" if target == "manifest" else next((root / "a/orchestrator").glob("*.md"))
    original = path.read_bytes()
    probes = []

    def observe_stat(name, *args, **kwargs):
        if name == path.name:
            probes.append(name)
            if len(probes) == 4:
                path.write_bytes(original + b" ")
        return os.stat(name, *args, **kwargs)

    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(os), "stat": observe_stat}))
    with pytest.raises(module.Refusal) as caught:
        module.inspect_mailbox(root, **OPTIONS)
    assert caught.value.code == "MD_IO" and len(probes) >= 4
    monkeypatch.setattr(module, "os", os)
    path.write_bytes(original)
    assert module.inspect_mailbox(root, **OPTIONS)["healthy"]


@pytest.mark.parametrize("target", ["message", "binding"])
def test_r1b_unknown_host_is_a_local_issue_and_keeps_prior_issues(tmp_path, target):
    root = make_store(tmp_path)
    path = next((root / "a/orchestrator").glob("*.md")) if target == "message" else root / "bindings/a/front-door/000001.json"
    original = path.read_bytes()
    if target == "message":
        header, body = original[4:].split(b"\n---\n\n", 1)
        changed = b"---\n" + json.dumps({**json.loads(header), "host": "review"}).encode() + b"\n---\n\n" + body
    else:
        changed = json.dumps({**json.loads(original), "host": "review"}).encode()
    path.write_bytes(changed)
    broken = root / "a/orchestrator/broken.md"
    broken.write_bytes(b"not a message")
    before = snapshot(root)
    report = module.inspect_mailbox(root, **OPTIONS)
    codes = [row["code"] for row in report["issues"]]
    assert not report["healthy"] and "MD_MESSAGE" in codes
    assert ("MD_MESSAGE" if target == "message" else "MD_BINDING") in codes
    assert snapshot(root) == before
    path.write_bytes(original)
    broken.unlink()
    assert module.inspect_mailbox(root, **OPTIONS)["healthy"]


@pytest.mark.parametrize("reason", ["scope", "binding", "reference", "history"])
def test_parity_refusal_is_local_and_inspection_keeps_collecting_issues(tmp_path, monkeypatch, reason):
    root = make_store(tmp_path)
    options = dict(OPTIONS)
    if reason == "history":
        reported = root / "bindings/a/front-door"
        path = reported / "000002.json"
        clean = None
        path.write_bytes((reported / "000001.json").read_bytes())
        monkeypatch.setattr(mailbox_module, "MAX_RECORDS", 1)
        code = "MD_BINDING"
    else:
        original_path = next((root / "a/orchestrator").glob("*.md"))
        reported = path = original_path.with_name("seed.md")
        original_path.rename(path)
        clean = path.read_bytes()
        header, body = clean[4:].split(b"\n---\n\n", 1)
        message = json.loads(header)
        if reason == "reference":
            message["in_reply_to"] = "missing"
        else:
            message["to"] = "b/orchestrator"
        if reason == "binding":
            # Inspection does not fence a caller. Exercise the typed refusal
            # through the injected role policy during stored-message validation.
            class BindingPolicy(RoleTables):
                def endpoint_parts(self, endpoint):
                    if endpoint == "b/orchestrator":
                        raise MailboxRefusal("binding")
                    return super().endpoint_parts(endpoint)
            options["roles"] = BindingPolicy()
        path.write_bytes(b"---\n" + json.dumps(message).encode() + b"\n---\n\n" + body)
        code = "MD_MESSAGE"

    lock = root / ".write.lock"
    lock.write_bytes(b"{}")
    before = snapshot(root)
    with ThreadPoolExecutor(max_workers=2) as pool:
        inspections = [pool.submit(module.inspect_mailbox, root, **options) for _ in range(2)]
        reports = [inspection.result(timeout=10) for inspection in inspections]
    assert reports[0] == reports[1]
    report = reports[0]
    assert not report["healthy"]
    assert {"code": code, "path": str(reported.relative_to(root.parent))} in report["issues"]
    assert {"code": "MD_LOCK", "path": str(lock.relative_to(root.parent))} in report["issues"]
    if reason != "history":
        assert report["index"] == {"status": "unavailable", "reason": "pinned_reconciliation", "differences": []}
    assert snapshot(root) == before

    if clean is None:
        path.unlink()
    else:
        path.write_bytes(clean)
    lock.unlink()
    assert module.inspect_mailbox(root, **options)["healthy"]


@pytest.mark.parametrize("target", ["manifest", "message", "binding", "brief", "lock"])
def test_r1b_change_between_read_fstats_is_io_for_every_record_class(tmp_path, monkeypatch, target):
    root = make_store(tmp_path)
    if target == "brief":
        path = root.parent / "brief.md"
        path.write_bytes(b"a brief\n")
        checkpoint = {"outgoing_stopped": True, "briefs": [{"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}],
                      "sources": [], "lease_refs": [], "completed_checks": [], "pending_message_ids": [], "last_acknowledgment_ids": []}
        legacy.Mailbox(root).bind({"endpoint": "a/front-door", "host": "primary", "session": "replacement",
                                  "expected_generation": 1, "checkpoint": checkpoint})
    elif target == "lock":
        path = root / ".write.lock"
        path.write_text(json.dumps({"pid": 42, "created_at": "2026-11-19T00:00:00Z"}))
    elif target == "manifest":
        path = root / "manifest.json"
    elif target == "binding":
        path = root / "bindings/a/front-door/000001.json"
    else:
        path = next((root / "a/orchestrator").glob("*.md"))
    original, identity = path.read_bytes(), path.stat()
    seen = []

    def changed_fstat(fd):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
            seen.append(fd)
            if len(seen) == 2:
                path.write_bytes(original + b" ")
                return os.fstat(fd)
        return info

    monkeypatch.setattr(storage, "os", SimpleNamespace(**{**vars(os), "fstat": changed_fstat}))
    with pytest.raises(module.Refusal) as caught:
        module.inspect_mailbox(root, **OPTIONS)
    assert caught.value.code == "MD_IO" and len(seen) >= 2
    monkeypatch.setattr(storage, "os", os)
    path.write_bytes(original)
    assert module.inspect_mailbox(root, **OPTIONS)["healthy"]
