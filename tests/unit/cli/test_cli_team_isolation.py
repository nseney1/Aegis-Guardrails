"""Exercise the registered CLI and descriptor boundary."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from aegis_cli import team_isolation as adapter
from aegis_cli.cli import main
from aegis_core.team_isolation_verify import container_name
from conftest import symlink_or_skip


def invoke(folder, capsys, *arguments, output="--json"):
    code = main(["--workspace", str(folder), "team", "isolation", "check", *arguments, output])
    captured = capsys.readouterr()
    assert captured.err == ""
    return code, json.loads(captured.out) if output == "--json" else captured.out


@pytest.fixture
def store(tmp_path):
    if not adapter.descriptor_supported():
        pytest.skip("descriptor-relative Linux observations required")
    return tmp_path


def test_check_plan_reports_sorted_json_on_success(store, capsys):
    config = store / "team-run.json"
    config.write_text("{}", encoding="utf-8")
    assert invoke(store, capsys, "--config", str(config)) == (
        0, {"create_argv": None, "isolation": None, "mode": "host", "mounts": [], "status": "ok"})
    assert invoke(store, capsys, "--config", str(config), output="--plain") == (0, "Isolation plan (host)\n")


def test_nested_usage_refuses_without_echoing_input(tmp_path, capsys):
    with pytest.raises(SystemExit) as error:
        main(["team", "isolation", "check", "--unknown", "untrusted-argument"])
    captured = capsys.readouterr()
    assert error.value.code == 2
    assert json.loads(captured.err)["code"] == "invalid_arguments"
    assert "untrusted-argument" not in captured.err + captured.out


def test_check_refuses_on_unsupported_platform(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(adapter, "file_support", lambda: False)
    code, result = invoke(tmp_path, capsys, "--config", "untrusted-config")
    assert code == 1 and result["code"] == "unsupported_platform"
    assert "untrusted-config" not in json.dumps(result)


@pytest.mark.parametrize(("content", "expected"), [
    (b'{"x":"untrusted-payload"}', "team_run_fields"),
    (b'{"', "document_invalid"),
    (b"x" * (1024 * 1024 + 1), "document_size"),
    (None, "document_read"),
], ids=["unknown", "malformed", "oversized", "missing"])
def test_check_refusals_and_retry(store, capsys, content, expected):
    config = store / "untrusted-config.json"
    if content is not None:
        config.write_bytes(content)
    code, result = invoke(store, capsys, "--config", str(config))
    assert code == 1 and result["code"] == expected
    assert "untrusted-" not in json.dumps(result)
    config.write_text("{}", encoding="utf-8")
    assert invoke(store, capsys, "--config", str(config))[0] == 0


@pytest.mark.parametrize("value", ["{}", "1" * 200], ids=["encoded-object", "digits"])
def test_check_refuses_non_object_configs_at_file_boundary(store, capsys, monkeypatch, value):
    path = store / "config.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    calls = []
    check = adapter.core.check

    def record(config, **kwargs):
        calls.append(config)
        return check(config, **kwargs)

    monkeypatch.setattr(adapter, "core", SimpleNamespace(**{**vars(adapter.core), "check": record}))
    status, result = invoke(store, capsys, "--config", str(path))
    assert status == 1 and result["code"] == "document_invalid"
    assert not calls
    path.write_text("{}", encoding="utf-8")
    assert invoke(store, capsys, "--config", str(path))[0] == 0
    assert calls == [{}]


@pytest.mark.parametrize("component", ["parent", "leaf"])
def test_check_does_not_follow_document_symlinks(store, capsys, component):
    real = store / "real"
    real.mkdir()
    target = real / "config.json"
    target.write_text("{}")
    link = store / "link"
    symlink_or_skip(real if component == "parent" else target, link, component == "parent")
    candidate = link / target.name if component == "parent" else link
    code, result = invoke(store, capsys, "--config", str(candidate))
    assert code == 1 and result["code"] == "document_read"
    assert invoke(store, capsys, "--config", str(target))[0] == 0


def test_observer_rename_refuses_and_retry_is_fresh(store, monkeypatch):
    root = store / "owned"
    root.mkdir()
    leaf = root / "leaf"
    leaf.mkdir()
    saved = store / "saved"

    def open_component(path, flags, **kwargs):
        fd = os.open(path, flags, **kwargs)
        if path == "leaf":
            root.rename(saved)
            root.mkdir()
        return fd

    monkeypatch.setattr(adapter, "os", SimpleNamespace(**{**vars(os), "open": open_component}))
    with pytest.raises(ValueError, match="^mount_changed$"):
        adapter.observe([str(leaf)], [], marker=None)
    monkeypatch.setattr(adapter, "os", os)
    retry = saved / "leaf"
    assert adapter.observe([str(retry)], [], marker=None)[str(retry)]["inode"] == retry.stat().st_ino


def container_inputs(store, *, source_name="source"):
    for name in ("run", "project", "venv", source_name):
        (store / name).mkdir()
    source = store / source_name
    image = "localhost/aegis-test@sha256:" + "a" * 64
    config = store / "team-run.json"
    config.write_text(json.dumps({
        "schema": "aegis.team-run/v2", "run": str(store / "run"), "project": str(store / "project"),
        "source": str(source), "recipes": {"python": str(store / "venv" / "bin" / "python")},
        "python_prefix": str(store / "venv"),
        "isolation": {"mode": "container", "engine": "docker", "image": image, "cpus": 1,
                      "memory": "1g", "pids": 64, "allow_unqualified": True},
    }), encoding="utf-8")
    return config, image


@pytest.fixture
def mount_inputs(store, monkeypatch):
    """Inject a qualified metadata snapshot independently of the host's mount namespaces."""
    observer = adapter.observe
    owner = store / "owner"
    owner.mkdir(mode=0o700)
    monkeypatch.setattr(adapter, "owner_homes", lambda: dict.fromkeys(
        ("explicit", "ambient", "password"), str(owner)))

    def snapshot(paths, homes, *, marker, protected_names):
        observed = observer(paths, homes, marker=marker, protected_names=protected_names)
        # The sandbox remaps root-owned directories to the overflow account.
        root_uid = observed["/"]["uid"]
        if root_uid not in (0, os.geteuid()):
            for row in observed.values():
                if row is not None and row["uid"] == root_uid:
                    row["uid"] = row["after"]["uid"] = 0
        return observed

    monkeypatch.setattr(adapter, "observe", snapshot)
    return store


def test_cli_verification_uses_only_digest_inspection(mount_inputs, capsys, monkeypatch):
    store = mount_inputs
    config, image = container_inputs(store)
    signed_digest = image.rsplit("@", 1)[1]
    actual = store / "inspect.json"
    actual.write_text("{}", encoding="utf-8")
    seen = []

    def inspector(argv, *, workspace):
        seen.append(argv)
        return json.dumps([{"Id": "sha256:" + "b" * 64, "RepoDigests": [image],
                            "Digest": signed_digest, "Config": {"Env": []}}]).encode()

    monkeypatch.setattr(adapter, "inspect_image", inspector)
    status, result = invoke(store, capsys, "--config", str(config), "--inspect", str(actual))
    assert status == 1 and result["status"] == "mismatch" and result["mismatches"], result
    assert seen == [["docker", "image", "inspect", image]]

    status, plan = invoke(store, capsys, "--config", str(config))
    assert status == 0, plan
    run, argv = plan["run"], plan["create_argv"]
    data = {"Name": "/" + container_name(run), "Image": "sha256:" + "b" * 64,
            "Config": {"Labels": {"aegis.team.run": run}, "User": "%d:%d" % (os.geteuid(), os.getegid()),
                       "Env": [argv[i + 1] for i, value in enumerate(argv) if value == "--env"]},
            "HostConfig": {"ReadonlyRootfs": True, "Privileged": False, "CapAdd": [], "Devices": [],
                           "PidMode": "", "IpcMode": "private", "UsernsMode": "", "NetworkMode": "bridge",
                           "SecurityOpt": ["systempaths=unconfined"], "NanoCpus": 1000000000, "Memory": 1073741824,
                           "PidsLimit": 64, "Tmpfs": {"/tmp": "rw,nosuid,nodev", "/dev/shm": "rw,nosuid,nodev"}},
            "Mounts": [dict(Type="bind", Source=row["source"], Destination=row["destination"], RW=row["rw"])
                       for row in plan["mounts"]]}
    actual.write_text(json.dumps([data]), encoding="utf-8")
    assert invoke(store, capsys, "--config", str(config), "--inspect", str(actual)) == (
        0, {"status": "ok", "mismatches": []})

    actual.write_text("{", encoding="utf-8")
    status, result = invoke(store, capsys, "--config", str(config), "--inspect", str(actual))
    assert status == 1 and result["code"] == "document_invalid" and len(seen) == 2

    def unexpected(*args, **kwargs):
        pytest.fail("double-encoded inspection reached a container dependency")

    actual.write_text(json.dumps(json.dumps([data])), encoding="utf-8")
    monkeypatch.setattr(adapter, "observe", unexpected)
    monkeypatch.setattr(adapter, "inspect_image", unexpected)
    assert invoke(store, capsys, "--config", str(config), "--inspect", str(actual)) == (
        1, {"status": "mismatch", "mismatches": ["inspect"]})


def test_cli_output_redacts_canonicalized_values_in_all_fields(mount_inputs, capsys):
    store = mount_inputs
    token = "ghp_" + "a" * 36
    # Fullwidth letters become the registered credential prefix during canonicalization.
    config, _ = container_inputs(store, source_name="ｇｈｐ_" + "a" * 36)
    status, result = invoke(store, capsys, "--config", str(config))
    assert status == 0 and result["mode"] == "container", result
    encoded = json.dumps(result, ensure_ascii=False)
    assert token not in encoded and "ｇｈｐ_" not in encoded and "[REDACTED" in encoded
    assert result["create_argv_display_only"] is True
    status, shown = invoke(store, capsys, "--config", str(config), output="--plain")
    assert status == 0 and token not in shown and "[REDACTED" in shown
    assert '"create_argv_display_only": true' in shown


@pytest.mark.parametrize("output", ["--json", "--plain"])
def test_cli_redacts_source_spelling_when_nfkc_composes_last_character(mount_inputs, capsys, output):
    store = mount_inputs
    token = "AK" + "IA" + "A" * 16
    config, _ = container_inputs(store, source_name=token + "\u0301")
    status, result = invoke(store, capsys, "--config", str(config), output=output)
    assert status == 0
    plan = result if output == "--json" else json.loads(result.splitlines()[1])
    assert token not in json.dumps(plan, ensure_ascii=False)
    assert any(row["source"] == row["destination"] == "[REDACTED]" for row in plan["mounts"])
    assert "[REDACTED]" in plan["create_argv"]
    assert plan["create_argv_display_only"] is True


def test_observer_refuses_an_incomplete_credential_policy(store):
    with pytest.raises(ValueError, match="^mount_metadata$"):
        adapter.observe([], [str(store)], marker=None, protected_names=frozenset())


@pytest.fixture
def engine_store(store, monkeypatch):
    # The sandbox maps ancestors outside the fixture to a different owner and
    # includes shared coordination directories. Only those ancestors are
    # projected as a qualified host chain. Test files and test PATH keep real facts.
    def trusted_ancestors(fd):
        info = os.fstat(fd)
        path = Path(os.readlink(f"/proc/self/fd/{fd}"))
        if path in store.parents:
            return SimpleNamespace(st_mode=info.st_mode & ~0o022, st_uid=0)
        return info

    monkeypatch.setattr(adapter, "os", SimpleNamespace(**{**vars(os), "fstat": trusted_ancestors}))
    return store


@pytest.mark.parametrize(("script", "code"), [
    ("printf '[]'", None), ("exit 9", "image_inspect"), ("exec sleep 60", "image_inspect_timeout"),
    ("exec head -c 1048577 /dev/zero", "document_size"),
], ids=["ok", "exit", "timeout", "oversized"])
def test_image_process_status_and_timeout(engine_store, monkeypatch, script, code):
    store = engine_store
    bindir, workspace = store / "bin", store / "workspace"
    bindir.mkdir()
    workspace.mkdir()
    executable = bindir / "podman"
    executable.write_text("#!/bin/sh\n" + script + "\n", encoding="utf-8")
    executable.chmod(0o700)
    search_path = str(bindir)
    if code == "image_inspect_timeout":
        times = iter((0, 31))
        monkeypatch.setattr(adapter, "time", SimpleNamespace(monotonic=lambda: next(times)))
    image = "localhost/aegis-test@sha256:" + "a" * 64
    argv = ["podman", "image", "inspect", image]
    if code is None:
        assert adapter.inspect_image(argv, workspace=workspace, search_path=search_path) == b"[]"
    else:
        with pytest.raises(ValueError, match="^" + code + "$"):
            adapter.inspect_image(argv, workspace=workspace, search_path=search_path)


def test_document_open_stays_bound_across_parent_rename(store, capsys, monkeypatch):
    parent = store / "original"
    parent.mkdir()
    old = store / "old"
    path = parent / "config.json"
    path.write_text("{}", encoding="utf-8")
    confined = adapter.confined_file

    @contextmanager
    def swap(root, parts):
        with confined(root, parts) as held:
            parent.rename(old)
            parent.mkdir()
            path.write_text('{"unknown":true}', encoding="utf-8")
            yield held

    monkeypatch.setattr(adapter, "confined_file", swap)
    assert invoke(store, capsys, "--config", str(path))[0] == 0
    monkeypatch.setattr(adapter, "confined_file", confined)
    status, result = invoke(store, capsys, "--config", str(path))
    assert status == 1 and result["code"] == "team_run_fields"


def test_held_mount_descriptor_stays_on_the_same_inode(store):
    real = store / "real"
    path = real / "leaf"
    real.mkdir()
    path.write_text("{}", encoding="utf-8")
    facts = adapter.observe([str(path)], [], marker=None)
    row = facts[str(path)]
    assert stat.S_ISREG(row["mode"])
    assert row["inode"] == row["after"]["inode"] == path.stat().st_ino


def test_host_file_reads_survive_unavailable_container_observation(store, capsys, monkeypatch):
    config, _ = container_inputs(store)
    monkeypatch.setattr(adapter, "descriptor_supported", lambda: False)
    assert invoke(store, capsys, "--config", str(config))[1]["code"] == "unsupported_platform"
    config.write_text('{"codex_home":"/unused","claude_home":"/unused"}', encoding="utf-8")
    assert invoke(store, capsys, "--config", str(config))[0] == 0


def test_unicode_mount_spelling_survives_every_display_field(mount_inputs, capsys):
    config, _ = container_inputs(mount_inputs, source_name="cafe\u0301，directory")
    path = str(mount_inputs / "cafe\u0301，directory")
    status, plan = invoke(mount_inputs, capsys, "--config", str(config))
    assert status == 0
    assert dict(source=path, destination=path, rw=False) in plan["mounts"]
    assert f"type=bind,src={path},dst={path},readonly" in plan["create_argv"]
    assert "create_argv_display_only" not in plan


@pytest.mark.parametrize("raw", [b"0", b"[]", b"[{},{}]"])
def test_invalid_cli_inspection_does_not_observe_or_spawn(store, capsys, monkeypatch, raw):
    config, _ = container_inputs(store)
    actual = store / "inspect.json"
    actual.write_bytes(raw)

    def unexpected(*args, **kwargs):
        pytest.fail("invalid inspection reached the observation or image process")

    monkeypatch.setattr(adapter, "observe", unexpected)
    monkeypatch.setattr(adapter, "inspect_image", unexpected)
    assert invoke(store, capsys, "--config", str(config), "--inspect", str(actual)) == (
        1, {"status": "mismatch", "mismatches": ["inspect"]})


def test_engine_lookup_refuses_shared_writable_path(engine_store):
    store = engine_store
    workspace = store / "workspace"
    workspace.mkdir()
    bindir = store / "shared-bin"
    bindir.mkdir()
    bindir.chmod(0o777)
    executable = bindir / "podman"
    executable.write_text("#!/bin/sh\nprintf '[]'\n", encoding="utf-8")
    executable.chmod(0o700)
    search_path = str(bindir)
    argv = ["podman", "image", "inspect", "localhost/aegis-test@sha256:" + "a" * 64]
    with pytest.raises(ValueError, match="^engine_custody$"):
        adapter.inspect_image(argv, workspace=workspace, search_path=search_path)
    bindir.chmod(0o700)
    assert adapter.inspect_image(argv, workspace=workspace, search_path=search_path) == b"[]"
    executable.chmod(0o720)
    with pytest.raises(ValueError, match="^engine_custody$"):
        adapter.inspect_image(argv, workspace=workspace, search_path=search_path)


def test_new_registry_owner_folder_blocks_mount_and_supplies_runtime_home(mount_inputs, capsys, monkeypatch):
    config, _ = container_inputs(mount_inputs)
    registry = adapter.team_host_registry
    added = {"home": {"variable": "FIXTURE_STATE", "run_folder": "fixture-state", "owner_folder": ".next-host"}}
    monkeypatch.setattr(adapter, "team_host_registry", SimpleNamespace(
        TEAM_HOSTS=(*registry.TEAM_HOSTS, "fixture"), entry=lambda kind: added if kind == "fixture" else registry.entry(kind)))
    status, plan = invoke(mount_inputs, capsys, "--config", str(config))
    assert status == 0
    assert f"FIXTURE_STATE={mount_inputs / 'run' / 'fixture-state'}" in plan["create_argv"]
    owner = mount_inputs / "owner" / ".next-host"
    owner.mkdir()
    value = json.loads(config.read_text(encoding="utf-8"))
    config.write_text(json.dumps(dict(value, source=str(owner))), encoding="utf-8")
    assert invoke(mount_inputs, capsys, "--config", str(config))[1]["code"] == "unsafe_mount"
    actual = mount_inputs / "inspect.json"
    actual.write_text("{}", encoding="utf-8")
    assert invoke(mount_inputs, capsys, "--config", str(config), "--inspect", str(actual))[1]["code"] == "unsafe_mount"


def test_engine_launch_uses_the_qualified_inode_after_rename(engine_store, monkeypatch):
    workspace, bindir = engine_store / "workspace", engine_store / "bin"
    workspace.mkdir()
    bindir.mkdir()
    executable = bindir / "podman"
    executable.write_text("#!/bin/sh\nprintf '[1]'\n", encoding="utf-8")
    executable.chmod(0o700)
    search_path = str(bindir)
    filesystem = adapter.os
    renames = []

    def swap_after_open(fd):
        info = filesystem.fstat(fd)
        if Path(os.readlink(f"/proc/self/fd/{fd}")) == executable and not renames:
            renames.append(executable.rename(bindir / "previous"))
            executable.write_text("#!/bin/sh\nprintf '[2]'\n", encoding="utf-8")
            executable.chmod(0o700)
        return info

    monkeypatch.setattr(adapter, "os", SimpleNamespace(**{**vars(filesystem), "fstat": swap_after_open}))
    argv = ["podman", "image", "inspect", "localhost/aegis-test@sha256:" + "a" * 64]
    assert adapter.inspect_image(argv, workspace=workspace, search_path=search_path) == b"[1]"
    assert adapter.inspect_image(argv, workspace=workspace, search_path=search_path) == b"[2]"
