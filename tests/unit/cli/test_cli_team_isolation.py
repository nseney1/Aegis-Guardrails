"""Exercise the registered CLI and descriptor boundary."""
from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import threading
import time
from types import SimpleNamespace

import pytest

from aegis_cli import team_isolation as adapter
from aegis_cli.cli import main
from aegis_core.team_isolation_refusal import IsolationRefusal, REFUSALS
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
    payload = json.loads(captured.err)
    assert payload["code"] == "invalid_arguments"
    assert set(payload) == {"status", "code", "reason", "next_action"}
    assert payload["reason"] == REFUSALS["invalid_arguments"]
    assert payload["next_action"] == {"actor": "operator", "command": payload["reason"]}
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
    if expected in ("document_invalid", "document_read", "document_size"):
        assert result["stage"] == "config"
        assert set(result) == {"status", "code", "reason", "next_action", "stage"}
        assert result["reason"] == REFUSALS[expected]
        assert "\n" not in result["reason"]
    else:
        assert "stage" not in result
        assert set(result) == {"status", "code", "reason", "next_action"}
    config.write_text("{}", encoding="utf-8")
    assert invoke(store, capsys, "--config", str(config))[0] == 0


def test_config_stage_text_is_one_line_and_retries(store, capsys):
    path = store / "team-run.json"
    path.write_bytes(b'{"')
    code = main(["--workspace", str(store), "team", "isolation", "check", "--config", str(path), "--plain"])
    captured = capsys.readouterr()
    assert code == 1 and captured.out == ""
    assert captured.err == "document_invalid — " + REFUSALS["document_invalid"] + " (config)\n"
    assert captured.err.count("\n") == 1
    path.write_text("{}", encoding="utf-8")
    assert invoke(store, capsys, "--config", str(path), output="--plain") == (0, "Isolation plan (host)\n")


@pytest.mark.parametrize("value", ["{}", "1" * 200], ids=["encoded-object", "digits"])
def test_check_passes_confined_bytes_and_refuses_non_objects(store, capsys, monkeypatch, value):
    path = store / "config.json"
    encoded = json.dumps(value).encode("utf-8")
    path.write_bytes(encoded)
    calls = []
    check = adapter.core.check

    def record(config, **kwargs):
        calls.append(config)
        return check(config, **kwargs)

    monkeypatch.setattr(adapter, "core", SimpleNamespace(**{**vars(adapter.core), "check": record}))
    status, result = invoke(store, capsys, "--config", str(path))
    assert status == 1 and result["code"] == "document_invalid"
    assert value not in json.dumps(result)
    assert calls == [encoded]
    path.write_bytes(b"{}")
    assert invoke(store, capsys, "--config", str(path))[0] == 0
    assert calls == [encoded, b"{}"]


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

    matching = _matching_container_document(store, config, capsys)
    actual.write_bytes(matching)
    assert invoke(store, capsys, "--config", str(config), "--inspect", str(actual)) == (
        0, {"status": "ok", "mismatches": []})

    actual.write_text("{", encoding="utf-8")
    status, result = invoke(store, capsys, "--config", str(config), "--inspect", str(actual))
    assert status == 1 and result["code"] == "document_invalid" and result["stage"] == "container-inspection"
    assert len(seen) == 2 and set(result) == {"status", "code", "reason", "next_action", "stage"}

    def unexpected(*args, **kwargs):
        pytest.fail("double-encoded inspection reached a container dependency")

    actual.write_text(json.dumps(matching.decode()), encoding="utf-8")
    monkeypatch.setattr(adapter, "observe", unexpected)
    monkeypatch.setattr(adapter, "inspect_image", unexpected)
    assert invoke(store, capsys, "--config", str(config), "--inspect", str(actual)) == (
        1, {"status": "mismatch", "mismatches": ["inspect"]})


def _image_document(image):
    digest = image.rsplit("@", 1)[1]
    return json.dumps([{"Id": "sha256:" + "b" * 64, "RepoDigests": [image],
                        "Digest": digest, "Config": {"Env": []}}]).encode()


def _matching_container_document(store, config, capsys):
    status, plan = invoke(store, capsys, "--config", str(config))
    assert status == 0 and plan["mode"] == "container", plan
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
    return json.dumps([data]).encode()


def _assert_cli_refusal(store, capsys, arguments, code, reason, stage=None):
    body = {"status": "refused", "code": code, "reason": reason,
            "next_action": {"actor": "operator", "command": reason}}
    line = code + " — " + reason
    if stage is not None:
        body["stage"] = stage
        line += " (" + stage + ")"
    assert invoke(store, capsys, *arguments) == (1, body)
    assert main(["--workspace", str(store), "team", "isolation", "check", *arguments, "--plain"]) == 1
    shown = capsys.readouterr()
    assert (shown.out, shown.err) == ("", line + "\n")


def _assert_verified(store, capsys, arguments):
    assert invoke(store, capsys, *arguments) == (0, {"status": "ok", "mismatches": []})
    assert invoke(store, capsys, *arguments, output="--plain") == (0, "Isolation verified\n")


@pytest.mark.parametrize(("stage", "code"), [
    ("config", "document_invalid"),
    ("container-inspection", "document_invalid"),
    ("image-inspection", "document_invalid"),
    ("image-inspection", "document_read"),
], ids=["config", "container", "image", "image-read"])
def test_each_document_stage_refuses_then_verifies_in_both_modes(mount_inputs, capsys, monkeypatch, stage, code):
    store = mount_inputs
    config, image = container_inputs(store)
    configured = config.read_bytes()
    matching = _matching_container_document(store, config, capsys)
    actual = store / "untrusted-inspect.json"
    actual.write_bytes(matching)
    arguments = ("--config", str(config), "--inspect", str(actual))
    snapshot = adapter.observe
    retry = False
    calls = []

    def unexpected(*args, **kwargs):
        pytest.fail("malformed config or container input reached observation")

    def inspector(argv, *, workspace):
        assert retry or stage == "image-inspection"
        calls.append(argv)
        if retry:
            return _image_document(image)
        if code == "document_read":
            raise IsolationRefusal(code)
        return b'{"untrusted-image":'

    if stage == "config":
        config.write_bytes(b'{"untrusted-config":')
    elif stage == "container-inspection":
        actual.write_bytes(b'{"untrusted-inspect":')
    if stage != "image-inspection":
        monkeypatch.setattr(adapter, "observe", unexpected)
    monkeypatch.setattr(adapter, "inspect_image", inspector)
    before = _open_fds()
    _assert_cli_refusal(store, capsys, arguments, code, REFUSALS[code], stage)
    failed_calls = 2 if stage == "image-inspection" else 0
    assert calls == [["docker", "image", "inspect", image]] * failed_calls
    assert _open_fds() == before
    config.write_bytes(configured)
    actual.write_bytes(matching)
    monkeypatch.setattr(adapter, "observe", snapshot)
    retry = True
    _assert_verified(store, capsys, arguments)
    assert calls == [["docker", "image", "inspect", image]] * (failed_calls + 2)
    assert _open_fds() == before


def test_launcher_environment_cli_refusal_hides_input_and_retries(mount_inputs, capsys, monkeypatch):
    store = mount_inputs
    snapshot = adapter.observe
    observed = []

    def observe(*args, **kwargs):
        facts = snapshot(*args, **kwargs)
        observed.append(facts)
        return facts

    monkeypatch.setattr(adapter, "observe", observe)
    config, image = container_inputs(store)
    actual = store / "inspect.json"
    actual.write_bytes(_matching_container_document(store, config, capsys))
    assert len(observed) == 1
    # Keep mount evidence independent of the engine custody fixture.
    monkeypatch.setattr(adapter, "observe", lambda *args, **kwargs: observed[0])
    _qualify_engine_ancestors(store, monkeypatch)
    _, _, _, executable = _prepare_engine(store, "exit 91")
    arguments = ("--config", str(config), "--inspect", str(actual))
    launched = []
    clean = False

    @contextmanager
    def popen(argv, **kwargs):
        assert clean, "invalid environment reached the process boundary"
        assert argv == [str(executable), "image", "inspect", image]
        assert kwargs["stderr"] == adapter.subprocess.DEVNULL
        assert kwargs["env"] == {"PATH": "/usr/bin", "LANG": "C"}
        launched.append(argv)
        output, writer = os.pipe()
        try:
            try:
                os.write(writer, _image_document(image))
            finally:
                os.close(writer)
            yield SimpleNamespace(stdout=SimpleNamespace(fileno=lambda: output), wait=lambda **_: 0, poll=lambda: 0)
        finally:
            os.close(output)

    _use_popen(monkeypatch, popen)
    monkeypatch.setattr(adapter, "which", lambda *_args, **_kwargs: str(executable))
    _use_environ(monkeypatch, environ={
        "PATH": "/usr/bin", "OPENAI_API_KEY": "synthetic-launcher-value", "BAD": "synthetic\x00untrusted"})
    before = _open_fds()
    _assert_cli_refusal(store, capsys, arguments, "image_inspect", "Retry from a clean launcher environment.")
    assert launched == [] and _open_fds() == before
    _use_environ(monkeypatch, environ={"PATH": "/usr/bin", "LANG": "C"})
    clean = True
    _assert_verified(store, capsys, arguments)
    assert len(launched) == 2 and _open_fds() == before


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
    _qualify_engine_ancestors(store, monkeypatch)
    return store


def _qualify_engine_ancestors(store, monkeypatch):
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
    if script == "exec sleep 60":
        script = "exec " + shlex.quote(_absolute_sleep()) + " 60"
    elif script.startswith("exec head "):
        head = shutil.which("head")
        if head is None:
            pytest.skip("head executable required")
        script = "exec " + shlex.quote(os.path.abspath(head)) + script[len("exec head"):]
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
        with pytest.raises(ValueError, match="^" + code + "$") as caught:
            adapter.inspect_image(argv, workspace=workspace, search_path=search_path)
        assert caught.value.stage == ("image-inspection" if code == "document_size" else None)
        if code == "image_inspect":
            assert caught.value.message == REFUSALS["image_inspect"]
            assert caught.value.note is None


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
    status, plan = invoke(store, capsys, "--config", str(config))
    assert status == 0
    assert plan == {"create_argv": None, "isolation": None, "mode": "host", "mounts": [], "status": "ok"}
    assert "/unused" not in json.dumps(plan)


def test_cli_bounds_ignored_aliases_and_keeps_host_and_container_plans(mount_inputs, capsys):
    store = mount_inputs
    host = store / "host.json"
    marker = "untrusted-alias"
    host.write_bytes(b'{"codex_home":"/a","codex_home":"/' + marker.encode("ascii") + b'"}')
    code, result = invoke(store, capsys, "--config", str(host))
    assert code == 1 and result["code"] == "document_invalid"
    assert marker not in json.dumps(result)
    host.write_text(json.dumps({"codex_home": "/unused", marker: True}), encoding="utf-8")
    code, result = invoke(store, capsys, "--config", str(host))
    assert code == 1 and result["code"] == "team_run_fields"
    assert marker not in json.dumps(result)
    host.write_text(json.dumps({"claude_home": "Q" * 16385}), encoding="utf-8")
    code, result = invoke(store, capsys, "--config", str(host))
    assert code == 1 and result["code"] == "document_size"
    assert "Q" * 80 not in json.dumps(result)
    host.write_text(json.dumps({"codex_home": "/unused", "claude_home": ""}), encoding="utf-8")
    status, plan = invoke(store, capsys, "--config", str(host))
    assert status == 0
    assert plan == {"create_argv": None, "isolation": None, "mode": "host", "mounts": [], "status": "ok"}

    config, _ = container_inputs(store)
    status, bare = invoke(store, capsys, "--config", str(config))
    assert status == 0 and bare["mode"] == "container", bare
    body = json.loads(config.read_text(encoding="utf-8"))
    body["codex_home"] = "/unused"
    body["claude_home"] = "/unused"
    config.write_text(json.dumps(body), encoding="utf-8")
    status, aliased = invoke(store, capsys, "--config", str(config))
    assert status == 0 and aliased == bare
    assert "/unused" not in json.dumps(aliased)


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


_IMAGE = "localhost/aegis-test@sha256:" + "a" * 64
_REPORT = """
printf 'keep=%s\\n' "$AEGIS_INSPECT_KEEP"
printf 'near=%s\\n' "$CLAUDE_CODEX_KEEP"
if [ -n "${CODEX_THREAD_ID+x}" ]; then printf 'session=present\\n'; else printf 'session=absent\\n'; fi
if [ -n "${CLAUDE_CODE_SESSION_ID+x}" ]; then printf 'claude-session=present\\n'; else printf 'claude-session=absent\\n'; fi
if [ -n "${OPENAI_API_KEY+x}" ]; then printf 'billing=present\\n'; else printf 'billing=absent\\n'; fi
if [ -n "${ANTHROPIC_API_KEY+x}" ]; then printf 'anthropic=present\\n'; else printf 'anthropic=absent\\n'; fi
if [ -n "${CLAUDE_CODE_EXTRA+x}" ]; then printf 'prefix=present\\n'; else printf 'prefix=absent\\n'; fi
if [ -n "${CODEX_CI+x}" ]; then printf 'marker=present\\n'; else printf 'marker=absent\\n'; fi
if [ -n "${PATH+x}" ]; then printf 'path=present\\n'; else printf 'path=absent\\n'; fi
if [ -n "${LANG+x}" ]; then printf 'lang=present\\n'; else printf 'lang=absent\\n'; fi
""".strip()
_FILTERED_REPORT = (
    "keep=before value\nnear=ordinary\nsession=absent\nclaude-session=absent\n"
    "billing=absent\nanthropic=absent\nprefix=absent\nmarker=absent\npath=present\nlang=present\n")


def _open_fds():
    return set(os.listdir("/proc/self/fd"))


def _absolute_sleep(search_path=None):
    found = shutil.which("sleep", path=search_path)
    if found is None:
        pytest.skip("sleep executable required")
    # The fake engine runs with cwd="/", so a relative PATH hit must be made absolute here.
    return os.path.abspath(found)


def _prepare_engine(store, script):
    bindir, workspace = store / "bin", store / "workspace"
    bindir.mkdir()
    workspace.mkdir()
    executable = bindir / "podman"
    executable.write_text("#!/bin/sh\n" + script + "\n", encoding="utf-8")
    executable.chmod(0o700)
    return workspace, str(bindir), ["podman", "image", "inspect", _IMAGE], executable


def _parent_environment():
    return {
        "PATH": "/usr/bin:/bin", "LANG": "C", "AEGIS_INSPECT_KEEP": "before value",
        "CLAUDE_CODEX_KEEP": "ordinary", "CODEX_THREAD_ID": "synthetic-session",
        "CLAUDE_CODE_SESSION_ID": "synthetic-claude-session", "OPENAI_API_KEY": "synthetic-billing",
        "ANTHROPIC_API_KEY": "synthetic-anthropic", "CLAUDE_CODE_EXTRA": "synthetic-prefix",
        "CODEX_CI": "synthetic-marker",
    }


def _use_environ(monkeypatch, environ):
    monkeypatch.setattr(adapter, "os", SimpleNamespace(**{**vars(adapter.os), "environ": environ}))


def _use_read(monkeypatch, read):
    monkeypatch.setattr(adapter, "os", SimpleNamespace(**{**vars(adapter.os), "read": read}))


def _use_popen(monkeypatch, popen):
    module = adapter.subprocess
    monkeypatch.setattr(adapter, "subprocess", SimpleNamespace(
        Popen=popen, DEVNULL=module.DEVNULL, PIPE=module.PIPE, TimeoutExpired=module.TimeoutExpired))


def _assert_reaped(process):
    assert process.stdout.closed
    assert process.returncode is not None and process.returncode < 0
    with pytest.raises(ProcessLookupError):
        os.kill(process.pid, 0)


def _refusal(caught, code, message=None):
    assert isinstance(caught.value, IsolationRefusal)
    assert caught.value.code == code
    assert str(caught.value) == code
    rendered = str(caught.value) + caught.value.message + json.dumps(caught.value.next_action)
    assert "synthetic" not in rendered and "untrusted" not in rendered
    assert "\n" not in caught.value.message and "\r" not in caught.value.message
    if message is None:
        assert caught.value.message == REFUSALS[code]
    else:
        assert caught.value.message == message
    assert caught.value.next_action == {"actor": "operator", "command": caught.value.message}


def test_image_launch_uses_registry_filtered_environment(engine_store, monkeypatch):
    """Invariant: the qualified inode starts with a no-host copy, not the live parent map."""
    workspace, search_path, argv, _executable = _prepare_engine(engine_store, _REPORT)
    source = _parent_environment()
    _use_environ(monkeypatch, environ=source)
    module = adapter.subprocess
    launched = []

    def popen(*args, **kwargs):
        assert kwargs["cwd"] == "/" and kwargs.get("shell") in (None, False)
        assert kwargs["stdin"] is module.DEVNULL and kwargs["stdout"] is module.PIPE
        assert kwargs["stderr"] is module.DEVNULL
        assert kwargs["executable"].startswith("/proc/self/fd/") and len(kwargs["pass_fds"]) == 1
        environment = kwargs["env"]
        assert environment["AEGIS_INSPECT_KEEP"] == "before value"
        assert environment["CLAUDE_CODEX_KEEP"] == "ordinary" and environment["PATH"] == source["PATH"]
        assert environment["LANG"] == "C"
        for name in ("CODEX_THREAD_ID", "CLAUDE_CODE_SESSION_ID", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                     "CLAUDE_CODE_EXTRA", "CODEX_CI"):
            assert name not in environment
        source["AEGIS_INSPECT_KEEP"] = "after"
        source["OPENAI_API_KEY"] = "synthetic-billing-changed"
        launched.append(environment)
        return module.Popen(*args, **kwargs)

    _use_popen(monkeypatch, popen)
    before = _open_fds()
    assert adapter.inspect_image(argv, workspace=workspace, search_path=search_path) == _FILTERED_REPORT.encode()
    assert _open_fds() == before and len(launched) == 1
    source["AEGIS_INSPECT_KEEP"] = "before value"
    del source["OPENAI_API_KEY"]
    source["OPENAI_API_KEY"] = "synthetic-billing"
    assert adapter.inspect_image(argv, workspace=workspace, search_path=search_path) == _FILTERED_REPORT.encode()
    assert len(launched) == 2 and launched[0] is not launched[1]


class _ThreadEnvironment:
    def __init__(self):
        self.local = threading.local()

    def items(self):
        payload = self.local.payload
        if payload is None:
            raise ValueError("synthetic-untrusted")
        return payload.items()


def test_image_environment_is_isolated_across_concurrent_launches(engine_store, monkeypatch):
    """Concurrent launches snapshot their own no-host maps. A policy failure does not stop the others."""
    workspace, search_path, argv, _executable = _prepare_engine(engine_store, _REPORT)
    environ = _ThreadEnvironment()
    _use_environ(monkeypatch, environ=environ)
    barrier = threading.Barrier(3)
    outcome = {}

    def worker(name):
        if name == "bad":
            environ.local.payload = None
        else:
            payload = _parent_environment()
            payload["AEGIS_INSPECT_KEEP"] = name
            environ.local.payload = payload
        try:
            barrier.wait(timeout=10)
            outcome[name] = adapter.inspect_image(argv, workspace=workspace, search_path=search_path)
        except BaseException as exc:
            outcome[name] = exc

    before = _open_fds()
    threads = [threading.Thread(target=worker, args=(name,), name=name) for name in ("alpha", "beta", "bad")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert [thread.is_alive() for thread in threads] == [False, False, False]
    assert _open_fds() == before
    for name in ("alpha", "beta"):
        assert outcome[name] == _FILTERED_REPORT.replace("before value", name).encode(), outcome[name]
    assert isinstance(outcome["bad"], IsolationRefusal) and outcome["bad"].code == "image_inspect"
    assert "synthetic-untrusted" not in str(outcome["bad"]) + outcome["bad"].message


class _BadItems:
    def items(self):
        raise ValueError("synthetic-untrusted")


@pytest.mark.parametrize(("label", "environ"), [
    ("missing", None),
    ("bad-items", _BadItems()),
    ("nul", {"PATH": "/usr/bin", "AEGIS_INSPECT_KEEP": "synthetic\x00untrusted"}),
    ("non-string", {"PATH": "/usr/bin", "AEGIS_INSPECT_KEEP": 7}),
    ("equals", {"PATH": "/usr/bin", "AEGIS=INSPECT": "synthetic-untrusted"}),
    ("surrogate-value", {"PATH": "/usr/bin", "AEGIS_INSPECT_KEEP": "synthetic\ud800untrusted"}),
    ("surrogate-key", {"PATH": "/usr/bin", "AEGIS\ud800KEEP": "synthetic-untrusted"}),
], ids=["missing", "bad-items", "nul", "non-string", "equals", "surrogate-value", "surrogate-key"])
def test_image_environment_policy_failure_refuses_before_spawn_and_retries(engine_store, monkeypatch, label, environ):
    """Policy failure is image_inspect before spawn. A later valid environment still launches."""
    marker = engine_store / ("spawned-" + label)
    script = ": > %s\nprintf '[]'\n" % shlex.quote(str(marker))
    workspace, search_path, argv, executable = _prepare_engine(engine_store, script)
    _use_environ(monkeypatch, environ=environ)
    module = adapter.subprocess
    launched = []

    def popen(*args, **kwargs):
        launched.append(kwargs.get("env"))
        return module.Popen(*args, **kwargs)

    _use_popen(monkeypatch, popen)
    before = _open_fds()
    with pytest.raises(ValueError, match="^image_inspect$") as caught:
        adapter.inspect_image(argv, workspace=workspace, search_path=search_path)
    _refusal(caught, "image_inspect", "Retry from a clean launcher environment.")
    assert caught.value.stage is None
    assert REFUSALS["image_inspect"] not in caught.value.message
    assert launched == [] and not marker.exists() and _open_fds() == before
    _use_environ(monkeypatch, environ=_parent_environment())
    executable.write_text("#!/bin/sh\n" + script + "\n", encoding="utf-8")
    executable.chmod(0o700)
    assert adapter.inspect_image(argv, workspace=workspace, search_path=search_path) == b"[]"
    assert marker.is_file() and len(launched) == 1
    assert "OPENAI_API_KEY" not in launched[0] and launched[0]["AEGIS_INSPECT_KEEP"] == "before value"
    assert _open_fds() == before


def test_non_dict_environment_policy_refuses_before_spawn_and_retries(engine_store, monkeypatch):
    workspace, search_path, argv, _executable = _prepare_engine(engine_store, "printf '[]'\n")
    registry = adapter.team_host_registry
    module = adapter.subprocess
    launched = []

    def policy(environ, purpose):
        assert purpose == "no-host" and environ == source
        return [("OPENAI_API_KEY", "synthetic-billing")]

    source = _parent_environment()
    _use_environ(monkeypatch, environ=source)

    def popen(*args, **kwargs):
        launched.append(kwargs.get("env"))
        return module.Popen(*args, **kwargs)

    _use_popen(monkeypatch, popen)
    monkeypatch.setattr(adapter, "team_host_registry", SimpleNamespace(
        child_environment=policy, HostRefusal=registry.HostRefusal))
    before = _open_fds()
    with pytest.raises(ValueError, match="^image_inspect$") as caught:
        adapter.inspect_image(argv, workspace=workspace, search_path=search_path)
    _refusal(caught, "image_inspect", "Retry from a clean launcher environment.")
    assert caught.value.stage is None
    assert "OPENAI_API_KEY" not in caught.value.message
    assert launched == [] and _open_fds() == before
    monkeypatch.setattr(adapter, "team_host_registry", registry)
    assert adapter.inspect_image(argv, workspace=workspace, search_path=search_path) == b"[]"
    assert len(launched) == 1 and "OPENAI_API_KEY" not in launched[0]
    assert _open_fds() == before


def _bind_selector(monkeypatch, select):
    class _Selector:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def register(self, stream, event):
            return None

        def select(self, timeout=None):
            return select(timeout)

    monkeypatch.setattr(adapter, "selectors", SimpleNamespace(
        DefaultSelector=_Selector, EVENT_READ=adapter.selectors.EVENT_READ))


def _two_tick_clock(monkeypatch, first, later):
    ticks = {"count": 0}

    def monotonic():
        ticks["count"] += 1
        return first if ticks["count"] == 1 else later

    monkeypatch.setattr(adapter, "time", SimpleNamespace(monotonic=monotonic))
    return ticks


def _install_clock(monkeypatch, now):
    monkeypatch.setattr(adapter, "time", SimpleNamespace(monotonic=lambda: now[0]))


def _expired_clock(monkeypatch):
    ticks = {"count": 0}

    def monotonic():
        ticks["count"] += 1
        return 0 if ticks["count"] == 1 else 31

    monkeypatch.setattr(adapter, "time", SimpleNamespace(monotonic=monotonic))
    return ticks


@pytest.mark.parametrize("mode", ["before-read", "empty-selector", "wait-timeout", "selector-error"])
def test_image_timeout_seams_refuse_close_and_reap_then_retry(engine_store, monkeypatch, mode):
    """Deadline, empty select, wait timeout and select failure close the pipe and reap the child."""
    sleep = shlex.quote(_absolute_sleep())
    sleeping = mode != "wait-timeout"
    script = "exec " + sleep + " 60" if sleeping else "printf '[]'\nexec 1>&-\nexec " + sleep + " 60"
    workspace, search_path, argv, executable = _prepare_engine(engine_store, script)
    module = adapter.subprocess
    seen = []
    waits = []
    reads = []
    now = [0.0]
    real_read = os.read

    def read(fd, size):
        chunk = real_read(fd, size)
        reads.append(chunk)
        if chunk == b"":
            now[0] = 29.5
        return chunk

    def popen(*args, **kwargs):
        process = module.Popen(*args, **kwargs)
        real_wait = process.wait

        def wait(timeout=None):
            waits.append(timeout)
            return real_wait(timeout)

        process.wait = wait
        seen.append(process)
        return process

    def counting_read(fd, size):
        reads.append(b"called")
        return real_read(fd, size)

    controlled = _parent_environment()
    controlled["PATH"] = search_path
    _use_environ(monkeypatch, environ=controlled)
    timeouts = []
    origin, later = 10.0, 10.5
    budget = origin + adapter._INSPECT_SECONDS - later

    def record_select(timeout=None):
        timeouts.append(timeout)
        if mode == "selector-error":
            raise OSError(errno.EBADF, "synthetic-untrusted")
        return []

    _use_popen(monkeypatch, popen)
    if mode == "before-read":
        _expired_clock(monkeypatch)
        _use_read(monkeypatch, read=counting_read)
        _bind_selector(monkeypatch, record_select)
    elif mode == "wait-timeout":
        _use_read(monkeypatch, read=read)
        _install_clock(monkeypatch, now)
    elif mode == "empty-selector":
        _two_tick_clock(monkeypatch, origin, later)
        _use_read(monkeypatch, read=counting_read)
        _bind_selector(monkeypatch, record_select)
    else:
        _two_tick_clock(monkeypatch, origin, later)
        _use_read(monkeypatch, read=counting_read)
        _bind_selector(monkeypatch, record_select)
    before = _open_fds()
    expected = "image_inspect" if mode == "selector-error" else "image_inspect_timeout"
    with pytest.raises(ValueError, match="^" + expected + "$") as caught:
        adapter.inspect_image(argv, workspace=workspace, search_path=search_path)
    _refusal(caught, expected)
    assert len(seen) == 1 and _open_fds() == before
    _assert_reaped(seen[0])
    # Popen's context exit also waits, with no timeout. Only the product wait is timed.
    timed = [item for item in waits if item is not None]
    if mode == "wait-timeout":
        assert b"" in reads and len(timed) == 1 and 0 < timed[0] < 1
    else:
        assert reads == [] and timed == []
    if mode == "before-read":
        assert timeouts == []
    elif mode in ("empty-selector", "selector-error"):
        assert timeouts == [budget]
    monkeypatch.setattr(adapter, "time", time)
    monkeypatch.setattr(adapter, "selectors", __import__("selectors"))
    _use_read(monkeypatch, read=real_read)
    executable.write_text("#!/bin/sh\nprintf '[]'\n", encoding="utf-8")
    executable.chmod(0o700)
    assert adapter.inspect_image(argv, workspace=workspace, search_path=search_path) == b"[]"
    assert _open_fds() == before


@pytest.mark.parametrize("mode", ["before-read", "wait-timeout"])
def test_image_timeout_kill_race_preserves_refusal_and_reaps(engine_store, monkeypatch, mode):
    """A kill that loses the pid must not replace the timeout refusal or leak the pipe."""
    sleep = shlex.quote(_absolute_sleep())
    script = "exec " + sleep + " 60" if mode == "before-read" else "printf '[]'\nexec 1>&-\nexec " + sleep + " 60"
    workspace, search_path, argv, _executable = _prepare_engine(engine_store, script)
    module = adapter.subprocess
    seen = []
    now = [0.0]

    def read(fd, size):
        chunk = os.read(fd, size)
        if chunk == b"":
            now[0] = 29.5
        return chunk

    def popen(*args, **kwargs):
        process = module.Popen(*args, **kwargs)
        real_kill = process.kill

        def kill():
            real_kill()
            raise ProcessLookupError(errno.ESRCH, "synthetic-untrusted")

        process.kill = kill
        process.poll = lambda: None
        seen.append(process)
        return process

    controlled = _parent_environment()
    controlled["PATH"] = search_path
    _use_environ(monkeypatch, environ=controlled)
    timeouts = []

    def record_select(timeout=None):
        timeouts.append(timeout)
        return []

    _use_popen(monkeypatch, popen)
    if mode == "before-read":
        _expired_clock(monkeypatch)
        _bind_selector(monkeypatch, record_select)
    else:
        _use_read(monkeypatch, read=read)
        _install_clock(monkeypatch, now)
    before = _open_fds()
    with pytest.raises(ValueError, match="^image_inspect_timeout$") as caught:
        adapter.inspect_image(argv, workspace=workspace, search_path=search_path)
    _refusal(caught, "image_inspect_timeout")
    assert len(seen) == 1 and seen[0].stdout.closed and seen[0].returncode is not None
    with pytest.raises(ProcessLookupError):
        os.kill(seen[0].pid, 0)
    assert _open_fds() == before
    if mode == "before-read":
        assert timeouts == []


def test_image_chunk_cannot_refresh_the_read_budget(engine_store, monkeypatch):
    """One delivered chunk still expires at the original deadline. The next select is not a fresh window."""
    sleep = shlex.quote(_absolute_sleep())
    workspace, search_path, argv, executable = _prepare_engine(engine_store, "exec " + sleep + " 60")
    module = adapter.subprocess
    seen = []
    timeouts = []
    reads = []
    origin, later, expired = 5.0, 5.25, 35.0
    samples = [origin, later]

    def monotonic():
        return samples.pop(0) if samples else expired

    def read(fd, size):
        reads.append(size)
        return b"x" if len(reads) == 1 else b""

    def select(timeout=None):
        timeouts.append(timeout)
        return [object()]

    def popen(*args, **kwargs):
        process = module.Popen(*args, **kwargs)
        seen.append(process)
        return process

    controlled = _parent_environment()
    controlled["PATH"] = search_path
    _use_environ(monkeypatch, environ=controlled)
    _use_read(monkeypatch, read=read)
    monkeypatch.setattr(adapter, "time", SimpleNamespace(monotonic=monotonic))
    _bind_selector(monkeypatch, select)
    _use_popen(monkeypatch, popen)
    before = _open_fds()
    with pytest.raises(ValueError, match="^image_inspect_timeout$") as caught:
        adapter.inspect_image(argv, workspace=workspace, search_path=search_path)
    _refusal(caught, "image_inspect_timeout")
    assert timeouts == [origin + adapter._INSPECT_SECONDS - later]
    assert reads == [8192]
    assert len(seen) == 1 and _open_fds() == before
    _assert_reaped(seen[0])
    monkeypatch.setattr(adapter, "time", time)
    monkeypatch.setattr(adapter, "selectors", __import__("selectors"))
    _use_read(monkeypatch, read=os.read)
    executable.write_text("#!/bin/sh\nprintf '[]'\n", encoding="utf-8")
    executable.chmod(0o700)
    assert adapter.inspect_image(argv, workspace=workspace, search_path=search_path) == b"[]"
    assert _open_fds() == before


def test_fixture_tools_are_absolute_under_a_relative_path(tmp_path):
    """A relative caller PATH entry still yields an absolute fake-engine tool (cwd is '/')."""
    tools = tmp_path / "toolchain" / "bin"
    tools.mkdir(parents=True)
    fake = tools / "sleep"
    fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake.chmod(0o700)
    found = _absolute_sleep(os.path.relpath(tools))
    assert os.path.isabs(found) and os.path.samefile(found, fake)
