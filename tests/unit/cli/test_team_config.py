"""Team configuration commands use independent, actionable envelopes."""
import argparse
import json
import os

import pytest

from aegis_cli import team
from aegis_core import team_profile as profile


def invoke(root, capsys, *argv):
    parser = argparse.ArgumentParser()
    team.TeamCommand().configure_parser(parser)
    args = parser.parse_args(list(argv) + ["--json"])
    args.workspace = str(root)
    rc = team.run_team(args)
    return rc, json.loads(capsys.readouterr().out)


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    return tmp_path.resolve()


def test_show_and_presets(isolated, capsys, monkeypatch):
    monkeypatch.setattr(profile, "load", lambda root: profile.resolve())
    rc, doc = invoke(isolated, capsys, "config", "show")
    assert rc == 0
    assert doc["schema"] == "aegis.team.config.show/v1"
    assert doc["schema_family"] == "aegis.team.config/v1"
    assert doc["values"]["policy.review.require_cross_family"]["value"] is False
    assert doc["governance"]["path"] == ".aegis/team/profile.json"
    assert doc["governance"]["approval_required_before_merge"] is True
    assert doc["governance"]["approval"] == "not checked"
    assert doc["next_action"]
    rc, doc = invoke(isolated, capsys, "config", "presets")
    assert rc == 0
    assert set(doc["presets"]) == {"solo", "pair", "mixed", "ci-only"}


def test_init_and_refuse(isolated, capsys):
    if not profile.descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    rc, doc = invoke(isolated, capsys, "config", "init", "--preset", "solo")
    assert rc == 0 and doc["status"] == "done"
    assert doc["governance"]["approval_required_before_merge"] is True
    assert "approve" in doc["next_action"]
    rc, doc = invoke(isolated, capsys, "config", "init", "--preset", "solo")
    assert rc == 1 and doc["status"] == "refused"
    assert doc["reason"] and doc["next_action"]
    rc, doc = invoke(isolated, capsys, "config", "init", "--preset", "pair", "--force")
    assert rc == 0
    assert doc["governance"]["approval_required_before_merge"] is True


@pytest.mark.parametrize("installed,expected,suggest", [
    ([], 1, []), (["codex"], 0, []), (["codex", "claude", "other"], 0, ["pair", "mixed"]),
])
def test_doctor_fake_path(isolated, capsys, monkeypatch, installed, expected, suggest):
    monkeypatch.setattr(profile, "load", lambda root: profile.resolve())
    binaries = isolated / "bin"
    binaries.mkdir()
    workspace = isolated / "project"
    workspace.mkdir()
    for name in installed:
        target = binaries / (name + (".exe" if os.name == "nt" else ""))
        target.write_text("fake CLI; never executed")
        if os.name == "posix":
            target.chmod(0o755)
    monkeypatch.setenv("PATH", str(binaries))
    rc, doc = invoke(workspace, capsys, "doctor")
    assert rc == expected
    assert doc["schema"] == "aegis.team.doctor/v1"
    assert doc["suggested_presets"] == suggest
    assert doc["checks"]["login"] == "not checked"
    assert doc["governance"]["approval_required_before_merge"] is True
    assert doc["next_action"]


def test_claude_writer_boundary(isolated, capsys, monkeypatch):
    resolved = profile.resolve(repo={"model_settings": {"hosts": {"primary": {"kind": "claude-code"}}}})
    monkeypatch.setattr(profile, "load", lambda root: resolved)
    rc, doc = invoke(isolated, capsys, "config", "show")
    assert rc == 0
    assert "write scope: permission rules, not OS-enforced" in doc["write_scope"]


def test_failure_never_echoes_input(isolated, capsys, monkeypatch):
    def failed(root):
        raise OSError("token=secret\n\x1b[31m")
    monkeypatch.setattr(profile, "load", failed)
    rc, doc = invoke(isolated, capsys, "config", "show")
    assert rc == 1 and doc["status"] == "refused"
    assert "secret" not in json.dumps(doc)


def test_public_entrypoint(isolated, capsys, monkeypatch):
    from aegis_cli.cli import main
    project = isolated / "project"
    (project / ".aegis" / "rules").mkdir(parents=True)
    monkeypatch.chdir(project)
    assert main(["team", "config", "presets", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["schema"] == "aegis.team.config.presets/v1"


def test_bad_preset_refuses_without_echo(isolated, capsys):
    rc, doc = invoke(isolated, capsys, "config", "init", "--preset", "token=secret")
    assert rc == 2 and doc["status"] == "refused"
    assert "secret" not in json.dumps(doc)


def test_init_binds_claude_host_and_doctor_uses_resolved_profile(isolated, capsys, monkeypatch):
    if not profile.descriptor_supported():
        pytest.skip("requires anchored profile I/O")
    workspace = isolated / "project"
    workspace.mkdir()
    rc, doc = invoke(workspace, capsys, "config", "init", "--preset", "solo", "--host", "claude-code")
    assert rc == 0
    assert doc["profile"]["model_settings"]["hosts"]["primary"]["kind"] == "claude-code"
    binaries = isolated / "bin"
    binaries.mkdir()
    cli = binaries / ("claude.exe" if os.name == "nt" else "claude")
    cli.write_text("never executed")
    if os.name == "posix":
        cli.chmod(0o755)
    monkeypatch.setenv("PATH", str(binaries))
    rc, doc = invoke(workspace, capsys, "doctor")
    assert rc == 0 and "solo" in doc["runnable_presets"]
    assert "write scope: permission rules, not OS-enforced" in doc["write_scope"]


@pytest.mark.parametrize("command", [("config", "show"), ("doctor",)])
@pytest.mark.parametrize("alias", ["home", "config"])
def test_config_commands_accept_user_root_aliases(isolated, capsys, monkeypatch, command, alias):
    from conftest import symlink_or_skip
    if not profile.descriptor_supported():
        pytest.skip("requires anchored profile I/O")
    workspace = isolated / "repo"
    workspace.mkdir()
    profile.initialize(workspace, "ci-only")
    home = isolated / "home"
    actual = isolated / "actual"
    actual.mkdir()
    if alias == "home":
        symlink_or_skip(actual, home, target_is_directory=True)
        config = actual / ".config"
    else:
        home.mkdir()
        symlink_or_skip(actual, home / ".config", target_is_directory=True)
        config = actual
    target = config / "aegis/team.json"
    target.parent.mkdir(mode=0o700, parents=True)
    target.write_text('{"version":1,"run_config":{"runners":{"local":{"cpus":3}}}}')
    monkeypatch.setenv("HOME", str(home))
    rc, doc = invoke(workspace, capsys, *command)
    assert rc == 0 and doc["status"] == "done"
    if command == ("doctor",):
        assert doc["healthy"] is True and "ci-only" in doc["runnable_presets"]
    else:
        assert doc["values"]["run_config.runners.local.cpus"]["value"] == 3
        assert doc["values"]["run_config.runners.local.cpus"]["layer"] == "user"


def test_refusal_json_identifies_file_and_does_not_reference_repo_docs(isolated, capsys):
    if not profile.descriptor_supported():
        pytest.skip("requires anchored profile I/O")
    target = isolated / ".aegis/team/profile.json"
    target.parent.mkdir(mode=0o700, parents=True)
    target.write_text('{"version":1,"run_config":{"oops":true}}')
    rc, doc = invoke(isolated, capsys, "config", "show")
    assert rc == 1
    assert doc["layer"] == "repo" and doc["file"] == str(target)
    assert "docs/" not in doc["next_action"]


@pytest.mark.parametrize("host_name", ["credentials", "token", "secret", "ghp_" + "x" * 24])
def test_display_preserves_identifiers_and_masks_only_secret_fields(isolated, capsys, monkeypatch, host_name):
    resolved = profile.resolve(repo={"model_settings": {"hosts": {host_name: {"kind": "codex-cli"}},
                                                        "roles": {"reviewer.correctness": {"hosts": [host_name]}}}},
                               user={"run_config": {"runners": {"local": {"credentials": "private-value"},
                                                                  "credentials": {"cpus": 1}}}})
    monkeypatch.setattr(profile, "load", lambda root: resolved)
    rc, doc = invoke(isolated, capsys, "config", "show")
    assert rc == 0
    assert doc["profile"]["model_settings"]["hosts"][host_name]["kind"] == "codex-cli"
    assert doc["values"]["model_settings.hosts." + host_name + ".kind"]["value"] == "codex-cli"
    assert doc["profile"]["model_settings"]["roles"]["reviewer.correctness"]["hosts"] == [host_name]
    assert doc["values"]["model_settings.roles.reviewer.correctness.hosts"]["value"] == [host_name]
    assert doc["profile"]["run_config"]["runners"]["credentials"] == {"cpus": 1}
    assert doc["profile"]["run_config"]["runners"]["local"]["credentials"] == "[REDACTED]"
    assert "private-value" not in json.dumps(doc)


def test_display_preserves_lens_identifiers_that_resemble_secrets(isolated, capsys, monkeypatch):
    name = "ghp_" + "x" * 24
    resolved = profile.resolve(repo={"policy": {"review": {"lenses": [
        {"name": name, "host_pref": ["primary"], "voting": False}]}}})
    monkeypatch.setattr(profile, "load", lambda root: resolved)
    rc, doc = invoke(isolated, capsys, "config", "show")
    assert rc == 0
    assert doc["profile"]["policy"]["review"]["lenses"][0]["name"] == name
    assert doc["values"]["policy.review.lenses"]["value"][0]["name"] == name


@pytest.mark.parametrize("command", [("config", "show"), ("doctor",)])
def test_home_lookup_keyerror_is_a_layered_refusal(isolated, capsys, monkeypatch, command):
    from types import SimpleNamespace
    from aegis_core.workspace import layout

    def missing_user(uid):
        raise KeyError("uid absent from passwd")

    pwd_lookup = SimpleNamespace(getpwuid=missing_user)

    class LookupPath:
        @staticmethod
        def home():
            return pwd_lookup.getpwuid(0)

    monkeypatch.delenv("HOME", raising=False)
    monkeypatch.delenv("USERPROFILE", raising=False)
    # Module-owned Path facades reproduce Python 3.9's pwd KeyError without
    # modifying the global pwd/Path objects pytest may use at teardown.
    monkeypatch.setattr(profile, "Path", LookupPath)
    monkeypatch.setattr(layout, "Path", LookupPath)
    rc, doc = invoke(isolated, capsys, *command)
    assert rc == 1 and doc["status"] == "refused"
    assert doc["layer"] == "user" and doc["file"] == "~/.config/aegis/team.json"
    assert "uid absent" not in json.dumps(doc)


def test_fresh_claude_only_machine_reports_an_executable_solo_binding(isolated, capsys, monkeypatch):
    from types import SimpleNamespace
    if not profile.descriptor_supported():
        pytest.skip("requires anchored profile I/O")
    monkeypatch.setattr(profile, "pathlookup", SimpleNamespace(which=lambda name, **kw: "/qualified/claude" if name == "claude" else None))
    rc, doc = invoke(isolated, capsys, "doctor")
    assert rc == 1 and doc["healthy"] is False
    assert "solo" in doc["runnable_presets"]
    bindings = [item for item in doc["runnable_bindings"] if item["preset"] == "solo"]
    assert bindings and bindings[0]["host"] == "claude-code"
    assert bindings[0]["hosts"] == {"primary": "claude-code"}
    assert "aegis team config init --preset solo --host claude-code" in doc["next_action"]
    rc, initialized = invoke(isolated, capsys, "config", "init", "--preset", "solo", "--host", "claude-code")
    assert rc == 0
    rc, doc = invoke(isolated, capsys, "doctor")
    assert rc == 0 and doc["healthy"] is True


@pytest.mark.parametrize("preset", ["pair", "mixed"])
def test_init_keeps_pinned_security_on_codex_and_reports_all_bindings(isolated, capsys, preset):
    if not profile.descriptor_supported():
        pytest.skip("requires anchored profile I/O")
    rc, doc = invoke(isolated, capsys, "config", "init", "--preset", preset, "--host", "claude-code")
    assert rc == 0
    settings = doc["profile"]["model_settings"]
    for role, kind in (("writer", "claude-code"), ("reviewer.correctness", "codex-cli"), ("reviewer.security", "codex-cli")):
        chain = settings["roles"][role]["hosts"]
        assert chain and all(settings["hosts"][name]["kind"] == kind for name in chain)
    assert settings == profile.load(isolated, user_root=isolated)["profile"]["model_settings"]


@pytest.mark.parametrize("preset", ["ci-only", "solo", "pair", "mixed"])
@pytest.mark.parametrize("command", [("config", "show"), ("doctor",)])
def test_global_user_preferences_do_not_refuse_commands(isolated, capsys, monkeypatch, preset, command):
    from types import SimpleNamespace
    if not profile.descriptor_supported():
        pytest.skip("requires anchored profile I/O")
    profile.initialize(isolated, preset)
    user_file = isolated.joinpath(*profile.USER_PATH)
    user_file.parent.mkdir(mode=0o700, parents=True)
    user_file.write_text(json.dumps({"version": 1, "model_settings": {
        "roles": {"writer": {"model": "preferred", "hosts": ["primary"]}, "lens.extra": {"model": "extra"}},
        "hosts": {"codex-cli": {"auth_mode": "sso"}, "codex": {"auth_mode": "token"}},
        "capacity": {"codex-cli": {"thresholds": {"hold_pct": 80}}}}}))
    monkeypatch.setattr(profile, "pathlookup", SimpleNamespace(which=lambda *a, **kw: "/qualified/cli"))
    rc, doc = invoke(isolated, capsys, *command)
    assert rc == 0 and doc["status"] == "done"
    if command == ("config", "show"):
        assert doc["values"]["user.model_settings.hosts.codex.auth_mode"]["status"] == "ignored"


@pytest.mark.parametrize("command", [("config", "show"), ("doctor",)])
def test_malformed_user_file_refuses_with_its_own_path(isolated, capsys, command):
    if not profile.descriptor_supported():
        pytest.skip("requires anchored profile I/O")
    target = isolated.joinpath(*profile.USER_PATH)
    target.parent.mkdir(mode=0o700, parents=True)
    target.write_text('{"version":1,"model_settings":{"roles":{"unknown":{}}}}')
    rc, doc = invoke(isolated, capsys, *command)
    assert rc == 1 and doc["status"] == "refused"
    assert doc["layer"] == "user" and doc["file"] == str(target)


@pytest.mark.parametrize("machine", [False, True])
@pytest.mark.parametrize("name", ["gate token=super-secret-credential", "x" * 490 + " token=\x1b[31msuper-secret-credential"])
def test_gate_free_text_is_redacted_in_profile_and_provenance(isolated, capsys, monkeypatch, machine, name):
    resolved = profile.resolve(repo={"policy": {"gates": [
        {"name": name, "runner": "local", "selector": "whole", "must_pass": True}]}})
    monkeypatch.setattr(profile, "load", lambda root: resolved)
    parser = argparse.ArgumentParser()
    team.TeamCommand().configure_parser(parser)
    args = parser.parse_args(["config", "show"] + (["--json"] if machine else []))
    args.workspace = str(isolated)
    args.json = machine
    assert team.run_team(args) == 0
    output = capsys.readouterr().out
    assert "super-secret-credential" not in output and "\\u001b" not in output
    doc = json.loads(output)
    for gate in (doc["profile"]["policy"]["gates"][0], doc["values"]["policy.gates"]["value"][0]):
        assert "REDACTED" in gate["name"] and len(gate["name"]) <= 512


@pytest.mark.parametrize("preset,installed", [(None, []), ("pair", ["codex"])])
def test_doctor_leads_with_installation_and_preserves_current_policy(isolated, capsys, monkeypatch, preset, installed):
    from types import SimpleNamespace
    if not profile.descriptor_supported():
        pytest.skip("requires anchored profile I/O")
    if preset is not None:
        profile.initialize(isolated, preset)
    target = isolated.joinpath(*profile.REPO_PATH)
    before = target.read_bytes() if target.exists() else None
    monkeypatch.setattr(profile, "pathlookup", SimpleNamespace(which=lambda name, **kw: "/qualified/" + name if name in installed else None))
    rc, doc = invoke(isolated, capsys, "doctor")
    assert rc == 1
    action = doc["next_action"]
    assert action.startswith("Install ") and ("claude" if preset == "pair" else "codex") in action
    assert "init" not in action and "--force" not in action
    assert (target.read_bytes() if target.exists() else None) == before


@pytest.mark.parametrize("command", [("config", "show"), ("doctor",)])
@pytest.mark.parametrize("repo_defect", [True, False])
def test_counterfactual_refusals_name_the_actual_file(isolated, capsys, command, repo_defect):
    if not profile.descriptor_supported():
        pytest.skip("requires anchored profile I/O")
    repo_file = isolated.joinpath(*profile.REPO_PATH)
    repo_file.parent.mkdir(mode=0o700, parents=True)
    repo_file.write_text(json.dumps({"version": 1, "preset": "pair", "model_settings": {
        "roles": {"research": {"pinned_family": True}}} if repo_defect else {}}))
    user_file = isolated.joinpath(*profile.USER_PATH)
    user_file.parent.mkdir(mode=0o700, parents=True)
    user_file.write_text(json.dumps({"version": 1, "model_settings": {"roles": {
        "research": {"hosts": ["primary", "review"]}}}, **({} if repo_defect else {"unknown": True})}))
    rc, doc = invoke(isolated, capsys, *command)
    assert rc == 1 and doc["status"] == "refused"
    assert doc["layer"] == ("repo" if repo_defect else "user")
    assert doc["file"] == str(repo_file if repo_defect else user_file)


def test_component_provenance_redacts_dotted_runner_credentials(isolated, capsys, monkeypatch):
    resolved = profile.resolve(user={"run_config": {"runners": {
        "dot.runner": {"cpus": 1, "credentials": "private-credential"}}}})
    monkeypatch.setattr(profile, "load", lambda root: resolved)
    rc, doc = invoke(isolated, capsys, "config", "show")
    assert rc == 0
    assert "private-credential" not in json.dumps(doc)
    assert doc["profile"]["run_config"]["runners"]["dot.runner"]["credentials"] == "[REDACTED]"
    record = next(record for record in doc["values"].values() if record["path"] == ["run_config", "runners", "dot.runner", "credentials"])
    assert record["value"] == "[REDACTED]"


@pytest.mark.parametrize("preset", ["solo", "ci-only"])
def test_doctor_never_proposes_init_for_customized_repository(isolated, capsys, monkeypatch, preset):
    from types import SimpleNamespace
    if not profile.descriptor_supported():
        pytest.skip("requires anchored profile I/O")
    document = {"version": 1, "preset": preset, "policy": {"review": {"require_cross_family": True}},
                "model_settings": {"hosts": {"primary": {"kind": "codex-cli"}, "review": {"kind": "claude-code"}},
                                   "roles": {"writer": {"hosts": ["primary"]},
                                             "reviewer.correctness": {"hosts": ["review"]},
                                             "reviewer.security": {"hosts": ["review"]}}}}
    target = isolated.joinpath(*profile.REPO_PATH)
    target.parent.mkdir(mode=0o700, parents=True)
    target.write_text(json.dumps(document))
    before = target.read_bytes()
    monkeypatch.setattr(profile, "pathlookup", SimpleNamespace(which=lambda name, **kw: "/qualified/codex" if name == "codex" else None))
    rc, doc = invoke(isolated, capsys, "doctor")
    assert rc == 1 and doc["status"] == "refused"
    assert doc["next_action"].startswith("Install ") and "claude" in doc["next_action"]
    assert "init" not in doc["next_action"] and "--force" not in doc["next_action"]
    assert target.read_bytes() == before


def test_doctor_never_proposes_init_for_existing_default_solo(isolated, capsys, monkeypatch):
    from types import SimpleNamespace
    if not profile.descriptor_supported():
        pytest.skip("requires anchored profile I/O")
    profile.initialize(isolated, "solo")
    monkeypatch.setattr(profile, "pathlookup", SimpleNamespace(which=lambda name, **kw: "/qualified/claude" if name == "claude" else None))
    rc, doc = invoke(isolated, capsys, "doctor")
    assert rc == 1 and "codex" in doc["next_action"]
    assert "init" not in doc["next_action"]


@pytest.mark.parametrize("absence_evidence", [None, True, 0, "false"])
def test_doctor_requires_confirmed_repository_absence_before_init_advice(isolated, capsys, monkeypatch, absence_evidence):
    from types import SimpleNamespace
    resolved = profile.resolve()
    if absence_evidence is not None:
        resolved["repository_profile_exists"] = absence_evidence
    monkeypatch.setattr(profile, "load", lambda root: resolved)
    monkeypatch.setattr(profile, "pathlookup", SimpleNamespace(which=lambda name, **kw: "/qualified/claude" if name == "claude" else None))
    rc, doc = invoke(isolated, capsys, "doctor")
    assert rc == 1
    assert "init" not in doc["next_action"]
