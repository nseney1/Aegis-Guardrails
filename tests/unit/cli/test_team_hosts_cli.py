"""Actionable host command envelopes and documented decision exit codes."""
import argparse
import json

import pytest

from aegis_cli import team
from aegis_core import team_hosts as hosts, team_profile as profile


def invoke(root, capsys, *argv, machine=True):
    parser = argparse.ArgumentParser()
    team.TeamCommand().configure_parser(parser)
    args = parser.parse_args(list(argv) + (["--json"] if machine else []))
    args.workspace, args.json = str(root), machine
    code = team.run_team(args)
    captured = capsys.readouterr()
    return code, json.loads(captured.out) if machine else captured.out + captured.err


@pytest.fixture
def configured(tmp_path, monkeypatch):
    doc = profile.resolve(repo={"model_settings": {
        "hosts": {"other": {"kind": "claude-code"}},
        "capacity": {"primary": {"usage_source": "subscription-window", "fallback": {"doc": ["other"]}}}}})
    monkeypatch.setattr(profile, "load", lambda root: doc)
    return tmp_path, doc


@pytest.mark.parametrize("decision,chain,used,expected", [
    ("go", [], 10, 0), ("hold", [], 100, 3),
    ("fallback:other", ["other"], 100, 4), ("skip", ["skip"], 100, 5)])
def test_check_exit_codes_and_standalone_context(configured, monkeypatch, capsys, decision, chain, used, expected):
    root, doc = configured
    doc["profile"]["model_settings"]["capacity"]["primary"]["fallback"]["doc"] = chain
    monkeypatch.setattr(hosts, "usage_adapter", lambda kind: hosts.FakeUsageAdapter({
        "primary": {"window": {"used_pct": used, "resets_at": "2026-11-16T22:00:00Z"}}}))
    code, out = invoke(root, capsys, "hosts", "check", "primary", "doc")
    assert code == expected and out["decision"] == decision
    assert out["schema"] == "aegis.team.hosts.check/v1" and out["status"] == "done"
    assert out["host"] == "primary" and out["kind"] == "doc"
    assert out["reason"] and out["next_action"] and out["write_scope"]
    assert out["governance"]["approval"] == "not checked"
    assert out["exit_codes"] == {"go": 0, "hold": 3, "fallback": 4, "skip": 5, "refused": 1, "usage": 2}


@pytest.mark.parametrize("verb", ("status", "usage"))
def test_read_commands_have_per_host_sources_and_no_totals(configured, capsys, verb):
    root, _ = configured
    code, doc = invoke(root, capsys, "hosts", verb)
    assert code == 0 and doc["status"] == "done"
    assert doc["schema"] == "aegis.team.hosts." + verb + "/v1"
    assert {row["host"] for row in doc["hosts"]} == {"primary", "other"}
    assert doc["hosts"][0]["usage_source"] == "subscription-window"
    assert doc["next_action"] and "total" not in doc
    if verb == "status":
        assert doc["hosts"][0]["decisions"]


def test_doctor_reports_usage_and_decisions(configured, monkeypatch, capsys):
    from types import SimpleNamespace
    root, _ = configured
    monkeypatch.setattr(profile, "pathlookup", SimpleNamespace(which=lambda *a, **kw: "/installed/cli"))
    code, doc = invoke(root, capsys, "doctor")
    assert code == 0
    assert doc["hosts"][0]["usage_source"] == "subscription-window"
    assert doc["hosts"][0]["decisions"]


@pytest.mark.parametrize("argv,code", [(("hosts",), 2), (("hosts", "check"), 2),
    (("hosts", "check", "token=private\nforged", "doc"), 2),
    (("hosts", "check", "primary", "token=private"), 2)])
def test_usage_refusals_do_not_echo_input(configured, capsys, argv, code):
    result, doc = invoke(configured[0], capsys, *argv)
    assert result == code and doc["status"] == "refused" and doc["next_action"]
    assert "private" not in json.dumps(doc)


@pytest.mark.parametrize("verb", ("check", "status", "usage"))
def test_unreadable_profile_refuses_before_usage(tmp_path, monkeypatch, capsys, verb):
    def unavailable(root):
        raise profile.ProfileError("unknown key", layer="repo", file=".aegis/team/profile.json")
    def never(kind):
        pytest.fail("profile refusal must precede adapter access")
    monkeypatch.setattr(profile, "load", unavailable)
    monkeypatch.setattr(hosts, "usage_adapter", never)
    code, doc = invoke(tmp_path, capsys, "hosts", verb, *(("primary", "doc") if verb == "check" else ()))
    assert code == 1 and doc["status"] == "refused" and doc["layer"] == "repo"


def test_unsupported_platform_uses_profile_refusal(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(profile, "descriptor_supported", lambda: False)
    code, doc = invoke(tmp_path, capsys, "hosts", "status")
    assert code == 1 and doc["status"] == "refused" and "unsupported platform" in doc["reason"]


@pytest.mark.parametrize("machine", (False, True))
def test_snapshot_display_canonicalizes_redacts_then_truncates(configured, monkeypatch, capsys, machine):
    root, doc = configured
    root = root / ("x" * max(0, 490 - len(str(root)) - 1) + " token=\x1b[31mprivate-credential")
    monkeypatch.setattr(hosts, "usage_adapter", lambda kind: hosts.FakeUsageAdapter({
        "primary": RuntimeError("token=private-credential\ntraceback")}))
    _, out = invoke(root, capsys, "hosts", "status", machine=machine)
    rendered = json.dumps(out) if machine else out
    assert "private-credential" not in rendered and "\\u001b" not in rendered
    assert "REDACTED" in rendered


def test_public_entrypoint(configured, monkeypatch, capsys):
    from aegis_cli.cli import main
    root, _ = configured
    (root / ".aegis/rules").mkdir(parents=True)
    monkeypatch.chdir(root)
    assert main(["team", "hosts", "usage", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["schema"] == "aegis.team.hosts.usage/v1"


def bind_graph(monkeypatch, *, roles=None, lenses=None, fallbacks=None, used=100):
    from types import SimpleNamespace
    document = {"preset": "ci-only", "model_settings": {
        "hosts": {"primary": {"kind": "codex-cli"}, "other": {"kind": "claude-code"}},
        "roles": roles or {}, "capacity": {"primary": {
            "usage_source": "subscription-window", "fallback": fallbacks or {}}}},
        "policy": {"review": {"lenses": lenses or []}}}
    monkeypatch.setattr(profile, "load", lambda root: profile.resolve(repo=document))
    monkeypatch.setattr(profile, "pathlookup", SimpleNamespace(which=lambda *a, **kw: "/installed/cli"))
    monkeypatch.setattr(hosts, "usage_adapter", lambda kind: hosts.FakeUsageAdapter({
        "primary": {"window": {"used_pct": used, "resets_at": "2026-11-16T22:00:00Z"}}}))
    return document


@pytest.mark.parametrize("kind", ("writer", "review", "reviewer.correctness", "reviewer.security",
                                   "research", "extra-review", "lens.extra", "audit"))
def test_absent_role_is_layered_refusal(tmp_path, monkeypatch, capsys, kind):
    bind_graph(monkeypatch)
    code, doc = invoke(tmp_path, capsys, "hosts", "check", "primary", kind)
    assert code == 1 and doc["status"] == "refused"
    assert doc["layer"] == "repo" and doc["file"].endswith(".aegis/team/profile.json")
    assert "not declared" in doc["reason"] and doc["next_action"]


@pytest.mark.parametrize("kind,generic", [("writer", "writer"), ("reviewer.correctness", "review"),
    ("reviewer.security", "review"), ("research", "research"), ("lens.extra", "extra-review"),
    ("audit", "review"), ("doc", "doc")])
@pytest.mark.parametrize("chain,expected,direct", [(["hold", "other"], "hold", 1),
    (["other", "hold"], "fallback:other", 0), (["hold", "skip", "other"], "hold", 1)])
def test_terminal_table_agrees_across_public_views(tmp_path, monkeypatch, capsys, kind, generic, chain, expected, direct):
    roles = {} if kind in ("audit", "doc") else {kind: {"hosts": ["primary"]}}
    lenses = [{"name": "audit", "host_pref": ["primary"], "voting": False}] if kind == "audit" else []
    bind_graph(monkeypatch, roles=roles, lenses=lenses, fallbacks={generic: chain})
    code, doc = invoke(tmp_path, capsys, "hosts", "check", "primary", kind)
    assert doc["decision"] == expected and code == (3 if expected == "hold" else 4)
    code, destination = invoke(tmp_path, capsys, "hosts", "check", "other", kind)
    # doc is explicitly generic and can start on any declared host.
    assert code == (0 if kind == "doc" else direct)
    if code == 1:
        assert destination["layer"] == "repo" and destination["file"] and destination["next_action"]
    for command in (("hosts", "status"), ("doctor",)):
        code, view = invoke(tmp_path, capsys, *command)
        assert code == 0
        row = next(row for row in view["hosts"] if row.get("host", row.get("name")) == "primary")
        decision = next(item for item in row["decisions"] if item["kind"] == kind)
        assert decision["decision"] == expected


@pytest.mark.parametrize("kind,generic", [("research", "research"), ("lens.extra", "extra-review"), ("audit", "review")])
def test_skip_terminal_excludes_later_host(tmp_path, monkeypatch, capsys, kind, generic):
    bind_graph(monkeypatch, roles={} if kind == "audit" else {kind: {"hosts": ["primary"]}},
               lenses=[{"name": "audit", "host_pref": ["primary"], "voting": False}] if kind == "audit" else [],
               fallbacks={generic: ["skip", "other"]})
    assert invoke(tmp_path, capsys, "hosts", "check", "primary", kind)[0] == 5
    code, doc = invoke(tmp_path, capsys, "hosts", "check", "other", kind)
    assert code == 1 and doc["layer"] == "repo"


@pytest.mark.parametrize("alias,canonical", [("review", "reviewer.correctness"), ("extra-review", "lens.extra")])
@pytest.mark.parametrize("generic,specific,expected", [(["hold"], ["other"], "fallback:other"),
    (["other"], ["hold"], "hold"), (["other"], [], "hold")])
def test_aliases_canonicalize_before_override(tmp_path, monkeypatch, capsys, alias, canonical, generic, specific, expected):
    bind_graph(monkeypatch, roles={canonical: {"hosts": ["primary"]}},
               fallbacks={alias: generic, canonical: specific})
    for kind in (alias, canonical):
        _, doc = invoke(tmp_path, capsys, "hosts", "check", "primary", kind)
        assert doc["decision"] == expected
        assert invoke(tmp_path, capsys, "hosts", "check", "other", kind)[0] == (0 if expected == "fallback:other" else 1)


@pytest.mark.parametrize("kind,generic", [("reviewer.correctness", "review"),
    ("reviewer.security", "review"), ("lens.extra", "extra-review")])
def test_pinned_override_does_not_union_generic_chain(tmp_path, monkeypatch, capsys, kind, generic):
    bind_graph(monkeypatch, roles={kind: {"hosts": ["primary"], "pinned_family": True}},
               fallbacks={generic: ["other"], kind: ["hold", "other"]})
    for command in (("hosts", "check", "primary", kind), ("hosts", "status"), ("doctor",)):
        code, doc = invoke(tmp_path, capsys, *command)
        assert code == (3 if "check" in command else 0), doc
    assert invoke(tmp_path, capsys, "hosts", "check", "other", kind)[0] == 1


@pytest.mark.parametrize("lenses,reason", [([{"host_pref": ["primary"]}], "name required"),
    ([{"name": "audit"}], "host_pref required"),
    ([{"name": "audit", "host_pref": ["primary"]}, {"name": "audit", "host_pref": ["other"]}], "duplicate review lens name"),
    ([{"name": "audit", "host_pref": ["primary", "other"]},
      {"name": "audit", "host_pref": ["primary"], "pinned_family": True}], "duplicate review lens name")])
@pytest.mark.parametrize("command", [("hosts", "check", "primary", "audit"), ("hosts", "status"), ("doctor",)])
def test_lens_identity_refuses_at_load(tmp_path, monkeypatch, capsys, lenses, reason, command):
    bind_graph(monkeypatch, lenses=lenses)
    code, doc = invoke(tmp_path, capsys, *command)
    assert code == 1 and doc["status"] == "refused" and reason in doc["reason"]
    assert doc["layer"] == "repo" and doc["file"].endswith(".aegis/team/profile.json") and doc["next_action"]


@pytest.mark.parametrize("voting,expected", [(True, "go"), (False, "hold")])
def test_custom_lens_threshold_matches_voting_status(tmp_path, monkeypatch, capsys, voting, expected):
    bind_graph(monkeypatch, lenses=[{"name": "audit", "host_pref": ["primary"], "voting": voting}], used=90)
    _, doc = invoke(tmp_path, capsys, "hosts", "check", "primary", "audit")
    assert doc["decision"] == expected
    for command in (("hosts", "status"), ("doctor",)):
        _, view = invoke(tmp_path, capsys, *command)
        assert next(d for d in view["hosts"][0]["decisions"] if d["kind"] == "audit")["decision"] == expected


def test_writer_destination_boundary_in_check_status_and_doctor(tmp_path, monkeypatch, capsys):
    bind_graph(monkeypatch, roles={"writer": {"hosts": ["primary"]}}, fallbacks={"writer": ["other"]})
    for host in ("primary", "other"):
        code, doc = invoke(tmp_path, capsys, "hosts", "check", host, "writer")
        assert code == (4 if host == "primary" else 0)
        assert doc["selected_host"] == "other"
        assert doc["write_scope"] == ["write scope: permission rules, not OS-enforced"]
    for command in (("hosts", "status"), ("doctor",)):
        code, doc = invoke(tmp_path, capsys, *command)
        assert code == 0
        writer = next(d for d in doc["hosts"][0]["decisions"] if d["kind"] == "writer")
        assert writer["selected_host"] == "other" and "not OS-enforced" in str(writer["write_scope"])
        if command == ("doctor",):
            assert "not OS-enforced" in str(doc["write_scope"])


@pytest.mark.parametrize("kind", ("extra-review", "lens.extra"))
def test_empty_optional_role_is_layered_refusal(tmp_path, monkeypatch, capsys, kind):
    bind_graph(monkeypatch, roles={"lens.extra": {"hosts": [], "optional": True}})
    code, doc = invoke(tmp_path, capsys, "hosts", "check", "primary", kind)
    assert code == 1 and "disabled" in doc["reason"]
    assert doc["layer"] == "repo" and doc["file"] and doc["next_action"]


def test_nested_terminal_excludes_later_branches(tmp_path, monkeypatch, capsys):
    document = bind_graph(monkeypatch, roles={"research": {"hosts": ["primary"]}},
                          fallbacks={"research": ["other", "third"]})
    document["model_settings"]["hosts"]["third"] = {"kind": "codex-cli"}
    document["model_settings"]["capacity"]["other"] = {"fallback": {"research": ["hold"]}}
    assert invoke(tmp_path, capsys, "hosts", "check", "primary", "research")[0] == 4
    assert invoke(tmp_path, capsys, "hosts", "check", "third", "research")[0] == 1
    for command in (("hosts", "status"), ("doctor",)):
        code, doc = invoke(tmp_path, capsys, *command)
        assert code == 0
        assert all(d["kind"] != "research" for d in doc["hosts"][2]["decisions"])


@pytest.mark.parametrize("route", profile.CAPACITY_KINDS)
def test_argon_every_fallback_identifier_is_preserved(tmp_path, monkeypatch, capsys, route):
    from types import SimpleNamespace
    name = "ghp_" + "A" * 20
    roles = {} if route == "doc" else {({"review": "reviewer.correctness", "extra-review": "lens.extra"}.get(route, route)): {"hosts": ["primary"]}}
    document = {"preset": "ci-only", "model_settings": {
        "hosts": {"primary": {"kind": "codex-cli"}, name: {"kind": "claude-code"}},
        "roles": roles, "capacity": {"primary": {"usage_source": "subscription-window", "fallback": {route: [name]}}}}}
    monkeypatch.setattr(profile, "load", lambda root: profile.resolve(repo=document))
    monkeypatch.setattr(profile, "pathlookup", SimpleNamespace(which=lambda *a, **kw: "/installed/cli"))
    monkeypatch.setattr(hosts, "usage_adapter", lambda kind: hosts.FakeUsageAdapter({
        "primary": {"window": {"used_pct": 100, "resets_at": "2026-11-16T22:00:00Z"}}}))
    code, doc = invoke(tmp_path, capsys, "config", "show")
    assert code == 0 and doc["profile"]["model_settings"]["capacity"]["primary"]["fallback"][route] == [name]
    assert doc["values"]["model_settings.capacity.primary.fallback." + route]["value"] == [name]
    _, doc = invoke(tmp_path, capsys, "hosts", "check", "primary", route)
    assert doc["decision"] == "fallback:" + name and doc["selected_host"] == name
    for command in (("hosts", "usage"), ("hosts", "status"), ("doctor",)):
        code, doc = invoke(tmp_path, capsys, *command)
        assert code == 0
        assert doc["hosts"][1].get("host", doc["hosts"][1].get("name")) == name


@pytest.mark.parametrize("host,kind,code,layer", [("unknown", "writer", 2, "flags"),
    ("primary", "extra-review", 1, "repo"), ("primary", "audit", 1, "repo")])
def test_argon_capacity_refusals_always_identify_input(tmp_path, monkeypatch, capsys, host, kind, code, layer):
    bind_graph(monkeypatch, roles={"lens.extra": {"hosts": [], "optional": True}})
    actual, doc = invoke(tmp_path, capsys, "hosts", "check", host, kind)
    assert actual == code and doc["status"] == "refused"
    assert doc["layer"] == layer and doc["file"] and doc["next_action"]


def bind_later_host(monkeypatch, kind, *, cycle=False, pinned=False):
    canonical = {"review": "reviewer.correctness", "extra-review": "lens.extra"}.get(kind, kind)
    lens = canonical == "audit"
    role = {"hosts": ["primary", "other"], "pinned_family": pinned}
    document = bind_graph(monkeypatch, roles={} if lens else {canonical: role},
                          lenses=[{"name": "audit", "host_pref": ["primary", "other"],
                                   "voting": False, "pinned_family": pinned}] if lens else [])
    settings = document["model_settings"]
    if pinned:
        settings["hosts"]["other"]["kind"] = "codex-cli"
    route = "review" if lens else canonical
    settings["capacity"] = {
        "primary": {"usage_source": "credits", "fallback": {route: ["other"]} if cycle else {}},
        "other": {"usage_source": "credits", "fallback": {route: ["primary"]}},
    }
    monkeypatch.setattr(hosts, "usage_adapter", lambda host_kind: hosts.FakeUsageAdapter({
        "primary": {"credits_left": 0 if cycle else 1}, "other": {"credits_left": 0}}))


def later_host_decision(root, capsys, command, kind):
    if command == "check":
        code, doc = invoke(root, capsys, "hosts", "check", "other", kind)
        return code, doc
    code, doc = invoke(root, capsys, *(("doctor",) if command == "doctor" else ("hosts", "status")))
    assert code == 0
    canonical = {"review": "reviewer.correctness", "extra-review": "lens.extra"}.get(kind, kind)
    row = next(row for row in doc["hosts"] if row.get("host", row.get("name")) == "other")
    decision = next(item for item in row["decisions"] if item["kind"] == canonical)
    return decision["exit_code"], decision


@pytest.mark.parametrize("kind", ("writer", "reviewer.correctness", "review", "reviewer.security",
                                   "research", "lens.extra", "extra-review", "audit"))
@pytest.mark.parametrize("command", ("check", "status", "doctor"))
def test_later_host_can_fall_back_to_available_earlier_host(tmp_path, monkeypatch, capsys, kind, command):
    bind_later_host(monkeypatch, kind)
    code, decision = later_host_decision(tmp_path, capsys, command, kind)
    assert code == 4 and decision["decision"] == "fallback:primary"
    assert decision["selected_host"] == "primary"
    if kind == "writer":
        assert decision["write_boundary"]["host"] == "primary"
        assert "OS sandbox" in decision["write_scope"][0]


@pytest.mark.parametrize("kind", ("writer", "reviewer.correctness", "review", "reviewer.security",
                                   "research", "lens.extra", "extra-review", "audit"))
@pytest.mark.parametrize("command", ("check", "status", "doctor"))
def test_later_host_fallback_cycle_exhausts(tmp_path, monkeypatch, capsys, kind, command):
    bind_later_host(monkeypatch, kind, cycle=True)
    code, decision = later_host_decision(tmp_path, capsys, command, kind)
    assert code == 3 and decision["decision"] == "hold"
    assert "exhausted" in decision["reason"]


@pytest.mark.parametrize("command", ("check", "status", "doctor"))
def test_later_pinned_security_host_waits_for_its_own_capacity(tmp_path, monkeypatch, capsys, command):
    bind_later_host(monkeypatch, "reviewer.security", pinned=True)
    code, decision = later_host_decision(tmp_path, capsys, command, "reviewer.security")
    assert code == 3 and decision["decision"] == "hold" and "pinned" in decision["reason"]


@pytest.mark.parametrize("command", ("check", "status", "doctor"))
def test_next_action_preserves_identifiers_and_redacts_free_text(tmp_path, monkeypatch, capsys, command):
    from types import SimpleNamespace
    host, lens = "ghp_" + "A" * 20, "ghp_" + "L" * 20
    document = {"preset": "ci-only", "model_settings": {
        "hosts": {"primary": {"kind": "codex-cli"}, host: {"kind": "claude-code"}},
        "capacity": {"primary": {"usage_source": "credits", "fallback": {"review": [host]}},
                     host: {"usage_source": "credits"}}},
        "policy": {"review": {"lenses": [{"name": lens, "host_pref": ["primary"], "voting": False}]}}}
    monkeypatch.setattr(profile, "load", lambda root: profile.resolve(repo=document))
    monkeypatch.setattr(profile, "pathlookup", SimpleNamespace(which=lambda *a, **kw: "/installed/cli"))
    monkeypatch.setattr(hosts, "usage_adapter", lambda host_kind: hosts.FakeUsageAdapter({
        "primary": {"credits_left": 0}, host: {"credits_left": 1}}))
    root = tmp_path / "token=private-free-text"
    if command == "check":
        code, doc = invoke(root, capsys, "hosts", "check", "primary", lens)
        assert code == 4
        decision = doc
    else:
        code, doc = invoke(root, capsys, *(("doctor",) if command == "doctor" else ("hosts", "status")))
        assert code == 0
        decision = next(item for item in doc["hosts"][0]["decisions"] if item["kind"] == lens)
    expected = "aegis team hosts check " + host + " " + lens + " --json"
    assert expected in decision["next_action"]
    assert "private-free-text" not in json.dumps(doc) and "REDACTED" in doc["scope"]["workspace"]
    code, direct = invoke(root, capsys, "hosts", "check", host, lens)
    assert code == 0 and host in direct["next_action"]


def test_mcp_masks_capacity_identifier_while_cli_suggestion_keeps_it_runnable(tmp_path, monkeypatch, capsys):
    from copy import deepcopy
    from aegis_mcp.tools import execute_tool

    host = "ghp_" + "A" * 20
    resolved = profile.resolve(repo={"preset": "ci-only", "model_settings": {
        "hosts": {"primary": {"kind": "codex-cli"}, host: {"kind": "claude-code"}},
        "roles": {"writer": {"hosts": ["primary"]}},
        "capacity": {"primary": {"usage_source": "credits", "fallback": {"writer": [host]}},
                     host: {"usage_source": "credits"}}}})
    monkeypatch.setattr(profile, "load", lambda root: resolved)
    monkeypatch.setattr(hosts, "usage_adapter", lambda kind: hosts.FakeUsageAdapter({
        "primary": {"credits_left": 0}, host: {"credits_left": 1}}))
    code, decision = invoke(tmp_path, capsys, "hosts", "check", "primary", "writer")
    assert code == 4 and decision["selected_host"] == host
    assert decision["next_action"] == ("Run aegis team hosts check " + host +
                                       " writer --json; use that declared host if admitted.")
    code, config = invoke(tmp_path, capsys, "config", "show")
    assert code == 0
    assert config["profile"]["model_settings"]["capacity"]["primary"]["fallback"]["writer"] == [host]
    actual = execute_tool("aegis_team_config", {"workspace": str(tmp_path)})
    expected_profile, expected_values = deepcopy(config["profile"]), deepcopy(config["values"])
    expected_profile["model_settings"]["capacity"]["primary"]["fallback"]["writer"] = ["ghp_REDACTED"]
    expected_values["model_settings.capacity.primary.fallback.writer"]["value"] = ["ghp_REDACTED"]
    assert actual["status"] == "done" and actual["profile"] == expected_profile
    assert actual["values"] == expected_values


@pytest.mark.parametrize("terminal", ("hold", "skip"))
@pytest.mark.parametrize("command", ("check", "status", "doctor"))
@pytest.mark.parametrize("kind", (*profile.CAPACITY_KINDS, "audit-vote", "audit-flex"))
def test_reserved_terminal_host_refuses_across_views(tmp_path, monkeypatch, capsys, terminal, command, kind):
    from types import SimpleNamespace
    canonical = {"review": "reviewer.correctness", "extra-review": "lens.extra"}.get(kind, kind)
    lens = kind.startswith("audit-")
    route = "review" if lens else kind
    roles = {} if lens or kind == "doc" else {canonical: {"hosts": ["primary"]}}
    document = {"preset": "ci-only", "model_settings": {
        "hosts": {"primary": {"kind": "codex-cli"}, terminal: {"kind": "claude-code"}}, "roles": roles,
        "capacity": {"primary": {"usage_source": "credits", "fallback": {route: [terminal]}},
                     terminal: {"usage_source": "credits"}}}}
    if lens:
        document["policy"] = {"review": {"lenses": [
            {"name": kind, "host_pref": ["primary"], "voting": kind == "audit-vote"}]}}
    monkeypatch.setattr(profile, "load", lambda root: profile.resolve(repo=document))
    monkeypatch.setattr(profile, "pathlookup", SimpleNamespace(which=lambda *args, **kwargs: "/installed/cli"))
    monkeypatch.setattr(hosts, "usage_adapter", lambda kind: hosts.FakeUsageAdapter({
        "primary": {"credits_left": 0}, terminal: {"credits_left": 1}}))
    code, result = invoke(tmp_path, capsys, *(("hosts", "check", "primary", kind) if command == "check" else
                                           ("doctor",) if command == "doctor" else ("hosts", "status")))
    assert code == 1 and result["status"] == "refused"
    assert result["reason"] == "host alias is reserved for a fallback terminal"
    assert result["layer"] == "repo" and result["file"] and result["next_action"]


@pytest.mark.parametrize("terminal", ("hold", "skip"))
@pytest.mark.parametrize("command", ("check", "status", "usage", "doctor"))
def test_consumer_revalidation_refuses_reserved_host_aliases(tmp_path, monkeypatch, capsys, terminal, command):
    from types import SimpleNamespace
    snapshot = profile.resolve()
    settings = snapshot["profile"]["model_settings"]
    settings["hosts"][terminal] = {"kind": "claude-code"}
    settings["capacity"]["primary"] = {"fallback": {"doc": [terminal]}}
    monkeypatch.setattr(profile, "load", lambda root: snapshot)
    monkeypatch.setattr(profile, "pathlookup", SimpleNamespace(which=lambda *args, **kwargs: "/installed/cli"))
    code, result = invoke(tmp_path, capsys, *(("hosts", "check", "primary", "doc") if command == "check" else
                                           ("doctor",) if command == "doctor" else ("hosts", command)))
    assert code == 1 and result["status"] == "refused"
    assert result["reason"] == "host alias is reserved for a fallback terminal"
    assert result["layer"] == "repo" and result["file"] and result["next_action"]


@pytest.mark.parametrize("command", ("check", "status", "doctor"))
@pytest.mark.parametrize("start", ("primary", "other", "last"))
@pytest.mark.parametrize("backward", (False, True))
def test_arg1138_three_bound_hosts_preserve_declared_restart_order(tmp_path, monkeypatch, capsys, command, start, backward):
    from types import SimpleNamespace
    binding = ["primary", "other", "last"]
    document = {"preset": "solo", "model_settings": {
        "hosts": {name: {"kind": "codex-cli"} for name in binding},
        "roles": {"writer": {"hosts": binding}},
        "capacity": {name: {"usage_source": "credits"} for name in binding}}}
    document["model_settings"]["capacity"]["primary"]["fallback"] = {"writer": ["last"]}
    if backward:
        document["model_settings"]["capacity"]["last"]["fallback"] = {"writer": ["other"]}
    available = "last" if start == "other" else "other"
    monkeypatch.setattr(profile, "load", lambda root: profile.resolve(repo=document))
    monkeypatch.setattr(profile, "pathlookup", SimpleNamespace(which=lambda *args, **kwargs: "/installed/cli"))
    monkeypatch.setattr(hosts, "usage_adapter", lambda kind: hosts.FakeUsageAdapter({
        name: {"credits_left": int(name == available)} for name in binding}))
    if command == "check":
        code, decision = invoke(tmp_path, capsys, "hosts", "check", start, "writer")
    else:
        code, result = invoke(tmp_path, capsys, *(("doctor",) if command == "doctor" else ("hosts", "status")))
        assert code == 0
        row = next(row for row in result["hosts"] if row.get("host", row.get("name")) == start)
        decision = next(item for item in row["decisions"] if item["kind"] == "writer")
        code = decision["exit_code"]
    if start == "last" and not backward:
        assert code == 3 and decision["decision"] == "hold" and decision["selected_host"] == start
    else:
        assert code == 4 and decision["decision"] == "fallback:" + available
        assert decision["selected_host"] == available


def test_malformed_action_parts_do_not_exempt_free_text():
    doc = team.display_profile({"next_action": "token=private-action",
                                "next_action_parts": [{"identifier": "token=private-fragment"}]}, capacity=True)
    assert "private-action" not in json.dumps(doc) and "private-fragment" not in json.dumps(doc)


def test_structured_action_free_fragment_is_redacted_after_canonicalization():
    host = "ghp_" + "A" * 20
    doc = team.display_profile({"next_action": "unused", "next_action_parts": [
        "Use ", {"identifier": host}, {"text": " token=\x1b[31mprivate-fragment"}]}, capacity=True)
    assert host in doc["next_action"] and "REDACTED" in doc["next_action"]
    assert "private-fragment" not in json.dumps(doc) and "\\u001b" not in json.dumps(doc)


def test_unrecognized_action_literal_is_free_text():
    doc = team.display_profile({"next_action": "unused", "next_action_parts": ["token=private-fragment"]}, capacity=True)
    assert "private-fragment" not in json.dumps(doc) and "REDACTED" in doc["next_action"]


@pytest.mark.parametrize("command", ("check", "status", "doctor"))
def test_arg0841_exact_solo_subscription_writer_action(tmp_path, monkeypatch, capsys, command):
    from types import SimpleNamespace
    host = "ghp_" + "A" * 20
    document = {"preset": "solo", "model_settings": {
        "hosts": {host: {"kind": "claude-code"}},
        "capacity": {"primary": {"usage_source": "subscription-window", "fallback": {"writer": [host]}},
                     host: {"usage_source": "subscription-window"}}}}
    monkeypatch.setattr(profile, "load", lambda root: profile.resolve(repo=document))
    monkeypatch.setattr(profile, "pathlookup", SimpleNamespace(which=lambda *a, **kw: "/installed/cli"))
    monkeypatch.setattr(hosts, "usage_adapter", lambda host_kind: hosts.FakeUsageAdapter({
        "primary": {"window": {"used_pct": 100, "resets_at": "2026-11-16T22:00:00Z"}},
        host: {"window": {"used_pct": 10, "resets_at": "2026-11-16T22:00:00Z"}}}))
    if command == "check":
        code, decision = invoke(tmp_path, capsys, "hosts", "check", "primary", "writer")
        assert code == 4
    else:
        code, doc = invoke(tmp_path, capsys, *(("doctor",) if command == "doctor" else ("hosts", "status")))
        assert code == 0
        decision = next(d for d in doc["hosts"][0]["decisions"] if d["kind"] == "writer")
    assert decision["decision"] == "fallback:" + host
    assert "aegis team hosts check " + host + " writer --json" in decision["next_action"]
    assert decision["write_boundary"]["host"] == host


PLAN_KINDS = ("writer", "reviewer.correctness", "review", "reviewer.security", "research",
              "lens.extra", "extra-review", "audit-vote", "audit-flex", "doc")
PLAN_TERMINALS = (None, "hold", "skip")


def bind_cyclic_plan(monkeypatch, kind, first, second, *, hidden_destination=False):
    canonical = {"review": "reviewer.correctness", "extra-review": "lens.extra"}.get(kind, kind)
    lens = kind.startswith("audit-")
    voting = canonical.startswith("reviewer.") or kind == "audit-vote"
    document = bind_graph(monkeypatch, roles={} if lens or canonical == "doc" else {canonical: {"hosts": ["primary"]}},
                          lenses=[{"name": kind, "host_pref": ["primary"], "voting": voting}] if lens else [])
    route = "review" if voting or lens else "extra-review" if canonical == "lens.extra" else canonical
    tail = ["third"] if hidden_destination else ([] if first is None else [first])
    settings = document["model_settings"]
    settings["capacity"] = {
        "primary": {"usage_source": "credits", "fallback": {route: ["other", *tail]}},
        "other": {"usage_source": "credits", "fallback": {route: ["primary"] + ([] if second is None else [second])}},
    }
    if hidden_destination:
        settings["hosts"]["third"] = {"kind": "codex-cli"}
    monkeypatch.setattr(hosts, "usage_adapter", lambda host_kind: hosts.FakeUsageAdapter({
        "primary": {"credits_left": 0}, "other": {"credits_left": 0}}))
    return document, canonical, voting


@pytest.mark.parametrize("kind", PLAN_KINDS)
@pytest.mark.parametrize("first", PLAN_TERMINALS)
@pytest.mark.parametrize("second", PLAN_TERMINALS)
@pytest.mark.parametrize("command", ("check", "status", "doctor"))
def test_plan_table_cycles_and_terminals(tmp_path, monkeypatch, capsys, kind, first, second, command):
    _, canonical, voting = bind_cyclic_plan(monkeypatch, kind, first, second)
    refused = (canonical == "writer" or voting) and "skip" in (first, second)
    if command == "check":
        for host, terminal in (("primary", second or first), ("other", first or second)):
            code, doc = invoke(tmp_path, capsys, "hosts", "check", host, kind)
            if refused:
                assert code == 1 and doc["status"] == "refused" and "skip" in doc["reason"]
                assert doc["layer"] == "repo" and doc["file"] and doc["next_action"]
            else:
                expected = "skip" if terminal == "skip" else "hold"
                assert doc["decision"] == expected and code == (5 if expected == "skip" else 3)
    else:
        code, doc = invoke(tmp_path, capsys, *(("doctor",) if command == "doctor" else ("hosts", "status")))
        if refused:
            assert code == 1 and "skip" in doc["reason"] and doc["layer"] == "repo" and doc["file"]
        else:
            assert code == 0
            for row, terminal in zip(doc["hosts"], (second or first, first or second)):
                decision = next(d for d in row["decisions"] if d["kind"] == canonical)
                assert decision["decision"] == ("skip" if terminal == "skip" else "hold")


@pytest.mark.parametrize("kind", [kind for kind in PLAN_KINDS if kind != "doc"])
@pytest.mark.parametrize("command", ("check", "status", "doctor"))
def test_restarted_plan_cannot_introduce_unadmitted_destination(tmp_path, monkeypatch, capsys, kind, command):
    bind_cyclic_plan(monkeypatch, kind, None, "hold", hidden_destination=True)
    code, doc = invoke(tmp_path, capsys, *(("hosts", "check", "other", kind) if command == "check" else
                                        ("doctor",) if command == "doctor" else ("hosts", "status")))
    assert code == 1 and doc["status"] == "refused"
    assert "not admitted" in doc["reason"] and doc["layer"] == "repo" and doc["file"] and doc["next_action"]


@pytest.mark.parametrize("scenario", ("family", "skip"))
@pytest.mark.parametrize("command", ("check", "status", "doctor"))
def test_formal0915_exact_restarted_policy_scenarios(tmp_path, monkeypatch, capsys, scenario, command):
    from types import SimpleNamespace
    if scenario == "family":
        document = {"preset": "pair", "model_settings": {
            "hosts": {"alternate": {"kind": "claude-code"}},
            "capacity": {"review": {"usage_source": "credits", "fallback": {"review": ["alternate", "primary"]}},
                         "alternate": {"usage_source": "credits", "fallback": {"review": ["review", "hold"]}},
                         "primary": {"usage_source": "credits"}}}}
        monkeypatch.setattr(profile, "load", lambda root: profile.resolve(repo=document))
        host = "alternate"
    else:
        bind_cyclic_plan(monkeypatch, "review", "skip", "hold")
        host = "other"
    monkeypatch.setattr(profile, "pathlookup", SimpleNamespace(which=lambda *a, **kw: "/installed/cli"))
    monkeypatch.setattr(hosts, "usage_adapter", lambda host_kind: hosts.FakeUsageAdapter({
        "primary": {"credits_left": 1 if scenario == "family" else 0}, "other": {"credits_left": 0},
        "review": {"credits_left": 0}, "alternate": {"credits_left": 0}}))
    code, doc = invoke(tmp_path, capsys, *(("hosts", "check", host, "review") if command == "check" else
                                        ("doctor",) if command == "doctor" else ("hosts", "status")))
    assert code == 1 and doc["status"] == "refused" and doc["layer"] == "repo" and doc["file"]
    assert ("cross-family" if scenario == "family" else "skip") in doc["reason"]


@pytest.mark.parametrize("scenario", ("writer", "pin"))
@pytest.mark.parametrize("command", ("check", "status", "doctor"))
def test_arg0915_bound_host_restart_refuses(tmp_path, monkeypatch, capsys, scenario, command):
    from types import SimpleNamespace
    kind = "writer" if scenario == "writer" else "reviewer.security"
    route = "writer" if scenario == "writer" else "review"
    document = {"preset": "pair", "model_settings": {
        "hosts": {"other": {"kind": "codex-cli"}},
        "roles": {kind: {"hosts": ["primary", "other"]}},
        "capacity": {"primary": {"usage_source": "credits", "fallback": {route: ["other", "review"]}},
                     "other": {"usage_source": "credits", "fallback": {route: ["primary", "hold"]}},
                     "review": {"usage_source": "credits"}}}}
    monkeypatch.setattr(profile, "load", lambda root: profile.resolve(repo=document))
    monkeypatch.setattr(profile, "pathlookup", SimpleNamespace(which=lambda *a, **kw: "/installed/cli"))
    monkeypatch.setattr(hosts, "usage_adapter", lambda host_kind: hosts.FakeUsageAdapter({
        "primary": {"credits_left": 0}, "other": {"credits_left": 0}, "review": {"credits_left": 1}}))
    code, doc = invoke(tmp_path, capsys, *(("hosts", "check", "other", kind) if command == "check" else
                                        ("doctor",) if command == "doctor" else ("hosts", "status")))
    assert code == 1 and doc["status"] == "refused" and doc["layer"] == "repo" and doc["file"] and doc["next_action"]
    assert ("not admitted" if scenario == "writer" else "pinned") in doc["reason"]
