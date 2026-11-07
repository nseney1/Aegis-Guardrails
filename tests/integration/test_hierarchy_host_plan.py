"""The run's host plan binds every team-run session to the host the run assigns it (spec rule 1, ADR T2(a) §1, §4).

Provision add-role and handoff check a binding against `<base>/host-plan.json` before they bind and write one
session record per endpoint and generation beside it; the team command parses aegis.team-run/v2 and writes the plan
at init. A base without a plan keeps today's unchecked binding. Fakes only: no host runs here.
"""
import hashlib
import json
import os
import sys
import uuid

import pytest

from tests.integration.test_hierarchy_handoff import handoff
from tests.integration.test_hierarchy_mailbox import ROOT, invoke
from tests.integration.test_hierarchy_provision import Setup
from tests.integration.test_hierarchy_team import Run as TeamRun, in_process, sha


sys.path.insert(0, str(ROOT / "tools"))
import hierarchy_hosts  # noqa: E402


posix = pytest.mark.skipif(os.name == "nt", reason="generated profiles and wakes are POSIX only")
linux = pytest.mark.skipif(not sys.platform.startswith("linux"),
                           reason="the loop and run-open read /proc and the wake supports POSIX process groups only")
CLAUDE, CODEX = "claude-code", "codex-cli"
CLAUDE_WRITER = {"boundary": "permission rules, not OS-enforced", "mechanism": "claude --restricted",
                 "os_enforced": False, "owner_decision": "teams 2026-11-07 decision 4",
                 "ends_when": "T2(b) qualifies an OS-enforced Claude write scope"}
CODEX_WRITER = {"boundary": "OS sandbox, qualification pending T2(b)", "mechanism": "codex sandbox writable_roots",
                "os_enforced": None}
READER = {"boundary": "no write tools"}
STAND_IN = {"boundary": "stand-in: runs no host"}
CODEX_SESSION = "01a19a29-d635-7411-8529-9efedafc0890"
ROOT_SESSION = "root-session-1"


def write_plan(setup, root=CODEX, team=CODEX, hierarchy="pilot", stand_ins=None):
    stand_ins = {"pilot/front-door": CLAUDE} if stand_ins is None else stand_ins
    plan = hierarchy_hosts.plan_record(hierarchy, root, team, stand_ins, "0" * 64)
    (setup.base / "host-plan.json").write_text(json.dumps(plan), encoding="utf-8")
    return plan


def record(setup, endpoint, generation=1):
    path = setup.base / "sessions" / ("%s-g%d.json" % (endpoint.replace("/", "%2F"), generation))
    return json.loads(path.read_text(encoding="utf-8"))


def expected(endpoint, role_kind, host, start_mode, session, scope, generation=1, stand_in=False):
    return {"schema": "aegis.team-session/v1", "endpoint": endpoint, "role_kind": role_kind, "host_kind": host,
            "start_mode": start_mode, "session": session, "generation": generation, "stand_in": stand_in,
            "write_scope": scope}


def unbound(setup, endpoint):
    return invoke(setup.root, "status")["bindings"][endpoint] is None


@pytest.fixture
def setup(tmp_path):
    built = Setup(tmp_path)
    built.init()
    return built


# -- add-role under a plan ----------------------------------------------------------------------------------------------

@posix
def test_a_claude_team_binds_on_claude_and_records_each_sessions_write_scope(setup):
    write_plan(setup, team=CLAUDE)
    writer = setup.add_role("pilot/lane/f2", CLAUDE, cwd=str(setup.tmp))
    reviewer = setup.add_role("pilot/lane/review", CLAUDE, cwd=str(setup.tmp))
    assert record(setup, "pilot/lane/f2") == expected("pilot/lane/f2", "implementer", CLAUDE, "print",
                                                      writer["session"], CLAUDE_WRITER)
    assert record(setup, "pilot/lane/review") == expected("pilot/lane/review", "reviewer", CLAUDE, "print",
                                                          reviewer["session"], READER)


@posix
def test_a_codex_team_records_the_pending_sandbox_boundary(setup):
    write_plan(setup)
    setup.add_role("pilot/lane/f2", CODEX, session=CODEX_SESSION, cwd=str(setup.source))
    found = record(setup, "pilot/lane/f2")
    assert found == expected("pilot/lane/f2", "implementer", CODEX, "exec", CODEX_SESSION, CODEX_WRITER)
    assert found["write_scope"]["boundary"] == "OS sandbox, qualification pending T2(b)"


@posix
def test_the_front_door_stand_in_binds_on_its_listed_host_without_qualification(setup):
    write_plan(setup)
    door = setup.add_role("pilot/front-door", CLAUDE, cwd=str(setup.tmp))
    assert record(setup, "pilot/front-door") == expected("pilot/front-door", "front-door", CLAUDE, None,
                                                         door["session"], STAND_IN, stand_in=True)


@posix
@pytest.mark.parametrize("endpoint,host,team,planned", [
    ("pilot/lane/f2", CLAUDE, CODEX, CODEX),
    ("pilot/orchestrator", CODEX, CLAUDE, CLAUDE),
    ("pilot/front-door", CODEX, CODEX, CLAUDE),
])
def test_a_host_the_plan_does_not_assign_is_refused_and_binds_nothing(setup, endpoint, host, team, planned):
    write_plan(setup, team=team)
    options = {"session": CODEX_SESSION, "cwd": str(setup.source)} if host == CODEX else {"cwd": str(setup.tmp)}
    refused = setup.add_role(endpoint, host, expect=2, **options)
    assert refused["error"] == "%s runs on %s in this run's host plan, not %s" % (endpoint, planned, host)
    assert unbound(setup, endpoint)
    assert not (setup.base / "sessions").exists() and not list(setup.base.glob("connections/*"))


@posix
@pytest.mark.parametrize("team", [CODEX, CLAUDE])
def test_a_native_thread_is_refused_in_a_team_run(setup, team):
    write_plan(setup, team=team)
    refused = setup.add_role("pilot/orchestrator", "codex", session=CODEX_SESSION, expect=2)
    assert refused["error"] == "pilot/orchestrator runs on %s in this run's host plan, not codex" % team
    assert unbound(setup, "pilot/orchestrator")


@posix
@pytest.mark.parametrize("key,value", [("background", True), ("assistants", True), ("add_dirs", None)])
def test_a_claude_team_role_takes_no_background_assistants_or_extra_folders(setup, key, value):
    write_plan(setup, team=CLAUDE)
    value = [str(setup.tmp)] if value is None else value
    refused = setup.add_role("pilot/orchestrator", CLAUDE, cwd=str(setup.tmp), expect=2, **{key: value})
    assert refused["error"] == "pilot/orchestrator: a claude-code role in a team run takes no %s" % key
    assert unbound(setup, "pilot/orchestrator")


@posix
def test_false_or_empty_claude_options_still_bind(setup):
    write_plan(setup, team=CLAUDE)
    role = setup.add_role("pilot/orchestrator", CLAUDE, cwd=str(setup.tmp), background=False, assistants=False,
                          add_dirs=[])
    assert record(setup, "pilot/orchestrator")["start_mode"] == "print" and role["generation"] == 1


@posix
def test_root_is_checked_against_the_plans_root_host(setup):
    write_plan(setup, root=CLAUDE, team=CODEX)
    refused = setup.add_role("pilot/root", CODEX, session=ROOT_SESSION, expect=2)
    assert refused["error"] == "pilot/root runs on claude-code in this run's host plan, not codex-cli"
    assert unbound(setup, "pilot/root")
    setup.add_role("pilot/root", CLAUDE, session=ROOT_SESSION)
    assert record(setup, "pilot/root") == expected("pilot/root", "root", CLAUDE, "print", ROOT_SESSION, READER)


@posix
def test_an_endpoint_of_another_hierarchy_is_unconstrained(setup):
    write_plan(setup, hierarchy="other", stand_ins={})
    role = setup.add_role("pilot/lane/f2", CLAUDE, cwd=str(setup.tmp))
    assert role["generation"] == 1
    assert not (setup.base / "sessions").exists()


@posix
def test_a_malformed_plan_refuses_add_role_before_anything_binds(setup):
    (setup.base / "host-plan.json").write_text("{", encoding="utf-8")
    refused = setup.add_role("pilot/orchestrator", CLAUDE, cwd=str(setup.tmp), expect=2)
    assert refused["error"].startswith("invalid host plan %s: " % (setup.base / "host-plan.json"))
    assert unbound(setup, "pilot/orchestrator")


@posix
def test_a_rerun_keeps_its_record_and_a_different_record_is_refused(setup):
    write_plan(setup, team=CLAUDE)
    first = setup.add_role("pilot/orchestrator", CLAUDE, cwd=str(setup.tmp))
    path = setup.base / "sessions" / "pilot%2Forchestrator-g1.json"
    before = path.read_bytes()
    again = setup.add_role("pilot/orchestrator", CLAUDE, session=first["session"], cwd=str(setup.tmp))
    assert again == first and path.read_bytes() == before
    path.write_text(json.dumps({**json.loads(before), "start_mode": "background"}), encoding="utf-8")
    refused = setup.add_role("pilot/orchestrator", CLAUDE, session=first["session"], cwd=str(setup.tmp), expect=2)
    assert refused["error"] == "session record for pilot/orchestrator generation 1 differs from this binding"


@posix
def test_a_stale_record_refuses_a_new_binding_before_it_binds(setup):
    write_plan(setup, team=CLAUDE)
    stale = expected("pilot/orchestrator", "orchestrator", CLAUDE, "print", str(uuid.uuid4()), READER)
    (setup.base / "sessions").mkdir()
    (setup.base / "sessions" / "pilot%2Forchestrator-g1.json").write_text(json.dumps(stale), encoding="utf-8")
    refused = setup.add_role("pilot/orchestrator", CLAUDE, cwd=str(setup.tmp), expect=2)
    assert refused["error"] == "session record for pilot/orchestrator generation 1 differs from this binding"
    assert unbound(setup, "pilot/orchestrator")


# -- without a plan -----------------------------------------------------------------------------------------------------

def bound_files(setup):
    """connections/ and profiles/, with this setup's folder written as <tmp>, so two setups compare."""
    found = {}
    for folder in ("connections", "profiles"):
        for path in sorted((setup.base / folder).rglob("*")):
            found[str(path.relative_to(setup.base))] = path.read_text(encoding="utf-8").replace(str(setup.tmp), "<tmp>")
    return found


@posix
@pytest.mark.parametrize("endpoint,host,changes", [
    ("pilot/lane/f2", CLAUDE, {"session": "6f0e7c1a-1111-4222-8333-944455556666"}),
    ("pilot/orchestrator", CODEX, {"session": CODEX_SESSION, "source_cwd": True}),
    ("pilot/front-door", CLAUDE, {"session": "6f0e7c1a-1111-4222-8333-944455556667"}),
])
def test_without_a_plan_add_role_answers_and_writes_exactly_what_a_planned_match_does(tmp_path, endpoint, host,
                                                                                     changes):
    (tmp_path / "plain").mkdir()
    (tmp_path / "plans").mkdir()
    plain, planned = Setup(tmp_path / "plain"), Setup(tmp_path / "plans")
    answers = []
    for built in (plain, planned):
        built.init()
        if built is planned:
            write_plan(built, team=CODEX if host == CODEX else CLAUDE)
        options = dict(changes)
        cwd = str(built.source) if options.pop("source_cwd", False) else str(built.tmp)
        answer = built.add_role(endpoint, host, cwd=cwd, **options)
        answers.append(json.loads(json.dumps(answer).replace(str(built.tmp), "<tmp>")))
    assert answers[0] == answers[1]
    assert bound_files(plain) == bound_files(planned)
    assert not (plain.base / "sessions").exists() and not (plain.base / "host-plan.json").exists()
    assert (planned.base / "sessions").is_dir()


# -- handoff under a plan -----------------------------------------------------------------------------------------------

def brief(setup):
    path = setup.base / "brief.md"
    path.write_bytes(b"Handoff.\n")
    return {"path": str(path), "sha256": hashlib.sha256(b"Handoff.\n").hexdigest()}


def spec(setup, host, session, endpoint="pilot/orchestrator"):
    return {"schema": "aegis.hierarchy-handoff/v1", "host": host, "session": session, "outgoing_stopped": True,
            "entries": [{"root": str(setup.root), "endpoint": endpoint, "briefs": [brief(setup)]}]}


@posix
def test_a_handoff_to_a_host_the_plan_does_not_assign_is_refused_per_entry_and_binds_nothing(setup):
    write_plan(setup)
    setup.add_role("pilot/orchestrator", CODEX, session=CODEX_SESSION, cwd=str(setup.source))
    result = handoff(setup.tmp, spec(setup, CLAUDE, str(uuid.uuid4())), 3)
    assert result["entries"] == [{"root": str(setup.root), "endpoint": "pilot/orchestrator", "ok": False,
                                  "error": "pilot/orchestrator runs on codex-cli in this run's host plan, not "
                                           "claude-code"}]
    assert invoke(setup.root, "status")["bindings"]["pilot/orchestrator"]["generation"] == 1
    assert not (setup.base / "sessions" / "pilot%2Forchestrator-g2.json").exists()


@posix
def test_a_handoff_on_the_planned_host_writes_the_successors_record_and_add_role_agrees(setup):
    write_plan(setup)
    setup.add_role("pilot/orchestrator", CODEX, session=CODEX_SESSION, cwd=str(setup.source))
    successor = "01a19a29-d635-7411-8529-9efedafc0891"
    result = handoff(setup.tmp, spec(setup, CODEX, successor), 0)
    assert result["entries"][0]["ok"] is True and result["entries"][0]["generation"] == 2
    written = record(setup, "pilot/orchestrator", 2)
    assert written == expected("pilot/orchestrator", "orchestrator", CODEX, "exec", successor, READER, generation=2)
    again = handoff(setup.tmp, spec(setup, CODEX, successor), 0)
    assert again["entries"][0]["already_bound"] is True
    # The successor's profile comes from add-role, which must find the same record, not a conflict.
    role = setup.add_role("pilot/orchestrator", CODEX, session=successor, cwd=str(setup.source))
    assert role["generation"] == 2 and record(setup, "pilot/orchestrator", 2) == written
    assert record(setup, "pilot/orchestrator", 1)["session"] == CODEX_SESSION


@posix
def test_a_handoff_in_a_base_without_a_plan_writes_no_record(setup):
    setup.add_role("pilot/orchestrator", CODEX, session=CODEX_SESSION, cwd=str(setup.source))
    result = handoff(setup.tmp, spec(setup, "host-two", "successor"), 0)
    assert result["entries"][0]["generation"] == 2
    assert not (setup.base / "sessions").exists()


@posix
def test_a_handoff_ignores_a_plan_whose_provision_names_another_mailbox(setup, tmp_path):
    write_plan(setup)
    setup.add_role("pilot/orchestrator", CODEX, session=CODEX_SESSION, cwd=str(setup.source))
    provision = setup.base / "provision.json"
    moved = {**json.loads(provision.read_text(encoding="utf-8")), "mailbox_root": str(tmp_path / "other" / "mailbox")}
    provision.write_text(json.dumps(moved), encoding="utf-8")
    result = handoff(setup.tmp, spec(setup, CLAUDE, str(uuid.uuid4())), 0)
    assert result["entries"][0]["generation"] == 2, "this mailbox is not the base's, so the base's plan is not its"
    assert not (setup.base / "sessions" / "pilot%2Forchestrator-g2.json").exists()


# -- the team command ---------------------------------------------------------------------------------------------------

@pytest.fixture
def team(tmp_path, monkeypatch):
    return TeamRun(tmp_path, monkeypatch)


def hosts_of(team):
    import hierarchy_team
    return hierarchy_team.Run(str(team.config_path)).hosts


@linux
def test_a_v1_config_means_codex_root_and_team(team):
    assert hosts_of(team) == {"root": CODEX, "team": CODEX}


@linux
@pytest.mark.parametrize("hosts", [{"root": CODEX, "team": CODEX}, {"root": CODEX, "team": CLAUDE},
                                   {"root": CLAUDE, "team": CODEX}])
def test_a_v2_config_names_root_and_team_hosts(team, hosts):
    team.config.update(schema="aegis.team-run/v2", hosts=hosts)
    team.save()
    assert hosts_of(team) == hosts


@linux
@pytest.mark.parametrize("change,error", [
    ({"schema": "aegis.team-run/v2"}, "aegis.team-run/v2 needs hosts: the root and team host kinds"),
    ({"hosts": {"root": CODEX, "team": CODEX}}, "hosts needs schema aegis.team-run/v2"),
    ({"schema": "aegis.team-run/v2", "hosts": {"root": CODEX}}, "hosts: missing fields: team"),
    ({"schema": "aegis.team-run/v2", "hosts": {"root": CODEX, "team": CODEX, "lanes": CODEX}},
     "hosts: unexpected fields: lanes"),
    ({"schema": "aegis.team-run/v2", "hosts": [CODEX, CODEX]}, "hosts: expected a JSON object"),
    ({"schema": "aegis.team-run/v2", "hosts": {"root": CODEX, "team": "codex"}},
     "hosts.team is codex (native): team runs start no native threads"),
    ({"schema": "aegis.team-run/v2", "hosts": {"root": "codex", "team": CODEX}},
     "hosts.root is codex (native): team runs start no native threads"),
    ({"schema": "aegis.team-run/v2", "hosts": {"root": "gemini", "team": CODEX}},
     "hosts.root must be claude-code or codex-cli, not 'gemini'"),
    ({"schema": "aegis.team-run/v2", "hosts": {"root": CODEX, "team": 7}},
     "hosts.team must be claude-code or codex-cli, not 7"),
    ({"schema": "aegis.team-run/v3"}, "unsupported team-run schema: aegis.team-run/v3"),
])
def test_a_host_plan_outside_the_v2_schema_is_refused(team, capsys, change, error):
    team.config.update(change)
    team.save()
    assert in_process(team, "status", capsys=capsys) == (2, {"error": error})


@linux
@pytest.mark.parametrize("hosts", [{"root": CODEX, "team": CLAUDE}, {"root": CLAUDE, "team": CODEX}])
def test_init_refuses_a_claude_plan_until_claude_support_lands_and_writes_nothing(team, hosts):
    team.config.update(schema="aegis.team-run/v2", hosts=hosts)
    team.save()
    answer = team.team("init", expect=2)
    assert answer == {"error": "this team command runs codex-cli roles and ROOT until T2(a) PR 6; hosts is %s"
                               % json.dumps(hosts, sort_keys=True)}
    assert not team.run.exists() and not team.codex_home.exists()


@linux
def test_init_writes_the_host_plan_with_the_front_door_stand_in_and_leaves_the_preflight_unconstrained(team):
    team.team("init")
    plan = json.loads((team.base_dir / "host-plan.json").read_text(encoding="utf-8"))
    assert plan == {"schema": "aegis.hierarchy-host-plan/v1", "hierarchy": "pilot", "root": CODEX, "team": CODEX,
                    "stand_ins": {"pilot/front-door": CLAUDE}, "config_sha256": sha(team.config_path)}
    assert json.loads((team.evidence / "host-plan.json").read_text(encoding="utf-8")) == plan
    index = json.loads((team.evidence / "index.json").read_text(encoding="utf-8"))
    assert index["files"]["host-plan.json"]["sha256"] == sha(team.evidence / "host-plan.json")
    door = team.mailbox().status()["bindings"]["pilot/front-door"]
    found = json.loads((team.base_dir / "sessions" / "pilot%2Ffront-door-g1.json").read_text(encoding="utf-8"))
    assert found == expected("pilot/front-door", "front-door", CLAUDE, None, door["session"], STAND_IN, stand_in=True)
    assert sorted(path.name for path in (team.base_dir / "sessions").iterdir()) == ["pilot%2Ffront-door-g1.json"]
    # The preflight binds claude-code stand-ins for pilotpre/orchestrator and pilotpre/root in a base of its own.
    preflight = team.run / "preflight" / "initiatives" / "pilotpre"
    assert not (preflight / "host-plan.json").exists() and not (preflight / "sessions").exists()
    from hierarchy_mailbox import Mailbox
    bindings = Mailbox(preflight / "mailbox").status()["bindings"]
    assert bindings["pilotpre/root"]["host"] == bindings["pilotpre/orchestrator"]["host"] == CLAUDE
