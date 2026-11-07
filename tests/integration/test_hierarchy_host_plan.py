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
from tests.integration.test_hierarchy_provision import Setup, provision
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


def real(path):
    return os.path.realpath(str(path))


def writer_scope(scope, *roots):
    return dict(scope, roots=[real(root) for root in roots])


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
                                                      writer["session"], writer_scope(CLAUDE_WRITER, setup.tmp))
    assert record(setup, "pilot/lane/review") == expected("pilot/lane/review", "reviewer", CLAUDE, "print",
                                                          reviewer["session"], READER)


@posix
def test_a_codex_team_records_the_pending_sandbox_boundary(setup):
    write_plan(setup)
    setup.add_role("pilot/lane/f2", CODEX, session=CODEX_SESSION, cwd=str(setup.source))
    found = record(setup, "pilot/lane/f2")
    assert found == expected("pilot/lane/f2", "implementer", CODEX, "exec", CODEX_SESSION,
                             writer_scope(CODEX_WRITER, setup.source))
    assert found["write_scope"]["boundary"] == "OS sandbox, qualification pending T2(b)"


@posix
def test_a_codex_writer_records_its_cwd_writable_roots_and_tmpdir_as_real_paths_once_each(setup):
    write_plan(setup)
    extra, scratch = setup.tmp / "integration", setup.tmp / "private-tmp"
    extra.mkdir()
    scratch.mkdir()
    setup.add_role("pilot/lane/f2", CODEX, session=CODEX_SESSION, cwd=str(setup.source),
                   writable_roots=[str(setup.source), str(extra)], tmpdir=str(scratch))
    assert record(setup, "pilot/lane/f2")["write_scope"] == writer_scope(CODEX_WRITER, setup.source, extra, scratch)


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
def test_a_plan_for_another_hierarchy_is_refused_before_anything_binds(setup):
    write_plan(setup, hierarchy="other", stand_ins={})
    refused = setup.add_role("pilot/lane/f2", CLAUDE, cwd=str(setup.tmp), expect=2)
    assert refused["error"] == "host plan is for hierarchy other, but this base serves pilot"
    assert unbound(setup, "pilot/lane/f2")
    assert not (setup.base / "sessions").exists()


@posix
@pytest.mark.parametrize("shape", ["file", "symlink"])
def test_a_sessions_path_that_is_not_a_real_folder_refuses_before_binding(setup, shape):
    write_plan(setup, team=CLAUDE)
    folder = setup.base / "sessions"
    if shape == "file":
        folder.write_text("not a folder\n", encoding="utf-8")
    else:
        (setup.tmp / "elsewhere").mkdir()
        folder.symlink_to(setup.tmp / "elsewhere")
    refused = setup.add_role("pilot/orchestrator", CLAUDE, cwd=str(setup.tmp), expect=2)
    assert refused["error"] == "session records need a real folder: %s" % folder
    assert unbound(setup, "pilot/orchestrator")
    if shape == "symlink":
        assert not list((setup.tmp / "elsewhere").iterdir())
    else:
        assert folder.read_text(encoding="utf-8") == "not a folder\n"


@posix
def test_add_role_fills_in_a_missing_record_on_an_existing_binding(setup):
    first = setup.add_role("pilot/lane/f2", CLAUDE, cwd=str(setup.tmp))
    assert not (setup.base / "sessions").exists(), "bound before the run had a plan"
    write_plan(setup, team=CLAUDE)
    again = setup.add_role("pilot/lane/f2", CLAUDE, session=first["session"], cwd=str(setup.tmp))
    assert again["generation"] == 1
    assert record(setup, "pilot/lane/f2") == expected("pilot/lane/f2", "implementer", CLAUDE, "print",
                                                      first["session"], writer_scope(CLAUDE_WRITER, setup.tmp))
    (setup.base / "sessions" / "pilot%2Flane%2Ff2-g1.json").unlink()
    setup.add_role("pilot/lane/f2", CLAUDE, session=first["session"], cwd=str(setup.tmp))
    assert record(setup, "pilot/lane/f2")["session"] == first["session"]


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


def handed(setup, endpoint, session, generation):
    binding = invoke(setup.root, "status")["bindings"][endpoint]
    return binding["session"] == session and binding["generation"] == generation


@posix
def test_a_handoff_to_a_host_the_plan_does_not_assign_is_refused_per_entry_and_binds_nothing(setup):
    write_plan(setup)
    setup.add_role("pilot/orchestrator", CODEX, session=CODEX_SESSION, cwd=str(setup.source))
    result = handoff(setup.tmp, spec(setup, CLAUDE, str(uuid.uuid4())), 3)
    assert result["entries"] == [{"root": str(setup.root), "endpoint": "pilot/orchestrator", "ok": False,
                                  "error": "pilot/orchestrator runs on codex-cli in this run's host plan, not "
                                           "claude-code"}]
    assert handed(setup, "pilot/orchestrator", CODEX_SESSION, 1)


@posix
def test_a_handoff_on_the_planned_host_binds_and_the_successors_add_role_writes_its_record(setup):
    write_plan(setup)
    setup.add_role("pilot/orchestrator", CODEX, session=CODEX_SESSION, cwd=str(setup.source))
    successor = "01a19a29-d635-7411-8529-9efedafc0891"
    result = handoff(setup.tmp, spec(setup, CODEX, successor), 0)
    assert result["entries"][0]["ok"] is True and result["entries"][0]["generation"] == 2
    assert not (setup.base / "sessions" / "pilot%2Forchestrator-g2.json").exists(), "add-role writes it"
    again = handoff(setup.tmp, spec(setup, CODEX, successor), 0)
    assert again["entries"][0]["already_bound"] is True
    assert not (setup.base / "sessions" / "pilot%2Forchestrator-g2.json").exists()
    role = setup.add_role("pilot/orchestrator", CODEX, session=successor, cwd=str(setup.source))
    assert role["generation"] == 2
    assert record(setup, "pilot/orchestrator", 2) == expected("pilot/orchestrator", "orchestrator", CODEX, "exec",
                                                              successor, READER, generation=2)
    assert record(setup, "pilot/orchestrator", 1)["session"] == CODEX_SESSION


@posix
def test_add_role_on_a_handed_off_writer_records_the_next_generation_with_its_roots(setup):
    write_plan(setup)
    extra = setup.tmp / "integration"
    extra.mkdir()
    setup.add_role("pilot/lane/f2", CODEX, session=CODEX_SESSION, cwd=str(setup.source))
    successor = "01a19a29-d635-7411-8529-9efedafc0892"
    assert handoff(setup.tmp, spec(setup, CODEX, successor, "pilot/lane/f2"), 0)["entries"][0]["generation"] == 2
    setup.add_role("pilot/lane/f2", CODEX, session=successor, cwd=str(setup.source), writable_roots=[str(extra)])
    assert record(setup, "pilot/lane/f2", 2) == expected("pilot/lane/f2", "implementer", CODEX, "exec", successor,
                                                         writer_scope(CODEX_WRITER, setup.source, extra), generation=2)
    assert record(setup, "pilot/lane/f2", 1)["write_scope"] == writer_scope(CODEX_WRITER, setup.source)


@posix
def test_a_handoff_of_the_front_door_stand_in_is_checked_against_its_listed_host(setup):
    write_plan(setup)
    door = setup.add_role("pilot/front-door", CLAUDE, cwd=str(setup.tmp))
    refused = handoff(setup.tmp, spec(setup, CODEX, CODEX_SESSION, "pilot/front-door"), 3)["entries"][0]
    assert refused["error"] == "pilot/front-door runs on claude-code in this run's host plan, not codex-cli"
    assert handed(setup, "pilot/front-door", door["session"], 1)
    successor = str(uuid.uuid4())
    assert handoff(setup.tmp, spec(setup, CLAUDE, successor, "pilot/front-door"), 0)["entries"][0]["generation"] == 2
    setup.add_role("pilot/front-door", CLAUDE, session=successor, cwd=str(setup.tmp))
    assert record(setup, "pilot/front-door", 2) == expected("pilot/front-door", "front-door", CLAUDE, None, successor,
                                                            STAND_IN, generation=2, stand_in=True)


@posix
def test_a_handoff_of_root_is_checked_against_the_plans_root_host(setup):
    write_plan(setup, root=CLAUDE, team=CODEX)
    setup.add_role("pilot/root", CLAUDE, session=ROOT_SESSION)
    refused = handoff(setup.tmp, spec(setup, CODEX, "root-session-2", "pilot/root"), 3)["entries"][0]
    assert refused["error"] == "pilot/root runs on claude-code in this run's host plan, not codex-cli"
    assert handed(setup, "pilot/root", ROOT_SESSION, 1)
    assert handoff(setup.tmp, spec(setup, CLAUDE, "root-session-2", "pilot/root"), 0)["entries"][0]["generation"] == 2
    setup.add_role("pilot/root", CLAUDE, session="root-session-2")
    assert record(setup, "pilot/root", 2) == expected("pilot/root", "root", CLAUDE, "print", "root-session-2", READER,
                                                      generation=2)


@posix
def test_a_handoff_in_a_base_without_a_plan_is_unchanged(setup):
    setup.add_role("pilot/orchestrator", CODEX, session=CODEX_SESSION, cwd=str(setup.source))
    result = handoff(setup.tmp, spec(setup, "host-two", "successor"), 0)
    assert result["entries"][0]["generation"] == 2
    assert not (setup.base / "sessions").exists()


@posix
def test_a_handoff_under_a_plan_for_another_hierarchy_is_refused_per_entry(setup):
    setup.add_role("pilot/orchestrator", CODEX, session=CODEX_SESSION, cwd=str(setup.source))
    write_plan(setup, hierarchy="other", stand_ins={})
    refused = handoff(setup.tmp, spec(setup, CODEX, str(uuid.uuid4())), 3)["entries"][0]
    assert refused["error"] == "host plan is for hierarchy other, but this base serves pilot"
    assert handed(setup, "pilot/orchestrator", CODEX_SESSION, 1)


@posix
@pytest.mark.parametrize("change", ["another mailbox", "no provision"])
def test_a_plan_beside_a_mailbox_its_provision_does_not_name_refuses_the_entry(setup, tmp_path, change):
    write_plan(setup)
    setup.add_role("pilot/orchestrator", CODEX, session=CODEX_SESSION, cwd=str(setup.source))
    provision_path = setup.base / "provision.json"
    if change == "no provision":
        provision_path.unlink()
    else:
        other = tmp_path / "other" / "mailbox"
        other.mkdir(parents=True)
        moved = {**json.loads(provision_path.read_text(encoding="utf-8")), "mailbox_root": str(other)}
        provision_path.write_text(json.dumps(moved), encoding="utf-8")
    refused = handoff(setup.tmp, spec(setup, CODEX, str(uuid.uuid4())), 3)["entries"][0]
    assert refused["error"] == ("host plan %s does not cover mailbox %s: its base's provision.json does not name that "
                                "mailbox" % (setup.base / "host-plan.json", setup.root))
    assert handed(setup, "pilot/orchestrator", CODEX_SESSION, 1)


# -- move ---------------------------------------------------------------------------------------------------------------

@posix
def test_a_planned_team_hierarchy_cannot_be_moved(setup):
    write_plan(setup)
    new_base = setup.tmp / "initiatives" / "moved" / "pilot"
    refused = provision("move", setup.request(
        store=str(setup.workspace.store), base=str(new_base), source=str(setup.source), old_root=str(setup.root),
        hierarchy="pilot", note="The owner approved this move.", root={"host": CODEX, "session": str(uuid.uuid4())},
        initiative={"project": "aegis", "repository": "aegis", "priority": 5, "target_branch": "develop"}), expect=2)
    assert refused == {"error": "a planned team hierarchy cannot be moved; start a new team run"}
    assert not new_base.exists()


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


@linux
def test_init_continue_resumes_after_the_plan_write_fails_without_running_provision_init_again(team, monkeypatch,
                                                                                               capsys):
    def broken(*arguments, **options):
        raise OSError("disk full while writing the host plan")

    working = hierarchy_hosts.plan_record
    monkeypatch.setattr(hierarchy_hosts, "plan_record", broken)
    code, answer = in_process(team, "init", capsys=capsys)
    assert (code, answer["step"], answer["error"]) == (3, "provision", "disk full while writing the host plan")
    state = json.loads((team.run / "team-state.json").read_text(encoding="utf-8"))
    assert "provision-init" in state["init"]["done"] and "pending" not in state["init"]
    assert not (team.base_dir / "host-plan.json").exists()
    # Only this patch: undo() would also drop the sealed PATH and HOME the team fixture set.
    monkeypatch.setattr(hierarchy_hosts, "plan_record", working)
    # Provision init refuses an initiative it already registered, so this completes only if it is not run again.
    answer = team.team("init", "--continue")
    assert answer["init"] == "complete" and answer["ran"][0] == "provision"
    assert json.loads((team.base_dir / "host-plan.json").read_text(encoding="utf-8"))["hierarchy"] == "pilot"

