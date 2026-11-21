"""The role registry: every hierarchy role as data, and the answers provisioning and the adapters read from it.

The registry is tools/hierarchy_templates/role-registry.json, at a fixed path beside this file, so a request
or environment cannot point a role at a wider copy. Every action a role lists comes from a closed vocabulary,
and a role may not both allow and prohibit the same action.

hierarchy_mailbox.py keeps the endpoint grammar and vertical routes as constants, because the native
foundation acceptance pins that file's bytes and imports it with no other files present. Loading refuses
when the registry and those constants disagree, so the two places cannot drift apart silently.
"""
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import (ENDPOINT_ROLES, LANE_KINDS, VERTICAL_ROUTES, endpoint_parts, fields,  # noqa: E402
                               read_json, require, text)


SCHEMA = "aegis.role-registry/v1"
PATH = Path(__file__).resolve().parent / "hierarchy_templates" / "role-registry.json"
LIFECYCLE_EVENTS = ("publish", "read", "route", "admit", "wait", "intent", "start", "terminal", "meter", "delivery",
                    "disposition", "resolve", "succeed", "associate", "observe", "cancel_attempt",
                    "small_change_plan", "small_change_admit")
VOCABULARY = {
    # loop_status is the loop's status.json; team_evidence is the run's evidence folder and its SHA256SUMS.
    "reads": {"source", "mailbox", "board", "lifecycle", "job_evidence", "owner_records", "workspace_capacity",
              "workspace_initiative", "workspace_path_overlap", "loop_status", "team_evidence"},
    # mailbox:bind is the binding record alone, which the launcher publishes through add-role; it is not mail.
    "writes": {"source", "mailbox", "mailbox:bind", "board", "job_evidence", "worktree_lease", "governance"}
              | {"lifecycle:" + event for event in LIFECYCLE_EVENTS},
    # router:route and jobs:run-open only start those tools as children, which keep their own checks; neither
    # lets the caller write mail or the journal, or run a job itself.
    "calls": {"mailbox:dispatch", "mailbox:job_request", "mailbox:job_receipt", "session:start", "session:resume",
              "session:stop", "session:wake", "router:route", "jobs:run-open", "job:run", "merge", "publish_release"},
    "approvals": {"lifecycle:decision", "lifecycle:review", "lifecycle:delegated_decision",
                  "lifecycle:small_change_decision", "owner_reserved",
                  "release_signature"},
}
KINDS = {"global", "per-team", "on-demand", "service", "legacy"}
M1_USE = {"loop", "hat", "later", "m6", "legacy"}
INDEPENDENCE = {"none", "not-author", "not-requester"}
LIFECYCLE_ROLES = {"root", "router", "coordinator", "operator", "reviewer", "decider"}
ASSISTANTS = {"builder", "front-door", "orchestrator", "reviewer"}
# In the order the adapter offers them, which the generated profiles keep.
WORKSPACE_TOOLS = ("workspace_capacity", "workspace_initiative", "workspace_path_overlap")
READ_TOOLS = ["Read", "Glob", "Grep"]
WRITE_TOOLS = ["Edit", "Write"]
# The lifecycle tools a session's mailbox connection may carry.
LIFECYCLE_TOOLS = ("router_status", "decider_record")
# The read tools ROOT's decision adapter may offer beside root_decide, and what each reads. team_request reads the
# journal's policy and custody to draft a publish event; none of them writes.
DECISION_READ_TOOLS = ("team_status", "team_pending", "team_request")
DECISION_TOOL_READS = {"team_status": {"lifecycle", "loop_status", "team_evidence"}, "team_pending": {"lifecycle"},
                       "team_request": {"lifecycle"}}
ROLE_FIELDS = {"title", "kind", "m1", "responsibility", "endpoint", "hat_of", "service", "lifecycle_role", "reads",
               "writes", "calls", "approvals", "prohibitions", "independence", "model_profile", "reports_to",
               "provision"}


def actions(role, name, group):
    values = role[group]
    require(isinstance(values, list) and len(values) == len(set(values)),
            "role %s %s must be a list without repeats" % (name, group))
    for value in values:
        require(isinstance(value, str) and value in VOCABULARY[group],
                "role %s lists an unknown %s action: %s" % (name, group, str(value)[:64]))
    return set(values)


def lifecycle_connection(name, role, allowed):
    """Only the journal role a tool is written for may carry it: the Router reads status, the Decider records
    within a delegation. ROOT's adapter is the decision tool alone."""
    tools = role["provision"]["lifecycle_tools"]
    require(isinstance(tools, list) and len(tools) == len(set(tools)),
            "role %s lifecycle_tools must be a list without repeats" % name)
    for tool in tools:
        require(isinstance(tool, str) and tool in LIFECYCLE_TOOLS,
                "role %s names an unknown lifecycle tool: %s" % (name, str(tool)[:64]))
    require(role["provision"]["adapter"] != "decision" or not tools,
            "role %s: the decision adapter offers only root_decide" % name)
    require("router_status" not in tools or ("lifecycle" in allowed["reads"] and role["lifecycle_role"] == "router"),
            "role %s: router_status is for the router, which reads the lifecycle journal" % name)
    require("decider_record" not in tools
            or ("lifecycle:delegated_decision" in allowed["approvals"] and role["lifecycle_role"] == "decider"),
            "role %s: decider_record is for the decider, which approves within a delegation" % name)


def decision_connection(name, role, allowed):
    """ROOT's read tools ride only on the decision adapter, and each needs the reads it shows ROOT."""
    tools = role["provision"].get("decision_tools", [])
    require(isinstance(tools, list) and len(tools) == len(set(tools)),
            "role %s decision_tools must be a list without repeats" % name)
    for tool in tools:
        require(isinstance(tool, str) and tool in DECISION_READ_TOOLS,
                "role %s names an unknown decision tool: %s" % (name, str(tool)[:64]))
    require(not tools or role["provision"]["adapter"] == "decision",
            "role %s: ROOT's read tools are for the decision adapter" % name)
    for tool in tools:
        missing = DECISION_TOOL_READS[tool] - allowed["reads"]
        require(not missing, "role %s: %s reads %s, which the role does not list" % (name, tool, ", ".join(sorted(missing))))


def validate_role(name, role):
    fields(role, ROLE_FIELDS)
    for key in ("title", "responsibility"):
        text(role[key], "role " + key, 256)
    require(role["kind"] in KINDS, "role %s has an unknown kind" % name)
    require(role["m1"] in M1_USE, "role %s has an unknown m1 use" % name)
    allowed = {group: actions(role, name, group) for group in VOCABULARY}
    prohibitions = role["prohibitions"]
    fields(prohibitions, set(VOCABULARY))
    for group in VOCABULARY:
        refused = actions(prohibitions, name, group)
        require(not refused & allowed[group], "role %s both allows and prohibits %s: %s"
                % (name, group, ", ".join(sorted(refused & allowed[group]))))
    lifecycle = {action for action in allowed["writes"] | allowed["approvals"] if action.startswith("lifecycle:")}
    require(role["lifecycle_role"] in LIFECYCLE_ROLES or (role["lifecycle_role"] is None and not lifecycle),
            "role %s records lifecycle events without a lifecycle role" % name)
    independence = role["independence"]
    fields(independence, {"rule", "separate_session"})
    require(independence["rule"] in INDEPENDENCE and type(independence["separate_session"]) is bool,
            "role %s has an invalid independence rule" % name)
    profile = role["model_profile"]
    require(isinstance(profile, dict) and profile.get("source") in {"team", "fixed", "none"},
            "role %s has an invalid model profile" % name)
    fields(profile, {"source"}, {"effort", "tier"} if profile["source"] == "fixed" else set())
    endpoint, provision = role["endpoint"], role["provision"]
    if endpoint is None:
        require(provision is None, "role %s has provisioning but no endpoint" % name)
    else:
        fields(endpoint, {"role"}, {"lane_kind"})
        require(endpoint["role"] in ENDPOINT_ROLES, "role %s names an unknown endpoint role" % name)
        require(("lane_kind" in endpoint) == (endpoint["role"] == "lane"),
                "role %s: only a lane endpoint names a lane kind" % name)
        fields(provision, {"adapter", "reader_shell", "assistants", "team_kind", "lifecycle_tools"}, {"decision_tools"})
        require(provision["adapter"] in {"mailbox", "decision"}, "role %s has an unknown adapter" % name)
        require(type(provision["reader_shell"]) is bool and type(provision["team_kind"]) is bool,
                "role %s has invalid provisioning flags" % name)
        require(provision["assistants"] is None or provision["assistants"] in ASSISTANTS,
                "role %s names an unknown assistant list" % name)
        # Codex has no file tools without its shell, so the shell is only for a role that reads source and
        # writes none; a writer already has one in its sandbox.
        require(not provision["reader_shell"] or ("source" in allowed["reads"] and "source" not in allowed["writes"]),
                "role %s: a reader shell is only for a role that reads source and writes none" % name)
        # The decision adapter writes only the decision. A role that could also write source or mail through
        # it would turn a decision boundary into an operational one.
        require(provision["adapter"] != "decision" or not ({"source", "mailbox", "board"} & allowed["writes"]),
                "role %s: the decision adapter cannot carry write access" % name)
        lifecycle_connection(name, role, allowed)
        decision_connection(name, role, allowed)
    require(role["service"] is None or (endpoint is None and role["kind"] == "service"),
            "role %s: only a service without an endpoint names a service module" % name)
    if role["service"] is not None:
        text(role["service"], "service module", 128)


def validate(registry):
    fields(registry, {"schema", "routes", "roles"})
    require(registry["schema"] == SCHEMA, "unsupported role registry schema")
    roles = registry["roles"]
    require(isinstance(roles, dict) and 0 < len(roles) <= 64, "invalid registry roles")
    endpoints = {}
    for name, role in roles.items():
        text(name, "role name", 64)
        validate_role(name, role)
        if role["endpoint"] is not None:
            key = role["endpoint"].get("lane_kind", role["endpoint"]["role"])
            require(key not in endpoints, "two roles claim endpoint " + key)
            endpoints[key] = name
    for name, role in roles.items():
        for link in ("hat_of", "reports_to"):
            target = role[link]
            require(target is None or target in roles, "role %s %s names an unknown role" % (name, link))
        if role["hat_of"] is not None:
            require(role["endpoint"] is None and roles[role["hat_of"]]["endpoint"] is not None,
                    "role %s is a hat, so it uses the endpoint of the role it is worn on" % name)
    named = {role["endpoint"]["role"] for role in roles.values() if role["endpoint"] is not None}
    require(named == set(ENDPOINT_ROLES), "registry endpoint roles differ from the mailbox endpoint grammar")
    lanes = {role["endpoint"]["lane_kind"] for role in roles.values()
             if role["endpoint"] is not None and role["endpoint"]["role"] == "lane"}
    require(lanes == set(LANE_KINDS), "registry lane kinds differ from the mailbox lane kinds")
    routes = registry["routes"]
    require(isinstance(routes, list) and all(isinstance(pair, list) and len(pair) == 2 for pair in routes),
            "invalid registry routes")
    pairs = [frozenset(pair) for pair in routes]
    require(len(pairs) == len(set(pairs)) and all(len(pair) == 2 for pair in pairs), "invalid registry routes")
    require(set(pairs) == {frozenset(pair) for pair in VERTICAL_ROUTES},
            "registry routes differ from the mailbox vertical routes")
    return registry


_LOADED = {}


def registry():
    if "registry" not in _LOADED:
        _LOADED["registry"] = validate(read_json(PATH))
    return _LOADED["registry"]


def role_name(endpoint, kind=None):
    """The registry role an endpoint is bound to. A lane's role comes from its manifest kind."""
    role = endpoint_parts(endpoint)[1]
    key = kind if role == "lane" else role
    for name, entry in registry()["roles"].items():
        if entry["endpoint"] is not None and entry["endpoint"].get("lane_kind", entry["endpoint"]["role"]) == key:
            return name
    raise ValueError("no registry role for endpoint " + endpoint)


def role(endpoint, kind=None):
    return registry()["roles"][role_name(endpoint, kind)]


def session_roles():
    """Registry roles that have a session endpoint, in a stable order."""
    return tuple(sorted(name for name, entry in registry()["roles"].items() if entry["endpoint"] is not None))


def fixed_model_profile(entry):
    """A fixed effort/tier expectation shared by provisioning and native observation."""
    profile = entry["model_profile"]
    return dict(profile) if profile["source"] == "fixed" else None


def reader_shell_roles():
    return tuple(name for name in session_roles() if registry()["roles"][name]["provision"]["reader_shell"])


def writer(entry):
    return "source" in entry["writes"]


def file_tools(entry):
    """Host file tools: reading source gives the read tools, and writing it adds the edit tools."""
    return (READ_TOOLS if "source" in entry["reads"] else []) + (WRITE_TOOLS if writer(entry) else [])


def require_file_tools(endpoint, kind, names):
    name = role_name(endpoint, kind)
    permitted = file_tools(registry()["roles"][name])
    for tool in names:
        require(tool in permitted, "the %s role does not permit file tool: %s" % (name, tool))


def workspace_tools(entry):
    return tuple(name for name in WORKSPACE_TOOLS if name in entry["reads"])


def lifecycle_tools(entry):
    return tuple(entry["provision"]["lifecycle_tools"])


def decision_tools(entry):
    """ROOT's read tools, in the order its adapter offers them after root_decide."""
    return tuple(entry["provision"].get("decision_tools", ()))


def takes_board(entry):
    return "board" in entry["reads"]


def require_board(endpoint, kind=None):
    name = role_name(endpoint, kind)
    require(takes_board(registry()["roles"][name]), "the %s role has no board access" % name)


# In the order the adapter offers them.
SOURCE_VIEW_TOOLS = ("source_show", "source_grep")


def source_views(entry):
    """Pinned show and grep stand in for a shell: for a role that reads source and writes none. A writer already
    has its worktree, and a role that never reads source has nothing to read."""
    return "source" in entry["reads"] and not writer(entry)


def require_source_views(endpoint, kind=None):
    name = role_name(endpoint, kind)
    require(source_views(registry()["roles"][name]),
            "the %s role has no source views: they are for roles that read source and write none" % name)


def require_independent_session(mailbox, endpoint, host, session):
    """Where independence is the control, the registry asks for a separate session, so one session can never hold
    both sides. Mailbox.bind calls this, so every path that binds is checked: the CLI, provisioning, a move and a
    handoff. Only the current binding of each other endpoint counts, and only the separate_session flag is
    mechanical; the not-author and not-requester rules are for the roles' own checks.

    The rule separates different roles. One session may hold the same role on several endpoints, such as one
    ROOT for hierarchies a and b in a shared root, because no independence boundary lies between them."""
    name = role_name(endpoint, mailbox.endpoint(endpoint).get("kind"))
    mine = registry()["roles"][name]
    for other in mailbox.manifest["endpoints"]:
        if other == endpoint:
            continue
        history = mailbox.bindings(other)
        if not history or (history[-1]["host"], history[-1]["session"]) != (host, session):
            continue
        other_name = role_name(other, mailbox.endpoint(other).get("kind"))
        if other_name == name:
            continue
        theirs = registry()["roles"][other_name]
        if mine["independence"]["separate_session"] or theirs["independence"]["separate_session"]:
            raise ValueError("session %s already holds %s; the role registry needs a separate session for %s"
                             % (session, other, endpoint if mine["independence"]["separate_session"] else other))


def team_kinds():
    """The team.json reasoning_by_kind keys: a lane's kind, or the endpoint role for any other team role."""
    return {entry["endpoint"].get("lane_kind", entry["endpoint"]["role"])
            for entry in registry()["roles"].values()
            if entry["provision"] is not None and entry["provision"]["team_kind"]}
