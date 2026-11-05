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
                    "disposition", "resolve", "succeed", "associate", "observe", "cancel_attempt")
VOCABULARY = {
    "reads": {"source", "mailbox", "board", "lifecycle", "job_evidence", "owner_records", "workspace_capacity",
              "workspace_initiative", "workspace_path_overlap"},
    "writes": {"source", "mailbox", "board", "job_evidence", "worktree_lease", "governance"}
              | {"lifecycle:" + event for event in LIFECYCLE_EVENTS},
    "calls": {"mailbox:dispatch", "mailbox:job_request", "mailbox:job_receipt", "session:start", "session:resume",
              "session:stop", "session:wake", "job:run", "merge", "publish_release"},
    "approvals": {"lifecycle:decision", "lifecycle:review", "delegated_decision", "owner_reserved",
                  "release_signature"},
}
KINDS = {"global", "per-team", "on-demand", "service", "legacy"}
M1_USE = {"loop", "hat", "later", "m6", "legacy"}
INDEPENDENCE = {"none", "not-author", "not-requester"}
LIFECYCLE_ROLES = {"root", "router", "coordinator", "operator", "reviewer"}
ASSISTANTS = {"builder", "front-door", "orchestrator", "reviewer"}
# In the order the adapter offers them, which the generated profiles keep.
WORKSPACE_TOOLS = ("workspace_capacity", "workspace_initiative", "workspace_path_overlap")
READ_TOOLS = ["Read", "Glob", "Grep"]
WRITE_TOOLS = ["Edit", "Write"]
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
        fields(provision, {"adapter", "reader_shell", "assistants", "team_kind"})
        require(provision["adapter"] in {"mailbox", "decision"}, "role %s has an unknown adapter" % name)
        require(type(provision["reader_shell"]) is bool and type(provision["team_kind"]) is bool,
                "role %s has invalid provisioning flags" % name)
        require(provision["assistants"] is None or provision["assistants"] in ASSISTANTS,
                "role %s names an unknown assistant list" % name)
        # Codex has no file tools without its shell, so the shell is only for a role that reads source and
        # writes none; a writer already has one in its sandbox.
        require(not provision["reader_shell"] or ("source" in allowed["reads"] and "source" not in allowed["writes"]),
                "role %s: a reader shell is only for a role that reads source and writes none" % name)
        # The decision adapter offers one tool. A role that could also write source or mail through
        # it would turn a decision boundary into an operational one.
        require(provision["adapter"] != "decision" or not ({"source", "mailbox", "board"} & allowed["writes"]),
                "role %s: the decision adapter cannot carry write access" % name)
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


def writer(entry):
    return "source" in entry["writes"]


def file_tools(entry):
    """Host file tools: reading source gives the read tools, and writing it adds the edit tools."""
    return (READ_TOOLS if "source" in entry["reads"] else []) + (WRITE_TOOLS if writer(entry) else [])


def workspace_tools(entry):
    return tuple(name for name in WORKSPACE_TOOLS if name in entry["reads"])


def takes_board(entry):
    return "board" in entry["reads"]


def team_kinds():
    """The team.json reasoning_by_kind keys: a lane's kind, or the endpoint role for any other team role."""
    return {entry["endpoint"].get("lane_kind", entry["endpoint"]["role"])
            for entry in registry()["roles"].values()
            if entry["provision"] is not None and entry["provision"]["team_kind"]}
