"""Packaged role policy and immutable mailbox tables.

Only the fixed resource in the trusted installed package is opened. Registry bytes
and caller values are untrusted, bounded before parsing/validation, and refused
with fixed diagnostics. The legacy tools module is neither imported nor modified.
"""
from functools import wraps
from importlib import resources
from inspect import signature
import json
from types import MappingProxyType

from aegis_core.primitives import json_preflight
from aegis_core.team_mailbox_primitives import MailboxRefusal, RoleTables, bounded_tree

__all__ = [
    "RoleRefusal", "SCHEMA", "VOCABULARY", "ENDPOINT_ROLES", "LANE_KINDS", "VERTICAL_ROUTES",
    "SOURCE_VIEW_TOOLS", "WORKSPACE_TOOLS", "READ_TOOLS", "WRITE_TOOLS",
    "require", "fields", "text", "load_registry", "registry", "role_tables", "role_name",
    "actions", "lifecycle_connection", "decision_connection", "validate_role", "validate",
    "role", "session_roles", "fixed_model_profile", "reader_shell_roles", "writer", "file_tools",
    "require_file_tools", "workspace_tools", "lifecycle_tools", "decision_tools", "takes_board",
    "require_board", "source_views", "require_source_views", "require_independent_session", "team_kinds",
]

MAX_BYTES = 262144
SCHEMA = "aegis.role-registry/v1"
_GRAMMAR = RoleTables()
ENDPOINT_ROLES = _GRAMMAR.endpoint_roles
LANE_KINDS = _GRAMMAR.lane_kinds
VERTICAL_ROUTES = _GRAMMAR.vertical_routes

_NEXT = {
    "invalid_registry": "Restore a complete registry matching the role schema and retry.",
    "unsupported_schema": "Install a registry using aegis.role-registry/v1 and retry.",
    "unknown_key": "Remove fields outside the role registry schema and retry.",
    "duplicate_key": "Remove duplicate JSON keys from the registry and retry.",
    "duplicate_role": "Give each endpoint exactly one registry role and retry.",
    "unknown_action": "Select actions from the closed role vocabulary and retry.",
    "unknown_endpoint": "Use a registered endpoint and its manifest lane kind and retry.",
    "independent_session": "Bind the independent role to a separate host session and retry.",
    "not_permitted": "Use a role permitted for the requested capability and retry.",
    "too_large": "Reduce the registry or input to the documented size limits and retry.",
    "missing_registry": "Restore the installed package role registry and retry.",
    "registry_io": "Check the installed package resource is readable and retry.",
    "policy_io": "Check role policy observations and retry from current trusted mailbox state.",
}


class RoleRefusal(ValueError):
    """Fixed, input-free reason, exit code and repair guidance."""
    def __init__(self, reason):
        self.reason = reason if type(reason) is str and reason in _NEXT else "invalid_registry"
        self.code = 1
        self.status = "refused"
        self.next_action = _NEXT[self.reason]
        super().__init__("role registry refused: " + self.reason)

    def as_dict(self):
        return {"status": self.status, "reason": self.reason, "code": self.code,
                "next_action": self.next_action}


def _operation(reason="invalid_registry", *, budget=False):
    def decorate(function):
        parameters = signature(function).parameters
        names = frozenset(parameters)
        positional = tuple(parameters)
        required = frozenset(name for name, parameter in parameters.items()
                             if parameter.default is parameter.empty)
        @wraps(function)
        def call(*args, **kwargs):
            try:
                require(len(args) <= len(positional) and len(kwargs) <= len(names), reason=reason)
                require(kwargs.keys() <= names, reason=reason)
                provided = frozenset(positional[:len(args)])
                require(not provided & kwargs.keys(), reason=reason)
                require(required <= provided | kwargs.keys(), reason=reason)
                if budget:
                    bounded_tree(args)
                    bounded_tree(kwargs)
                return function(*args, **kwargs)
            except RoleRefusal:
                raise
            except MailboxRefusal as error:
                code = "too_large" if error.reason == "too_large" else reason
                raise RoleRefusal(code) from None
            except OSError:
                raise RoleRefusal("policy_io") from None
            except (ValueError, KeyError, IndexError, AttributeError,
                    RecursionError, OverflowError):
                raise RoleRefusal(reason) from None
        return call
    return decorate


def require(condition, *, reason="invalid_registry"):
    if type(condition) is not bool or type(reason) is not str or reason not in _NEXT:
        raise RoleRefusal("invalid_registry")
    if not condition:
        raise RoleRefusal(reason)


def fields(value, required, optional=()):
    require(type(value) is dict)
    require(len(value) <= 10000, reason="too_large")
    _strings(required, (set, frozenset, tuple, list))
    _strings(optional, (set, frozenset, tuple, list))
    require(set(required) <= value.keys())
    require(value.keys() <= set(required) | set(optional), reason="unknown_key")


def text(value, label, limit=4096):
    require(type(label) is str and type(limit) is int)
    require(type(value) is str and 0 < len(value) <= limit and "\x00" not in value)
    return value


def _strings(value, containers=(list,)):
    """Check collection shape before allocating a set/tuple or using its items."""
    require(type(value) in containers)
    require(len(value) <= 10000, reason="too_large")
    require(all(type(item) is str for item in value))
    return value


def _member(value, vocabulary, *, nullable=False):
    require(type(value) is str or nullable and value is None)
    require(nullable and value is None or value in vocabulary)


def _groups(entry, *groups):
    require(type(entry) is dict)
    for group in groups:
        require(group in entry)
        _strings(entry[group])


def _provision(entry):
    require(type(entry) is dict and 'provision' in entry)
    provision = entry['provision']
    require(type(provision) is dict)
    return provision


def _connection(name, role, allowed):
    text(name, 'role name', 64)
    bounded_tree(role)
    provision = _provision(role)
    require('adapter' in provision)
    _member(provision['adapter'], {'mailbox', 'decision'})
    require(type(allowed) is dict and set(VOCABULARY) <= allowed.keys())
    for group in VOCABULARY:
        _strings(allowed[group], (set, frozenset, list, tuple))
    return provision


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, reason="duplicate_key")
        result[key] = value
    return result


@_operation()
def load_registry(raw):
    """Load bytes or text; reject size, depth and duplicates before table creation."""
    require(type(raw) in (bytes, str))
    require(len(raw) <= MAX_BYTES, reason="too_large")
    if type(raw) is str:
        # Bound characters before the UTF-8 allocation, then bound encoded bytes.
        require(sum(1 if ord(c) < 128 else 2 if ord(c) < 2048 else 3 if ord(c) < 65536 else 4
                    for c in raw) <= MAX_BYTES, reason="too_large")
    checked = json_preflight(raw, max_bytes=MAX_BYTES, max_depth=32,
                             max_nodes=32768, max_items=10000,
                             max_string=MAX_BYTES, max_atom=64)
    return validate(json.loads(checked, object_pairs_hook=_pairs))


@_operation()
def registry():
    """Read bounded package data; no caller or environment supplies a path.

    No mutable global cache: failures do not poison a retry and callers cannot
    corrupt later or concurrent lookups by editing a returned registry.
    """
    try:
        with resources.files("aegis_core.team_templates").joinpath("role-registry.json").open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
    except FileNotFoundError:
        raise RoleRefusal("missing_registry") from None
    except OSError:
        raise RoleRefusal("registry_io") from None
    return load_registry(raw)


def _freeze(value):
    """Own a deeply read-only copy of an already bounded, validated JSON tree."""
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) in (list, tuple):
        return tuple(_freeze(item) for item in value)
    return value


def _snapshot():
    return _freeze(registry())


def _thaw(value):
    """Preserve the public JSON dict/list values without exposing the snapshot."""
    if type(value) is MappingProxyType:
        return {key: _thaw(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_thaw(item) for item in value]
    return value


def _endpoint_key(endpoint, kind):
    try:
        family = _GRAMMAR.endpoint_parts(endpoint)[1]
    except MailboxRefusal:
        raise RoleRefusal("unknown_endpoint") from None
    if family == "lane":
        require(type(kind) is str and len(kind) <= 64 and kind in LANE_KINDS,
                reason="unknown_endpoint")
    return family, kind if family == "lane" else family


def _lookup(snapshot, endpoint_key):
    family, key = endpoint_key
    for name, entry in snapshot['roles'].items():
        definition = entry['endpoint']
        if (definition is not None and definition['role'] == family
                and definition.get('lane_kind', definition['role']) == key):
            return name
    raise RoleRefusal("unknown_endpoint")


def _entry(snapshot, endpoint_key):
    return snapshot['roles'][_lookup(snapshot, endpoint_key)]


def _session_roles(snapshot):
    return tuple(sorted(name for name, entry in snapshot['roles'].items() if entry['endpoint'] is not None))


def _file_tools(entry):
    return (READ_TOOLS if 'source' in entry['reads'] else []) + (WRITE_TOOLS if 'source' in entry['writes'] else [])


def _source_views(entry):
    return 'source' in entry['reads'] and 'source' not in entry['writes']


@_operation(budget=True)
def role_tables(value=None):
    """Build immutable tables only after complete validation.

    Writes retain registry vocabulary verbatim; this does not invent mailbox
    operation grants (bind, initialize, etc.). Operation policy remains the
    integrating caller's responsibility. Grammar is the TA-1 immutable grammar.
    """
    snapshot = _snapshot() if value is None else _freeze(validate(value))
    entries = snapshot["roles"]
    independent = {entry["endpoint"].get("lane_kind", entry["endpoint"]["role"])
                   for entry in entries.values()
                   if entry["endpoint"] and entry["independence"]["separate_session"]}
    return RoleTables(writes={name: entry["writes"] for name, entry in entries.items()},
                      vertical_routes=snapshot["routes"], independent=independent)


@_operation("unknown_endpoint")
def role_name(endpoint, kind=None):
    """Resolve an endpoint using the manifest kind for a lane."""
    key = _endpoint_key(endpoint, kind)
    return _lookup(_snapshot(), key)


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
# In the order the adapter offers them.
SOURCE_VIEW_TOOLS = ("source_show", "source_grep")

@_operation(budget=True)
def actions(role, name, group):
    text(name, 'role name', 64)
    _member(group, VOCABULARY)
    require(type(role) is dict and group in role)
    values = role[group]
    _strings(values)
    require(len(values) == len(set(values)))
    for value in values:
        require(isinstance(value, str) and value in VOCABULARY[group], reason='unknown_action')
    return set(values)


@_operation()
def lifecycle_connection(name, role, allowed):
    """Only the journal role a tool is written for may carry it: the Router reads status, the Decider records
    within a delegation. ROOT's adapter is the decision tool alone."""
    provision = _connection(name, role, allowed)
    require('lifecycle_tools' in provision and 'lifecycle_role' in role)
    require(role['lifecycle_role'] is None or type(role['lifecycle_role']) is str)
    tools = _strings(provision['lifecycle_tools'])
    require(len(tools) == len(set(tools)))
    for tool in tools:
        require(isinstance(tool, str) and tool in LIFECYCLE_TOOLS)
    require(role['provision']['adapter'] != 'decision' or not tools)
    require('router_status' not in tools or ('lifecycle' in allowed['reads'] and role['lifecycle_role'] == 'router'))
    require('decider_record' not in tools or ('lifecycle:delegated_decision' in allowed['approvals'] and role['lifecycle_role'] == 'decider'))


@_operation()
def decision_connection(name, role, allowed):
    """ROOT's read tools ride only on the decision adapter, and each needs the reads it shows ROOT."""
    provision = _connection(name, role, allowed)
    tools = _strings(provision.get('decision_tools', []))
    require(len(tools) == len(set(tools)))
    for tool in tools:
        require(isinstance(tool, str) and tool in DECISION_READ_TOOLS)
    require(not tools or role['provision']['adapter'] == 'decision')
    for tool in tools:
        missing = DECISION_TOOL_READS[tool] - set(allowed['reads'])
        require(not missing)


@_operation(budget=True)
def validate_role(name, role):
    text(name, 'role name', 64)
    fields(role, ROLE_FIELDS)
    for key in ('title', 'responsibility'):
        text(role[key], 'role ' + key, 256)
    _member(role['kind'], KINDS)
    _member(role['m1'], M1_USE)
    allowed = {group: actions(role, name, group) for group in VOCABULARY}
    prohibitions = role['prohibitions']
    fields(prohibitions, set(VOCABULARY))
    for group in VOCABULARY:
        refused = actions(prohibitions, name, group)
        require(not refused & allowed[group])
    lifecycle = {action for action in allowed['writes'] | allowed['approvals'] if action.startswith('lifecycle:')}
    _member(role['lifecycle_role'], LIFECYCLE_ROLES, nullable=True)
    require(role['lifecycle_role'] is not None or not lifecycle)
    independence = role['independence']
    fields(independence, {'rule', 'separate_session'})
    _member(independence['rule'], INDEPENDENCE)
    require(type(independence['separate_session']) is bool)
    profile = role['model_profile']
    require(type(profile) is dict and 'source' in profile)
    _member(profile['source'], {'team', 'fixed', 'none'})
    fields(profile, {'source'}, {'effort', 'tier'} if profile['source'] == 'fixed' else set())
    endpoint, provision = (role['endpoint'], role['provision'])
    if endpoint is None:
        require(provision is None)
    else:
        fields(endpoint, {'role'}, {'lane_kind'})
        _member(endpoint['role'], ENDPOINT_ROLES)
        require(('lane_kind' in endpoint) == (endpoint['role'] == 'lane'))
        if 'lane_kind' in endpoint:
            text(endpoint['lane_kind'], 'lane kind', 64)
        fields(provision, {'adapter', 'reader_shell', 'assistants', 'team_kind', 'lifecycle_tools'}, {'decision_tools'})
        _member(provision['adapter'], {'mailbox', 'decision'})
        require(type(provision['reader_shell']) is bool and type(provision['team_kind']) is bool)
        _member(provision['assistants'], ASSISTANTS, nullable=True)
        require(not provision['reader_shell'] or ('source' in allowed['reads'] and 'source' not in allowed['writes']))
        require(provision['adapter'] != 'decision' or not {'source', 'mailbox', 'board'} & allowed['writes'])
        lifecycle_connection(name, role, allowed)
        decision_connection(name, role, allowed)
    require(role['service'] is None or (endpoint is None and role['kind'] == 'service'))
    if role['service'] is not None:
        text(role['service'], 'service module', 128)
    for link in ('hat_of', 'reports_to'):
        require(role[link] is None or type(role[link]) is str)


@_operation(budget=True)
def validate(registry):
    fields(registry, {'schema', 'routes', 'roles'})
    require(registry['schema'] == SCHEMA, reason='unsupported_schema')
    roles = registry['roles']
    require(isinstance(roles, dict) and 0 < len(roles) <= 64)
    endpoints = {}
    for name, role in roles.items():
        text(name, 'role name', 64)
        validate_role(name, role)
        if role['endpoint'] is not None:
            key = role['endpoint'].get('lane_kind', role['endpoint']['role'])
            require(key not in endpoints, reason='duplicate_role')
            endpoints[key] = name
    for name, role in roles.items():
        for link in ('hat_of', 'reports_to'):
            target = role[link]
            require(target is None or target in roles)
        if role['hat_of'] is not None:
            require(role['endpoint'] is None and roles[role['hat_of']]['endpoint'] is not None)
    named = {role['endpoint']['role'] for role in roles.values() if role['endpoint'] is not None}
    require(named == set(ENDPOINT_ROLES))
    lanes = {role['endpoint']['lane_kind'] for role in roles.values() if role['endpoint'] is not None and role['endpoint']['role'] == 'lane'}
    require(lanes == set(LANE_KINDS))
    routes = registry['routes']
    require(isinstance(routes, list) and all((isinstance(pair, list) and len(pair) == 2 for pair in routes)))
    require(all(type(value) is str for pair in routes for value in pair))
    pairs = [frozenset(pair) for pair in routes]
    require(len(pairs) == len(set(pairs)) and all((len(pair) == 2 for pair in pairs)))
    require(set(pairs) == {frozenset(pair) for pair in VERTICAL_ROUTES})
    return registry


@_operation()
def role(endpoint, kind=None):
    key = _endpoint_key(endpoint, kind)
    return _thaw(_entry(_snapshot(), key))


@_operation()
def session_roles():
    """Registry roles that have a session endpoint, in a stable order."""
    return _session_roles(_snapshot())


@_operation(budget=True)
def fixed_model_profile(entry):
    """A fixed effort/tier expectation shared by provisioning and native observation."""
    require(type(entry) is dict and 'model_profile' in entry)
    profile = entry['model_profile']
    require(type(profile) is dict and 'source' in profile)
    require(type(profile['source']) is str)
    return dict(profile) if profile['source'] == 'fixed' else None


@_operation()
def reader_shell_roles():
    snapshot = _snapshot()
    return tuple(name for name in _session_roles(snapshot) if snapshot['roles'][name]['provision']['reader_shell'])


@_operation(budget=True)
def writer(entry):
    _groups(entry, 'writes')
    return 'source' in entry['writes']


@_operation(budget=True)
def file_tools(entry):
    """Host file tools: reading source gives the read tools, and writing it adds the edit tools."""
    _groups(entry, 'reads', 'writes')
    return _file_tools(entry)


@_operation()
def require_file_tools(endpoint, kind, names):
    require(type(names) in (list, tuple, set, frozenset))
    key = _endpoint_key(endpoint, kind)
    permitted = _file_tools(_entry(_snapshot(), key))
    for tool in names:
        require(type(tool) is str and tool in permitted, reason='not_permitted')


@_operation(budget=True)
def workspace_tools(entry):
    _groups(entry, 'reads')
    return tuple((name for name in WORKSPACE_TOOLS if name in entry['reads']))


@_operation(budget=True)
def lifecycle_tools(entry):
    provision = _provision(entry)
    require('lifecycle_tools' in provision)
    return tuple(_strings(provision['lifecycle_tools']))


@_operation(budget=True)
def decision_tools(entry):
    """ROOT's read tools, in the order its adapter offers them after root_decide."""
    provision = _provision(entry)
    return tuple(_strings(provision.get('decision_tools', ()), (list, tuple)))


@_operation(budget=True)
def takes_board(entry):
    _groups(entry, 'reads')
    return 'board' in entry['reads']


@_operation()
def require_board(endpoint, kind=None):
    key = _endpoint_key(endpoint, kind)
    require('board' in _entry(_snapshot(), key)['reads'], reason='not_permitted')


@_operation(budget=True)
def source_views(entry):
    """Pinned show and grep stand in for a shell: for a role that reads source and writes none. A writer already
    has its worktree, and a role that never reads source has nothing to read."""
    _groups(entry, 'reads', 'writes')
    return _source_views(entry)


@_operation()
def require_source_views(endpoint, kind=None):
    key = _endpoint_key(endpoint, kind)
    require(_source_views(_entry(_snapshot(), key)), reason='not_permitted')


@_operation()
def require_independent_session(mailbox, endpoint, host, session):
    """Where independence is the control, the registry asks for a separate session, so one session can never hold
    both sides. Mailbox.bind calls this, so every path that binds is checked: the CLI, provisioning, a move and a
    handoff. Only the current binding of each other endpoint counts, and only the separate_session flag is
    mechanical; the not-author and not-requester rules are for the roles' own checks.

    The rule separates different roles. One session may hold the same role on several endpoints, such as one
    ROOT for hierarchies a and b in a shared root, because no independence boundary lies between them."""
    text(endpoint, 'endpoint', 256)
    text(host, 'host')
    text(session, 'session')
    require(callable(getattr(mailbox, 'endpoint', None)) and callable(getattr(mailbox, 'bindings', None)))
    manifest = getattr(mailbox, 'manifest', None)
    require(type(manifest) is dict and 'endpoints' in manifest)
    endpoints = manifest['endpoints']
    require(type(endpoints) is dict)
    bounded_tree(endpoints)
    definition = mailbox.endpoint(endpoint)
    require(type(definition) is dict)
    key = _endpoint_key(endpoint, definition.get('kind'))
    snapshot = _snapshot()
    name = _lookup(snapshot, key)
    mine = snapshot['roles'][name]
    for other in endpoints:
        if other == endpoint:
            continue
        history = mailbox.bindings(other)
        require(type(history) is list)
        if not history:
            continue
        latest = history[-1]
        require(type(latest) is dict and {'host', 'session'} <= latest.keys())
        require(type(latest['host']) is str and type(latest['session']) is str)
        if (latest['host'], latest['session']) != (host, session):
            continue
        definition = mailbox.endpoint(other)
        require(type(definition) is dict)
        other_name = _lookup(snapshot, _endpoint_key(other, definition.get('kind')))
        if other_name == name:
            continue
        theirs = snapshot['roles'][other_name]
        if mine['independence']['separate_session'] or theirs['independence']['separate_session']:
            raise RoleRefusal('independent_session')


@_operation()
def team_kinds():
    """The team.json reasoning_by_kind keys: a lane's kind, or the endpoint role for any other team role."""
    snapshot = _snapshot()
    return {entry['endpoint'].get('lane_kind', entry['endpoint']['role']) for entry in snapshot['roles'].values() if entry['provision'] is not None and entry['provision']['team_kind']}
