"""Pinned lifecycle values and fixed refusals over caller-held core storage.

Native authority is injected; this module never discovers plans or imports tools.
"""
from __future__ import annotations
from contextlib import contextmanager
from functools import wraps
import copy
import errno
import hashlib
import inspect
import json
import math
import os
from pathlib import Path, PurePath, PurePosixPath
from types import MappingProxyType
import uuid
from aegis_core.primitives import json_preflight
from aegis_core.team_mailbox_primitives import GIT_ID, SHA256, SLUG, MailboxRefusal, bounded_tree, fields, integer, matching, parse_time, text, render_mailbox_refusal

__all__ = [
    'INITIAL_ENVELOPE', 'JOURNAL', 'LifecycleRefusal', 'MAX_BYTES', 'MAX_EVENTS', 'POLICY', 'SHA256', 'SLUG',
    'active_seconds', 'actor_for', 'add_request', 'approved_authority', 'boundary', 'bounded_tree', 'checkpoint', 'covered',
    'delegated_decision', 'digest', 'encoded', 'evidence', 'fields', 'initial_key', 'initial_state', 'inspect_request',
    'matching', 'parse_time', 'policy_field', 'provider_handle', 'raw_value', 'reduce_event', 'require', 'resolve_row',
    'safe_path', 'small_change_approval', 'small_change_event', 'small_change_execution', 'small_change_participant', 'small_change_participants', 'small_change_review', 'small_change_started',
    'source', 'strict_json', 'target', 'unknown_effect', 'validate_association', 'validate_mapping', 'validate_observation', 'validate_policy', 'validate_request',
]

class LifecycleRefusal(ValueError):
    """Fixed refusal envelope, including a closed policy-field vocabulary."""

    def __init__(self, code='invalid_record', *, field=None):
        if type(code) is not str or field is not None and type(field) is not str:
            raise LifecycleRefusal()
        self.code, self.field = (code, field)
        self.reason = 'lifecycle refused: ' + code
        self.next_action = 'Supply a qualified host-authority port before retrying.' if code == 'unqualified' else 'Reconcile the lifecycle input and canonical history before retrying.'
        super().__init__(self.reason)

    def as_dict(self):
        if not isinstance(self, LifecycleRefusal):
            raise LifecycleRefusal()
        return {'state': 'refused', 'code': self.code, 'reason': self.reason, 'next_action': self.next_action, 'field': self.field}
_CONTINUATION_REASONS = frozenset({'a delegation authorizes the Decider, not work', 'actor cumulative active cap reached', 'bounded authority exhausted', 'bounded authority expired', 'canonical request is denied', 'invalid small-change participant generation', 'no approved bounded authority', 'prerequisite lacks accepted delivery', 'request is outside approved continuation', 'small-change participant generation mismatch', 'small-change participant is no longer current', 'small-change participant role mismatch', 'small-change plan lacks admission', 'small-change plan lacks approval', 'small-change reviewer must be independent'})

def require(condition, message=''):
    if type(message) is not str or type(condition) is not bool and not (type(condition) is list and not condition):
        raise LifecycleRefusal()
    if not condition:
        error = LifecycleRefusal()
        error.continuation_reason = message if message in _CONTINUATION_REASONS else error.reason
        raise error

_DECORATOR = object()

def boundary(function=_DECORATOR, *, checks=None):
    """Bind explicit validators at registration and translate documented failures."""
    require(checks is None or type(checks) is dict)
    bindings = MappingProxyType(checks.copy() if checks is not None else {})
    require(checks is None or bool(bindings) and
            all(type(name) is str and callable(check) for name, check in bindings.items()))

    def call(target, positional_count, names, keywords, required, args, kwargs):
        try:
            require(len(args) <= positional_count and kwargs.keys() <= keywords)
            values = dict(zip(names, args), **kwargs)
            require(len(values) == len(args) + len(kwargs) and required <= values.keys())
            for name in filter(bindings.__contains__, values):
                bindings[name](values[name])
            return target(*args, **kwargs)
        except MailboxRefusal as error:
            raise LifecycleRefusal(render_mailbox_refusal(error)["reason"]) from None
        except LifecycleRefusal:
            raise
        except OSError as error:
            refusal = {errno.ENOENT: 'missing', errno.EEXIST: 'exists', errno.ELOOP: 'unsafe_path', errno.ENOTDIR: 'unsafe_path'}.get(error.errno, 'io')
            raise LifecycleRefusal(refusal) from None
        except (ValueError, KeyError, AttributeError, RecursionError, OverflowError):
            raise LifecycleRefusal() from None

    def decorate(target, /):
        require(inspect.isfunction(target))
        code = target.__code__
        names = code.co_varnames[:code.co_argcount + code.co_kwonlyargcount]
        require(bindings.keys() <= set(names))
        keywords = frozenset(names[code.co_posonlyargcount:])
        required = frozenset(names[:code.co_argcount - len(target.__defaults__ or ())]) | (
            frozenset(names[code.co_argcount:]) - (target.__kwdefaults__ or {}).keys())
        @wraps(target)
        def wrapped(*args, **kwargs):
            return call(target, code.co_argcount, names, keywords, required, args, kwargs)
        return wrapped

    return decorate if function is _DECORATOR and checks is not None else decorate(function)

_MAP_FIELDS = frozenset({'event', 'custody', 'continuation', 'profile', 'actors', 'current', 'successors', 'requests', 'consumed', 'receipts', 'meters', 'request', 'intent', 'start', 'terminal', 'admission', 'association', 'initial_bootstrap', 'genesis', 'creations', 'small_change', 'registration', 'envelope', 'value', 'cancellation', 'resolution', 'provider_handle'})
_NULL_MAPS = frozenset({'intent', 'start', 'terminal', 'admission', 'association', 'cancellation', 'resolution', 'provider_handle'})
_LIST_FIELDS = frozenset({'decisions', 'delegated_decisions', 'observations', 'results', 'dispositions', 'successions', 'reservations', 'writing_lanes'})
_ID_MAPS = frozenset({'actors', 'current', 'successors', 'requests', 'consumed', 'receipts', 'meters', 'creations'})
_STRING_FIELDS = frozenset({'id', 'actor', 'actor_cid', 'cid', 'role', 'type', 'decision', 'provider_state', 'outcome', 'kind', 'verdict', 'status', 'subject', 'predecessor', 'request_id', 'delegation_id', 'intent_id', 'original_actor'})

def _shape(value):
    bounded_tree(value, limit=67108864)
    pending = [(value, None)]
    while pending:
        item, context = pending.pop()
        if type(item) is list:
            pending.extend((entry, None) for entry in item)
        elif type(item) is dict:
            # Identity-map keys are data, even when they spell schema labels.
            if context in _ID_MAPS:
                pending.extend((entry, None) for entry in item.values())
                continue
            if 'request' in item and 'raw' in item:
                require(type(item['raw']) is dict)
                require(all(item.get(key) is None or type(item[key]) is dict for key in ('review', 'delivery', 'wait', 'read', 'routed')))
            for key, child in item.items():
                if key in _MAP_FIELDS:
                    require(type(child) is dict or child is None and key in _NULL_MAPS)
                if key in _LIST_FIELDS:
                    require(type(child) is list and all(type(entry) is dict for entry in child))
                    require(key != 'writing_lanes' or len(child) > 0)
                if key in _STRING_FIELDS:
                    require(type(child) is str)
                if key in {'current', 'successors'}:
                    require(all(type(entry) is str for entry in child.values()))
                if key in {'actors', 'requests', 'receipts', 'meters', 'creations'}:
                    require(all(type(entry) is dict for entry in child.values()))
                if key == 'consumed':
                    require(all(type(entry) is int for entry in child.values()))
                if key == 'request' and 'authority' in child:
                    require(type(child['authority']) is str)
                if key in {'sequence', 'generation'}:
                    require(type(child) is int)
                if key == 'active_seconds':
                    require(type(child) in (int, float) and math.isfinite(child))
                pending.append((child, key))

def _mapping(value):
    """Validate a bounded lifecycle mapping before copies or nested access."""
    require(type(value) is dict)
    _shape(value)

validate_mapping = boundary(_mapping)

def _string(value):
    require(type(value) is str)

def _path_value(value, *, posix=False):
    """Keep legacy pathlib semantics for trusted in-process path objects."""
    require(isinstance(value, (str, os.PathLike)))
    if not isinstance(value, (str, PurePath)):
        protocol = inspect.getattr_static(type(value), '__fspath__', None)
        binding = getattr(type(protocol), '__get__', None)
        if binding is not None:
            require(callable(binding))
            protocol = binding(protocol, value, type(value))
        require(callable(protocol))
        value = protocol()
        require(isinstance(value, str))
    path = (PurePosixPath if posix else Path)(value)
    spelling = str(path)
    if len(spelling) > 32768 or len(path.parts) > 128:
        raise LifecycleRefusal('unsafe_path')
    size = 0
    for char in spelling:
        code = ord(char)
        size += 1 if code < 128 else 2 if code < 2048 else 3 if code < 65536 else 4
        if size > 32768:
            raise LifecycleRefusal('unsafe_path')
    return path

@boundary
def safe_path(value):
    path = _path_value(value)
    require(path.is_absolute() and '..' not in path.parts)
    require(not path.is_symlink())
    require(not any(part.is_symlink() for part in path.parents))
    return path

@contextmanager
def policy_field(name):
    require(type(name) is str and name in {'schema', 'source', 'authority', 'actors', 'current', 'successors'})
    try:
        yield
    except (ValueError, KeyError, OSError):
        raise LifecycleRefusal('invalid_policy', field=name) from None

@boundary
def strict_json(raw):
    checked = json_preflight(raw, max_bytes=MAX_BYTES, max_depth=32, max_nodes=32768, max_items=10000, max_string=MAX_BYTES, max_atom=64)

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result

    def nonfinite(value):
        raise LifecycleRefusal()
    result = json.loads(checked, object_pairs_hook=pairs, parse_constant=nonfinite)
    bounded_tree(result, limit=MAX_BYTES)
    return result

@boundary
def encoded(value, *, limit=67108864):
    require(type(limit) is int and 0 <= limit <= 67108864)
    bounded_tree(value, limit=limit, ascii_strings=True)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('utf-8')

def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()
POLICY = 'aegis.lifecycle-policy/v1'
REQUEST = 'aegis.lifecycle-request/v1'
SMALL_CHANGE_PLAN = 'aegis.small-change-plan/v1'
REQUEST_INSPECTION = 'aegis.request-inspection/v1'
JOURNAL = 'aegis.lifecycle-event/v1'
ZERO = '0' * 64
MAX_EVENTS = 10000
MAX_REQUESTS = 256
MAX_BYTES = 1048576
ROLES = {'root', 'router', 'coordinator', 'operator', 'reviewer', 'decider'}
OPTIONAL_ROLES = {'decider'}
INITIAL_ENVELOPE = 'aegis.initial-bootstrap-envelope/v1'
UINT64 = (1 << 64) - 1
PERMISSIONS = {'publish': {'coordinator', 'router'}, 'read': {'router', 'coordinator', 'operator', 'reviewer'}, 'route': {'router'}, 'decision': {'root'}, 'delegated_decision': {'decider'}, 'admit': {'operator'}, 'wait': {'operator'}, 'intent': {'operator'}, 'start': {'operator'}, 'terminal': {'operator'}, 'meter': {'operator'}, 'review': {'reviewer'}, 'delivery': {'coordinator'}, 'disposition': {'coordinator'}, 'resolve': {'coordinator'}, 'succeed': ROLES, 'associate': {'operator'}, 'observe': {'operator'}, 'cancel_attempt': {'operator'}, 'small_change_plan': {'coordinator', 'router'}, 'small_change_decision': {'root'}, 'small_change_admit': {'operator'}}
GATES = {'source', 'capability', 'lease', 'capacity', 'observer', 'job'}
PROVIDER_STATES = {'not_started', 'running', 'disconnected', 'ambiguous', 'cancel_requested', 'cancelled', 'passed', 'failed', 'unknown'}

# The reducer calls the private implementations with data already checked at
# its boundary. The public wrappers also accept independent caller input.
def _provider_handle(row):
    for observation in row.get('observations', []):
        handle = observation['value']['provider_handle']
        if handle is not None:
            return handle
    return None

provider_handle = boundary(_provider_handle, checks={'row': _mapping})

def _validate_observation(row, value):
    fields(value, {'association_sha256', 'provider_state', 'provider_handle', 'exit_code', 'evidence', 'quiescent'})
    require(value['association_sha256'] == row['association']['sha256'])
    require(isinstance(value['provider_state'], str) and value['provider_state'] in PROVIDER_STATES)
    require(type(value['quiescent']) is bool)
    handle = value['provider_handle']
    if handle is not None:
        fields(handle, {'thread_id', 'turn_id'})
        for name in handle:
            text(handle[name], 'provider ' + name, 256)
        require(handle['thread_id'] == row['association']['value']['thread_id'])
        known = _provider_handle(row)
        require(known is None or known == handle)
    state, code = (value['provider_state'], value['exit_code'])
    if state in {'passed', 'failed', 'cancelled'}:
        require(handle is not None and value['quiescent'] is True)
        require(type(code) is int and (code == 0 if state == 'passed' else code != 0))
    else:
        require(code is None and value['quiescent'] is False)
    evidence(value['evidence'])
    return value

validate_observation = boundary(_validate_observation, checks={'row': _mapping})

def _validate_association(policy, state, row, value, cid, at):
    require('small_change' not in row)
    fields(value, {'schema', 'request_id', 'request_sha256', 'intent_id', 'source', 'authority', 'authority_sha256', 'decision_sha256', 'admission_sha256', 'original_actor', 'original_generation', 'original_cap_seconds', 'authority_expires_at', 'provider', 'endpoint_id', 'thread_id', 'client_id', 'deadline'})
    require(value['schema'] == 'aegis.provider-association/v1')
    request = row['request']
    require(row['intent'] is not None and row['start'] is not None)
    require(row['intent']['actor'] == cid)
    require(row['terminal'] is None and row.get('association') is None)
    authority = state['requests'][request['authority']]
    decisions = [d for d in state['decisions'] if d['request_id'] == request['authority']]
    require(decisions and decisions[-1]['decision'] == 'approve')
    expected = {'request_id': request['id'], 'request_sha256': row['raw']['sha256'], 'intent_id': row['intent']['id'], 'source': request['source'], 'authority': request['authority'], 'authority_sha256': authority['raw']['sha256'], 'decision_sha256': digest(decisions[-1]), 'admission_sha256': digest(row['admission']), 'original_actor': cid, 'original_generation': policy['actors'][cid]['generation'], 'original_cap_seconds': policy['actors'][cid]['cap_seconds'], 'authority_expires_at': authority['request']['continuation']['expires_at'], 'client_id': 'client-' + row['intent']['id']}
    require(all((value[k] == v for k, v in expected.items())))
    integer(value['original_generation'], 'original generation')
    integer(value['original_cap_seconds'], 'original cap', maximum=3600)
    for name, limit in (('provider', 128), ('endpoint_id', 128), ('thread_id', 256), ('client_id', 256)):
        text(value[name], 'provider ' + name, limit)
    require(parse_time(at) < parse_time(value['deadline']) <= parse_time(value['authority_expires_at']))
    require((parse_time(value['deadline']) - parse_time(at)).total_seconds() <= policy['actors'][cid]['cap_seconds'] - _active_seconds(state, cid, at))
    return value

validate_association = boundary(_validate_association, checks={'policy': _mapping, 'state': _mapping, 'row': _mapping, 'cid': _string, 'at': _string})

@boundary
def evidence(value):
    require(isinstance(value, list) and 0 < len(value) <= 64)
    for ref in value:
        fields(ref, {'path', 'sha256'})
        safe_path(text(ref['path'], 'evidence path'))
        matching(ref['sha256'], SHA256, 'evidence sha256')

@boundary
def source(value):
    fields(value, {'commit', 'tree', 'dirty_sha256'})
    for key in ('commit', 'tree'):
        matching(value[key], GIT_ID, 'source ' + key)
    matching(value['dirty_sha256'], SHA256, 'source dirty sha256')

@boundary
def raw_value(value):
    fields(value, {'raw', 'sha256'})
    spelling = text(value['raw'], 'raw request', MAX_BYTES)
    parsed = strict_json(spelling)
    raw = spelling.encode('utf-8')
    matching(value['sha256'], SHA256, 'raw request sha256')
    require(hashlib.sha256(raw).hexdigest() == value['sha256'])
    return parsed

def _validate_request(raw):
    value = raw_value(raw)
    fields(value, {'schema', 'id', 'version', 'team', 'owner', 'next_decision', 'phase', 'operation', 'source', 'paths', 'prerequisites', 'authority', 'continuation'})
    require(value['schema'] == REQUEST)
    for key in ('id', 'team', 'phase', 'operation', 'authority'):
        matching(value[key], SLUG, key)
    integer(value['version'], 'request version')
    for key in ('owner', 'next_decision'):
        text(value[key], key)
    source(value['source'])
    require(isinstance(value['paths'], list) and 0 < len(value['paths']) <= 256)
    for path in value['paths']:
        safe_path(text(path, 'request path'))
    require(isinstance(value['prerequisites'], list) and len(value['prerequisites']) <= 256)
    for identifier in value['prerequisites']:
        matching(identifier, SLUG, 'prerequisite')
    require(value['id'] not in value['prerequisites'])
    scope = value['continuation']
    fields(scope, {'members', 'max_starts', 'expires_at'})
    integer(scope['max_starts'], 'max_starts', maximum=256)
    parse_time(scope['expires_at'])
    require(isinstance(scope['members'], list) and len(scope['members']) <= 255)
    known = {value['id']}
    for member in scope['members']:
        fields(member, {'id', 'sha256', 'phase', 'operation'})
        for key in ('id', 'phase', 'operation'):
            matching(member[key], SLUG, 'continuation ' + key)
        matching(member['sha256'], SHA256, 'continuation sha256')
        require(member['id'] not in known)
        known.add(member['id'])
    require(value['authority'] == value['id'] or not scope['members'])
    return value

validate_request = boundary(_validate_request, checks={'raw': _mapping})

@boundary
def inspect_request(value):
    """Classify inert declarations, without loading a journal or conferring authority.

    The plan is separate from the unchanged v1 request, and names its exact raw
    hash. Neither the declared approved scope nor distinct actor names establish
    approval, admitted checks, authenticated identity or execution authority.
    """
    plan = None
    if isinstance(value, dict) and 'schema' in value:
        fields(value, {'schema', 'request', 'plan'})
        require(value['schema'] == SMALL_CHANGE_PLAN)
        raw, plan = (value['request'], value['plan'])
    else:
        raw = value
    request = validate_request(raw)
    reasons = []
    independence = 'not_declared'
    if plan is None:
        require(value is raw)
        reasons.append('plan_missing')
    else:
        flags = ('shared_interface_change', 'migration', 'governance_change', 'budget_expansion', 'scope_certain')
        fields(plan, {'request_sha256', 'projects', 'writing_lanes', 'path_scopes', 'checks', 'reviewer', *flags})
        matching(plan['request_sha256'], SHA256, 'plan request sha256')
        require(plan['request_sha256'] == raw['sha256'])
        for name in flags:
            require(type(plan[name]) is bool)
        for name in ('projects', 'checks'):
            items = plan[name]
            require(isinstance(items, list) and len(items) <= 256)
            for item in items:
                matching(item, SLUG, 'plan ' + name)
            require(len(set(items)) == len(items))
        lanes = plan['writing_lanes']
        require(isinstance(lanes, list) and len(lanes) <= 256)
        lane_ids, writers = (set(), set())
        for lane in lanes:
            fields(lane, {'lane', 'writer'})
            matching(lane['lane'], SLUG, 'plan lane')
            matching(lane['writer'], SLUG, 'plan writer')
            require(lane['lane'] not in lane_ids)
            require(lane['writer'] not in writers)
            lane_ids.add(lane['lane'])
            writers.add(lane['writer'])
        scopes = plan['path_scopes']
        require(isinstance(scopes, list) and len(scopes) <= 256)
        for paths in scopes:
            require(isinstance(paths, list) and 0 < len(paths) <= 256)
            for path in paths:
                safe_path(text(path, 'plan path'))
            require(len(set(paths)) == len(paths))
        matching(plan['reviewer'], SLUG, 'plan reviewer')
        for name, items in (('project_count', plan['projects']), ('writing_lane_count', lanes), ('path_scope_count', scopes)):
            if len(items) != 1:
                reasons.append(name)
        if len(scopes) == 1 and set(scopes[0]) != set(request['paths']):
            reasons.append('path_scope_mismatch')
        if not plan['checks']:
            reasons.append('checks_missing')
        independence = 'declared_distinct'
        if plan['reviewer'] in writers:
            reasons.append('writer_reviewer_conflict')
            independence = 'conflict'
        for name in flags[:-1]:
            if plan[name]:
                reasons.append(name)
        if not plan['scope_certain']:
            reasons.append('uncertain_scope')
    return {'schema': REQUEST_INSPECTION, 'request_id': request['id'], 'request_sha256': raw['sha256'], 'request_schema': request['schema'], 'classification': 'full_planning_required' if reasons else 'declared_eligible', 'escalation_reasons': reasons, 'approval': 'not_evaluated', 'checks_admission': 'not_evaluated', 'reviewer_independence': independence, 'reviewer_authenticated': False, 'execution_enabled': False}

@boundary
def validate_policy(value):
    with policy_field('schema'):
        bounded_tree(value, limit=MAX_BYTES)
    with policy_field('schema'):
        fields(value, {'schema', 'source', 'authority', 'actors', 'current', 'successors'})
    with policy_field('schema'):
        require(value['schema'] == POLICY)
    with policy_field('source'):
        source(value['source'])
    with policy_field('authority'):
        evidence(value['authority'])
    with policy_field('actors'):
        actors = value['actors']
        require(isinstance(actors, dict) and 5 <= len(actors) <= 128)
        for cid, actor in actors.items():
            matching(cid, SLUG, 'actor CID')
            fields(actor, {'role', 'generation', 'profile', 'cap_seconds'})
            require(type(actor['role']) is str and actor['role'] in ROLES)
            integer(actor['generation'], 'actor generation')
            integer(actor['cap_seconds'], 'actor cap', maximum=86400 if actor['role'] == 'root' else 3600)
            profile = actor['profile']
            fields(profile, {'model', 'effort', 'tier', 'filesystem', 'tools'})
            for key in ('model', 'effort', 'tier', 'filesystem'):
                text(profile[key], 'profile ' + key, 128)
            require(isinstance(profile['tools'], list) and all((isinstance(t, str) for t in profile['tools'])))
            if actor['role'] == 'root':
                require(profile['filesystem'] == 'read-only' and set(profile['tools']) <= {'read', 'decide', 'attest'})
            if actor['role'] == 'router':
                require(profile['effort'] == 'medium' and profile['tier'] == 'ultrafast')
    with policy_field('current'):
        fields(value['current'], ROLES - OPTIONAL_ROLES, OPTIONAL_ROLES)
        for role, cid in value['current'].items():
            require(type(cid) is str and cid in actors and actors[cid]['role'] == role)
    with policy_field('successors'):
        require(isinstance(value['successors'], dict))
        for old, new in value['successors'].items():
            require(type(new) is str and old in actors and new in actors and (old != new))
            before, after = (actors[old], actors[new])
            require(before['role'] == after['role'] and after['generation'] == before['generation'] + 1)
            require(before['profile'] == after['profile'] and before['cap_seconds'] == after['cap_seconds'])
    return value

@boundary(checks={'policy': _mapping})
def initial_state(policy):
    return {'sequence': 0, 'head': ZERO, 'current': copy.deepcopy(policy['current']), 'requests': {}, 'decisions': [], 'consumed': {}, 'receipts': {}, 'meters': {cid: {'active_seconds': 0, 'open_since': None} for cid in policy['actors']}, 'successions': []}

def _active_seconds(state, cid, at):
    meter = state['meters'][cid]
    elapsed = max(0.0, (parse_time(at) - parse_time(meter['open_since'])).total_seconds()) if meter['open_since'] else 0
    return meter['active_seconds'] + elapsed

active_seconds = boundary(_active_seconds, checks={'state': _mapping, 'cid': _string, 'at': _string})

def _checkpoint(policy, state):
    body = {'schema': 'aegis.lifecycle-checkpoint/v1', 'policy_sha256': digest(policy), 'policy': policy, 'state': state, 'execution_enabled': False, 'native_enforcement': 'unqualified'}
    return {**body, 'sha256': digest(body)}

checkpoint = boundary(_checkpoint, checks={'policy': _mapping, 'state': _mapping})

def _initial_process(value):
    fields(value, {'boot_id', 'pid_namespace', 'pid', 'start_ticks'})
    boot = value['boot_id']
    require(isinstance(boot, str) and str(uuid.UUID(boot)) == boot)
    integer(value['pid'], 'bootstrap process id', maximum=2147483647)
    for name in ('pid_namespace', 'start_ticks'):
        integer(value[name], 'bootstrap ' + name, maximum=UINT64)

def _initial_channel(value):
    fields(value, {'schema', 'runtime_instance', 'appserver_instance', 'control_peer_instance', 'read_pipe_inode', 'write_pipe_inode', 'epoch', 'deployment_sha256', 'runtime_executable_sha256', 'host_source_closure_sha256', 'role_ceiling_sha256'})
    require(value['schema'] == 'aegis.host-channel-witness/v1')
    for name in ('runtime_instance', 'appserver_instance', 'control_peer_instance'):
        _initial_process(value[name])
    for name in ('read_pipe_inode', 'write_pipe_inode', 'epoch'):
        integer(value[name], 'bootstrap ' + name, maximum=UINT64)
    require(value['read_pipe_inode'] != value['write_pipe_inode'])
    for name in ('deployment_sha256', 'runtime_executable_sha256', 'host_source_closure_sha256', 'role_ceiling_sha256'):
        matching(value[name], SHA256, 'bootstrap ' + name)

def _initial_key(policy, cid):
    return 'initial-' + digest({'schema': 'aegis.initial-creation-key/v1', 'policy_sha256': digest(policy), 'actor_cid': cid})[:40]

initial_key = boundary(_initial_key, checks={'policy': _mapping, 'cid': _string})

def _reduce_initial(policy, state, envelope):
    """Validate inert bootstrap journal evidence, without authenticating a host."""
    fields(envelope, {'schema', 'id', 'event'})
    require(envelope['schema'] == INITIAL_ENVELOPE)
    matching(envelope['id'], SLUG, 'event id')
    event = envelope['event']
    require(isinstance(event, dict))
    if event.get('type') == 'initial_reservations':
        fields(event, {'type', 'approved_plan', 'channel_witness', 'reservations'})
        require(envelope['id'] == 'initial-genesis' and state['sequence'] == 0 and ('initial_bootstrap' not in state))
        evidence([event['approved_plan']])
        require(policy['authority'] == [event['approved_plan']])
        _initial_channel(event['channel_witness'])
        channel_sha256 = digest(event['channel_witness'])
        rows = event['reservations']
        require(isinstance(rows, list) and 5 <= len(rows) <= 128)
        cids, sequences = ([], set())
        for row in rows:
            fields(row, {'schema', 'channel_instance_sha256', 'approved_plan_sha256', 'actor_cid', 'role', 'generation', 'profile_sha256', 'cap_seconds', 'reservation_sequence', 'expires_monotonic_ns'})
            require(row['schema'] == 'aegis.host-reservation-witness/v1')
            cid = row['actor_cid']
            matching(cid, SLUG, 'bootstrap actor CID')
            require(cid in policy['actors'])
            actor = policy['actors'][cid]
            integer(row['generation'], 'bootstrap generation', maximum=UINT64)
            integer(row['cap_seconds'], 'bootstrap cap', maximum=86400 if actor['role'] == 'root' else 3600)
            integer(row['reservation_sequence'], 'bootstrap reservation sequence', maximum=UINT64)
            integer(row['expires_monotonic_ns'], 'bootstrap reservation expiry', maximum=UINT64)
            require(row['role'] == actor['role'] and row['generation'] == actor['generation'] and (row['profile_sha256'] == digest(actor['profile'])) and (row['cap_seconds'] == actor['cap_seconds']) and (row['approved_plan_sha256'] == event['approved_plan']['sha256']) and (row['channel_instance_sha256'] == channel_sha256))
            require(row['reservation_sequence'] not in sequences)
            sequences.add(row['reservation_sequence'])
            cids.append(cid)
        require(cids == sorted(policy['actors']))
        state['initial_bootstrap'] = {'genesis': {'envelope': copy.deepcopy(envelope)}, 'reservations': copy.deepcopy(rows), 'creations': {}}
        return
    require(event.get('type') == 'initial_creation')
    fields(event, {'type', 'genesis_event_sha256', 'approved_plan_sha256', 'reservation_set_sha256', 'actor_cid', 'role', 'generation', 'profile_sha256', 'cap_seconds', 'channel_instance_sha256', 'reservation_witness_sha256'})
    require('initial_bootstrap' in state)
    bootstrap = state['initial_bootstrap']
    cid = event['actor_cid']
    matching(cid, SLUG, 'bootstrap actor CID')
    require(cid in policy['current'].values())
    actor = policy['actors'][cid]
    require(state['current'].get(actor['role']) == cid)
    require(cid not in bootstrap['creations'])
    integer(event['generation'], 'bootstrap generation', maximum=UINT64)
    integer(event['cap_seconds'], 'bootstrap cap', maximum=86400 if actor['role'] == 'root' else 3600)
    row = next((row for row in bootstrap['reservations'] if row['actor_cid'] == cid), None)
    require(row is not None)
    expected = {name: row[name] for name in ('actor_cid', 'role', 'generation', 'profile_sha256', 'cap_seconds', 'channel_instance_sha256', 'approved_plan_sha256')}
    expected.update(type='initial_creation', genesis_event_sha256=digest(bootstrap['genesis']['envelope']), reservation_set_sha256=digest(bootstrap['reservations']), reservation_witness_sha256=digest(row))
    require(event == expected and envelope['id'] == _initial_key(policy, cid))
    bootstrap['creations'][cid] = {'actor_cid': cid, 'envelope': copy.deepcopy(envelope)}

def _actor_for(policy, state, envelope):
    fields(envelope, {'id', 'actor', 'generation', 'custody', 'event'})
    matching(envelope['id'], SLUG, 'event id')
    cid = envelope['actor']
    require(isinstance(cid, str) and cid in policy['actors'])
    actor = policy['actors'][cid]
    require(type(envelope['generation']) is int and envelope['generation'] == actor['generation'])
    fields(envelope['custody'], {'cid', 'generation'})
    root = state['current']['root']
    require(envelope['custody'] == {'cid': root, 'generation': policy['actors'][root]['generation']})
    event = envelope['event']
    require(isinstance(event, dict) and isinstance(event.get('type'), str))
    kind = event['type']
    require(kind in PERMISSIONS)
    require(actor['role'] in PERMISSIONS[kind])
    if kind != 'succeed':
        require(state['current'].get(actor['role']) == cid)
    return (cid, actor, event)

actor_for = boundary(_actor_for, checks={'policy': _mapping, 'state': _mapping, 'envelope': _mapping})

def _add_request(state, raw, publisher):
    value = _validate_request(raw)
    existing = state['requests'].get(value['id'])
    if existing:
        require(existing['raw'] == raw)
        return existing
    require(len(state['requests']) < MAX_REQUESTS)
    row = {'request': value, 'raw': raw, 'publisher': publisher, 'read': None, 'routed': None, 'admission': None, 'wait': None, 'intent': None, 'start': None, 'terminal': None, 'results': [], 'review': None, 'delivery': None, 'resolution': None, 'dispositions': []}
    state['requests'][value['id']] = row
    return row

add_request = boundary(_add_request, checks={'state': _mapping, 'raw': _mapping, 'publisher': _string})

def _target(state, event):
    require(event['request_id'] in state['requests'])
    row = state['requests'][event['request_id']]
    require(event['request_sha256'] == row['raw']['sha256'])
    return row

target = boundary(_target, checks={'state': _mapping, 'event': _mapping})

def _approved_authority(state, row, at):
    value = row['request']
    parent = state['requests'].get(value['authority'])
    decisions = [d for d in state['decisions'] if d['request_id'] == value['authority']]
    require(parent is not None and decisions and (decisions[-1]['decision'] == 'approve'), 'no approved bounded authority')
    require(parent['request']['operation'] != 'delegate-merge', 'a delegation authorizes the Decider, not work')
    scope = parent['request']['continuation']
    require(parse_time(at) < parse_time(scope['expires_at']), 'bounded authority expired')
    if parent is not row:
        expected = {'id': value['id'], 'sha256': row['raw']['sha256'], 'phase': value['phase'], 'operation': value['operation']}
        require(expected in scope['members'], 'request is outside approved continuation')
    require(state['consumed'].get(value['authority'], 0) < scope['max_starts'], 'bounded authority exhausted')
    for prerequisite in value['prerequisites']:
        prior = state['requests'].get(prerequisite)
        require(prior is not None and prior['resolution'] is not None and (prior['resolution']['kind'] == 'complete'), 'prerequisite lacks accepted delivery')
    return value['authority']

approved_authority = boundary(_approved_authority, checks={'state': _mapping, 'row': _mapping, 'at': _string})

@boundary
def covered(scope, path):
    require(type(scope) in (list, tuple))
    """Component-wise, so /a/b covers /a/b/c and /a/b/ but never /a/b-two."""
    parts = _path_value(path, posix=True).parts
    grants = (_path_value(granted, posix=True).parts for granted in scope)
    return any(parts[:len(granted)] == granted for granted in grants)

def _small_change_participant(policy, state, binding, expected, name, role):
    """Check one configured identity/generation, never host authentication."""
    fields(binding, {'cid', 'generation'})
    require(binding['cid'] == expected)
    require(type(binding['generation']) is int and binding['generation'] > 0, 'invalid small-change participant generation')
    actor = policy['actors'].get(binding['cid'])
    require(actor is not None and actor['role'] == role, 'small-change participant role mismatch')
    require(binding['generation'] == actor['generation'], 'small-change participant generation mismatch')
    require(state['current'][role] == binding['cid'], 'small-change participant is no longer current')

small_change_participant = boundary(_small_change_participant, checks={'policy': _mapping, 'state': _mapping, 'binding': _mapping, 'expected': _string, 'name': _string, 'role': _string})

def _small_change_participants(policy, state, row, plan, participants):
    """Check configured identity/generation only. This is not host authentication."""
    fields(participants, {'writer', 'reviewer'})
    expected = {'writer': plan['writing_lanes'][0]['writer'], 'reviewer': plan['reviewer']}
    for name, role in (('writer', 'operator'), ('reviewer', 'reviewer')):
        _small_change_participant(policy, state, participants[name], expected[name], name, role)
    require(participants['reviewer']['cid'] not in {row['publisher'], participants['writer']['cid']}, 'small-change reviewer must be independent')

small_change_participants = boundary(_small_change_participants, checks={'policy': _mapping, 'state': _mapping, 'row': _mapping, 'plan': _mapping, 'participants': _mapping})

def _small_change_approval(state, row):
    """Keep plan approval/admission separate from permission to start work."""
    value, change = (row['request'], row['small_change'])
    canonical = [d for d in state['decisions'] if d['request_id'] == value['id']]
    require(not canonical or canonical[-1]['decision'] != 'deny', 'canonical request is denied')
    decisions = change['decisions']
    require(decisions and decisions[-1]['decision'] == 'approve', 'small-change plan lacks approval')
    require(change['admission'] is not None, 'small-change plan lacks admission')
    return change['registration']

small_change_approval = boundary(_small_change_approval, checks={'state': _mapping, 'row': _mapping})

def _small_change_execution(policy, state, row, at):
    """Validate the admitted plan's scope and bindings before new work."""
    value = row['request']
    registration = _small_change_approval(state, row)
    require(parse_time(at) < parse_time(value['continuation']['expires_at']), 'bounded authority expired')
    plan = raw_value(registration['proposal'])['plan']
    _mapping(plan)
    _small_change_participants(policy, state, row, plan, registration['participants'])
    if row['intent'] is None:
        require(state['consumed'].get(value['authority'], 0) < value['continuation']['max_starts'], 'bounded authority exhausted')
    for prerequisite in value['prerequisites']:
        prior = state['requests'].get(prerequisite)
        require(prior is not None and prior['resolution'] is not None and (prior['resolution']['kind'] == 'complete'), 'prerequisite lacks accepted delivery')
    return plan

small_change_execution = boundary(_small_change_execution, checks={'policy': _mapping, 'state': _mapping, 'row': _mapping, 'at': _string})

def _small_change_started(row):
    """Terminal evidence and review require the same recorded start."""
    intent, start = (row['intent'], row['start'])
    require(intent is not None and start is not None and (start['intent_id'] == intent['id']))
    return start

small_change_started = boundary(_small_change_started, checks={'row': _mapping})

def _small_change_review(policy, state, row, cid):
    """Review finished evidence without renewing expiry or the writer binding."""
    registration = _small_change_approval(state, row)
    _small_change_started(row)
    plan = raw_value(registration['proposal'])['plan']
    require(type(plan) is dict)
    _small_change_participant(policy, state, registration['participants']['reviewer'], plan['reviewer'], 'reviewer', 'reviewer')
    require(cid == plan['reviewer'])

small_change_review = boundary(_small_change_review, checks={'policy': _mapping, 'state': _mapping, 'row': _mapping, 'cid': _string})

def _small_change_event(policy, state, row, event, mark, at):
    """Durable pre-dispatch evidence, deliberately separate from v1 work authority."""
    kind = event['type']
    value = row['request']
    require(row['resolution'] is None and row['routed'] is None and (row['admission'] is None) and (row['intent'] is None))
    if kind == 'small_change_plan':
        require('small_change' not in row)
        proposal = raw_value(event['proposal'])
        inspection = inspect_request(proposal)
        require(inspection['classification'] == 'declared_eligible')
        require(proposal['request'] == row['raw'])
        require(value['authority'] == value['id'] and (not value['continuation']['members']) and (value['continuation']['max_starts'] == 1) and (value['operation'] != 'delegate-merge'))
        _mapping(proposal['plan'])
        _small_change_participants(policy, state, row, proposal['plan'], event['participants'])
        row['small_change'] = {'registration': {**mark, 'proposal': event['proposal'], 'participants': event['participants']}, 'decisions': [], 'admission': None}
        return
    change = row.get('small_change')
    require(change is not None)
    registration = change['registration']
    require(event['plan_sha256'] == registration['proposal']['sha256'])
    if kind == 'small_change_admit' or event.get('decision') == 'approve':
        canonical = [d for d in state['decisions'] if d['request_id'] == value['id']]
        require(not canonical or canonical[-1]['decision'] != 'deny', 'canonical request is denied')
    if kind == 'small_change_decision':
        require(event['decision'] in {'approve', 'deny'})
        text(event['reason'], 'decision reason', 1024)
        decisions = change['decisions']
        require(not decisions or (decisions[-1]['decision'] == 'approve' and event['decision'] == 'deny'))
        if event['decision'] == 'approve':
            require(parse_time(at) < parse_time(value['continuation']['expires_at']), 'bounded authority expired')
            proposal = raw_value(registration['proposal'])
            _mapping(proposal['plan'])
            _small_change_participants(policy, state, row, proposal['plan'], registration['participants'])
        decisions.append({**mark, **event})
        return
    decisions = change['decisions']
    require(decisions and decisions[-1]['decision'] == 'approve', 'small-change plan lacks approval')
    require(event['decision_sha256'] == digest(decisions[-1]))
    require(event['source'] == value['source'])
    require(event['participants'] == registration['participants'])
    proposal = raw_value(registration['proposal'])
    _mapping(proposal['plan'])
    _small_change_participants(policy, state, row, proposal['plan'], registration['participants'])
    require(mark['actor'] == registration['participants']['writer']['cid'])
    require(parse_time(at) < parse_time(value['continuation']['expires_at']), 'bounded authority expired')
    for prerequisite in value['prerequisites']:
        prior = state['requests'].get(prerequisite)
        require(prior is not None and prior['resolution'] is not None and (prior['resolution']['kind'] == 'complete'), 'prerequisite lacks accepted delivery')
    checks = event['checks']
    require(isinstance(checks, list) and len(checks) <= 256)
    names = []
    for check in checks:
        fields(check, {'check', 'recipe', 'recipes_sha256', 'evidence'})
        matching(check['check'], SLUG, 'small-change check')
        matching(check['recipe'], SLUG, 'small-change recipe')
        matching(check['recipes_sha256'], SHA256, 'small-change recipes sha256')
        evidence(check['evidence'])
        names.append(check['check'])
    require(len(set(names)) == len(names) and set(names) == set(proposal['plan']['checks']))
    fields(event['gates'], GATES | {'reviewer'})
    for refs in event['gates'].values():
        evidence(refs)
    require(change['admission'] is None)
    change['admission'] = {**mark, **event}

small_change_event = boundary(_small_change_event, checks={'policy': _mapping, 'state': _mapping, 'row': _mapping, 'event': _mapping, 'mark': _mapping, 'at': _string})

def _delegated_decision(state, row, event, mark):
    """Record the Decider's approve or escalate. It is non-admitting: it never touches decisions,
    consumed or approved_authority, so nothing it records makes a request admissible."""
    value, cid, at = (row['request'], mark['actor'], mark['at'])
    require(event['delegation_id'] in state['requests'])
    parent = state['requests'][event['delegation_id']]
    require(event['delegation_sha256'] == parent['raw']['sha256'])
    require(event['decision'] in {'approve', 'escalate'})
    matching(event['commit'], GIT_ID, 'reviewed commit')
    evidence(event['review'])
    text(event['reason'], 'delegated decision reason', 1024)
    require(parent is not row)
    grant = parent['request']
    require(grant['operation'] == 'delegate-merge' and grant['authority'] == grant['id'] and (not grant['continuation']['members']))
    require(value['authority'] == value['id'])
    recorded = state.get('delegated_decisions', [])
    require(all((d['request_id'] != value['id'] for d in recorded)))
    require(all((d['request_id'] != value['id'] for d in state['decisions'])))
    if event['decision'] == 'approve':
        require(value['operation'] == 'merge')
        decisions = [d for d in state['decisions'] if d['request_id'] == grant['id']]
        require(decisions and decisions[-1]['decision'] == 'approve')
        require(parse_time(at) < parse_time(grant['continuation']['expires_at']))
        require(grant['team'] == value['team'])
        require(all((_path_value(granted, posix=True).parts != ('/',) for granted in grant['paths'])))
        require(all((covered(grant['paths'], path) for path in value['paths'])))
        used = sum((1 for d in recorded if d['delegation_id'] == grant['id'] and d['decision'] == 'approve'))
        require(used < grant['continuation']['max_starts'])
        require(event['commit'] == value['source']['commit'])
        require(cid != row['publisher'])
    state['delegated_decisions'] = recorded + [{**mark, **event}]

delegated_decision = boundary(_delegated_decision, checks={'state': _mapping, 'row': _mapping, 'event': _mapping, 'mark': _mapping})

def _unknown_effect(row):
    return row['intent'] is not None and (row['terminal'] is None or row['terminal']['value']['outcome'] == 'unknown')

unknown_effect = boundary(_unknown_effect, checks={'row': _mapping})

def _resolve_row(state, row, resolution, cid):
    require(isinstance(resolution, dict))
    kind = resolution.get('kind')
    require(kind in {'complete', 'next', 'blocked'})
    optional = {'request'} if kind == 'next' else {'owner', 'next_decision', 'condition'} if kind == 'blocked' else set()
    fields(resolution, {'kind', 'evidence'} | optional)
    evidence(resolution['evidence'])
    if kind != 'blocked':
        require(not _unknown_effect(row))
    if kind == 'complete':
        require(row['terminal'] is not None and row['terminal']['value']['outcome'] == 'passed' and (row['review'] is not None) and (row['review']['verdict'] == 'accept') and (row['review']['result_sha256'] == row['terminal']['sha256']) and (row['delivery'] is not None))
    elif kind == 'next':
        following = _validate_request(resolution['request'])
        require(following['id'] != row['request']['id'])
        require(following['id'] not in state['requests'])
        _add_request(state, resolution['request'], cid)
        resolution = {'kind': kind, 'request_id': following['id'], 'request_sha256': resolution['request']['sha256'], 'owner': following['owner'], 'next_decision': following['next_decision'], 'evidence': resolution['evidence']}
    else:
        for key in ('owner', 'next_decision', 'condition'):
            text(resolution[key], key)
    row['resolution'] = resolution

resolve_row = boundary(_resolve_row, checks={'state': _mapping, 'row': _mapping, 'resolution': _mapping, 'cid': _string})

def _reduce_event(policy, state, envelope, at):
    if isinstance(envelope, dict) and envelope.get('schema') == INITIAL_ENVELOPE:
        return _reduce_initial(policy, state, envelope)
    cid, actor, event = _actor_for(policy, state, envelope)
    kind = event['type']
    if kind not in {'meter', 'succeed', 'terminal', 'observe'}:
        require(_active_seconds(state, cid, at) < actor['cap_seconds'], 'actor cumulative active cap reached')
    mark = {'actor': cid, 'generation': actor['generation'], 'at': at}
    if kind == 'publish':
        fields(event, {'type', 'request'})
        _add_request(state, event['request'], cid)
        return
    if kind == 'meter':
        fields(event, {'type', 'subject', 'active_seconds', 'open_since'})
        subject = event['subject']
        require(subject in policy['actors'])
        seconds = event['active_seconds']
        require(type(seconds) in (int, float) and math.isfinite(seconds) and (seconds >= _active_seconds(state, subject, at)))
        if event['open_since'] is not None:
            require(parse_time(event['open_since']) <= parse_time(at))
        state['meters'][subject] = {'active_seconds': seconds, 'open_since': event['open_since']}
        return
    if kind == 'succeed':
        fields(event, {'type', 'predecessor', 'checkpoint_sha256'})
        old = event['predecessor']
        require(policy['successors'].get(old) == cid and state['current'].get(actor['role']) == old)
        require(event['checkpoint_sha256'] == _checkpoint(policy, state)['sha256'])
        state['current'][actor['role']] = cid
        state['successions'].append({**mark, **event})
        return
    common = {'type', 'request_id', 'request_sha256'}
    extra = {'decision': {'decision', 'reason'}, 'read': set(), 'route': {'to'}, 'admit': {'source', 'gates'}, 'wait': {'reason'}, 'intent': {'intent_id'}, 'start': {'intent_id'}, 'terminal': {'result'}, 'review': {'result_sha256', 'source', 'verdict', 'evidence'}, 'delivery': {'evidence'}, 'disposition': {'status', 'resolution'}, 'resolve': {'blocker_sha256', 'resolution'}, 'associate': {'association'}, 'observe': {'intent_id', 'association_sha256', 'observation'}, 'cancel_attempt': {'intent_id', 'association_sha256', 'reason'}, 'delegated_decision': {'delegation_id', 'delegation_sha256', 'commit', 'review', 'decision', 'reason'}, 'small_change_plan': {'proposal', 'participants'}, 'small_change_decision': {'plan_sha256', 'decision', 'reason'}, 'small_change_admit': {'plan_sha256', 'decision_sha256', 'source', 'participants', 'checks', 'gates'}}
    fields(event, common | extra[kind])
    row = _target(state, event)
    value = row['request']
    if row['resolution'] and row['resolution']['kind'] in {'complete', 'next'}:
        require(kind in {'read', 'route', 'decision'})
    _request_effect(policy, state, row, event, mark, at, cid, actor, kind, value)

def _request_effect(policy, state, row, event, mark, at, cid, actor, kind, value):
    if kind in {'small_change_plan', 'small_change_decision', 'small_change_admit'}:
        _small_change_event(policy, state, row, event, mark, at)
    elif kind == 'associate':
        binding = _validate_association(policy, state, row, event['association'], cid, at)
        row['association'] = {**mark, 'value': binding, 'sha256': digest(binding)}
        row['observations'], row['cancellation'] = ([], None)
    elif kind in {'observe', 'cancel_attempt'}:
        require(row.get('association') is not None)
        require(event['intent_id'] == row['intent']['id'] and event['association_sha256'] == row['association']['sha256'])
        require(row['terminal'] is None or row['terminal']['value']['outcome'] == 'unknown')
        if kind == 'observe':
            value = _validate_observation(row, event['observation'])
            row['observations'].append({**mark, 'value': value})
        else:
            require(row.get('cancellation') is None)
            require(_provider_handle(row) is not None)
            text(event['reason'], 'cancellation reason', 1024)
            row['cancellation'] = {**mark, 'reason': event['reason']}
    elif kind == 'decision':
        require(value['authority'] == value['id'])
        require(event['decision'] in {'approve', 'deny'})
        text(event['reason'], 'decision reason', 1024)
        prior = [d for d in state['decisions'] if d['request_id'] == value['id']]
        require(not prior or (prior[-1]['decision'] == 'approve' and event['decision'] == 'deny'))
        state['decisions'].append({**mark, **event})
    elif kind == 'delegated_decision':
        _delegated_decision(state, row, event, mark)
    elif kind == 'read':
        row['read'] = mark
    elif kind == 'route':
        if 'small_change' in row:
            plan = _small_change_execution(policy, state, row, at)
            require(event['to'] == value['team'] + '/lane/' + plan['writing_lanes'][0]['lane'])
        text(event['to'], 'route recipient')
        row['routed'] = {**mark, 'to': event['to']}
    elif kind in {'admit', 'intent'}:
        if 'small_change' in row:
            require(kind == 'intent')
        require(row['intent'] is None)
        require(row['resolution'] is None)
        if 'small_change' in row:
            plan = _small_change_execution(policy, state, row, at)
            require(cid == plan['writing_lanes'][0]['writer'])
            authority = value['authority']
        else:
            authority = _approved_authority(state, row, at)
        if kind == 'admit':
            require(event['source'] == value['source'])
            fields(event['gates'], GATES)
            for refs in event['gates'].values():
                evidence(refs)
            row['admission'] = {**mark, 'gates': event['gates'], 'source': event['source']}
        else:
            if 'small_change' not in row:
                require(row['admission'] is not None and row['admission']['actor'] == cid)
            matching(event['intent_id'], SLUG, 'intent id')
            require(all((r['intent'] is None or r['intent']['id'] != event['intent_id'] for r in state['requests'].values())))
            row['intent'] = {**mark, 'id': event['intent_id'], 'request_sha256': row['raw']['sha256'], 'phase': value['phase'], 'operation': value['operation'], 'authority': authority}
            state['consumed'][authority] = state['consumed'].get(authority, 0) + 1
        if state['meters'][cid]['open_since'] is None:
            state['meters'][cid]['open_since'] = at
    else:
        _request_completion(policy, state, row, event, mark, at, cid, actor, kind, value)

def _request_completion(policy, state, row, event, mark, at, cid, actor, kind, value):
    if kind == 'wait':
        text(event['reason'], 'wait reason', 1024)
        row['wait'] = {**mark, 'reason': event['reason']}
        if state['meters'][cid]['open_since'] is None:
            state['meters'][cid]['open_since'] = at
    elif kind == 'start':
        if 'small_change' in row:
            plan = _small_change_execution(policy, state, row, at)
            require(cid == plan['writing_lanes'][0]['writer'])
        require(row['intent'] is not None and row['intent']['id'] == event['intent_id'])
        require(row['intent']['actor'] == cid and row['start'] is None and (row['terminal'] is None))
        if 'small_change' not in row:
            approved = [d for d in state['decisions'] if d['request_id'] == value['authority']]
            require(approved and approved[-1]['decision'] == 'approve')
            require(parse_time(at) < parse_time(state['requests'][value['authority']]['request']['continuation']['expires_at']), 'bounded authority expired')
        row['start'] = {**mark, 'intent_id': event['intent_id']}
    elif kind == 'terminal':
        if 'small_change' in row:
            start = _small_change_started(row)
            require((cid, actor['generation']) == (start['actor'], start['generation']))
        result = raw_value(event['result'])
        fields(result, {'request_sha256', 'intent_id', 'outcome', 'exit_code', 'source', 'evidence'})
        require(row['intent'] is not None and result['intent_id'] == row['intent']['id'] and (result['request_sha256'] == row['raw']['sha256']))
        require(result['source'] == value['source'])
        require(type(result['outcome']) is str and result['outcome'] in {'passed', 'failed', 'unknown'})
        exit_code, outcome = (result['exit_code'], result['outcome'])
        valid_exit = type(exit_code) is int and exit_code == 0 if outcome == 'passed' else type(exit_code) is int and exit_code != 0 if outcome == 'failed' else exit_code is None or type(exit_code) is int
        require(valid_exit)
        evidence(result['evidence'])
        require(row['terminal'] is None or row['terminal']['value']['outcome'] == 'unknown')
        row['terminal'] = {**mark, 'sha256': event['result']['sha256'], 'raw': event['result'], 'value': result}
        row['results'].append(row['terminal'])
        row['review'], row['delivery'] = (None, None)
    elif kind == 'review':
        if 'small_change' in row:
            _small_change_review(policy, state, row, cid)
        require(row['terminal'] is not None and event['result_sha256'] == row['terminal']['sha256'])
        require(event['source'] == value['source'])
        require(cid != row['publisher'] and cid != row['intent']['actor'])
        require(event['verdict'] in {'accept', 'reject'})
        evidence(event['evidence'])
        row['review'] = {**mark, **event}
        row['delivery'] = None
    elif kind == 'delivery':
        require(row['review'] is not None and row['review']['verdict'] == 'accept')
        evidence(event['evidence'])
        row['delivery'] = {**mark, 'evidence': event['evidence']}
    else:
        if kind == 'disposition':
            require(event['status'] in {'FINAL', 'HOLD'})
            require(row['resolution'] is None)
        else:
            require(row['resolution'] is not None and row['resolution']['kind'] == 'blocked')
            require(event['blocker_sha256'] == digest(row['resolution']))
            require(isinstance(event['resolution'], dict))
            require(event['resolution'].get('kind') != 'blocked')
        _resolve_row(state, row, event['resolution'], cid)
        row['dispositions'].append({**mark, **event})

@boundary(checks={'policy': _mapping, 'state': _mapping, 'envelope': _mapping, 'at': _string})
def reduce_event(policy, state, envelope, at):
    bounded_tree(envelope, limit=MAX_BYTES)
    candidate = copy.deepcopy(state)
    result = _reduce_event(policy, candidate, envelope, at)
    bounded_tree(candidate, limit=67108864, ascii_strings=True)
    state.clear()
    state.update(candidate)
    return result
