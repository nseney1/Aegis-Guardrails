"""Read recorded native evidence through the descriptor-backed rollout port.

Returned fields are unrendered evidence for comparison. They neither
authenticate the session nor grant the authority to execute a command.
"""
from contextlib import closing

from aegis_core.team_native_codemode import (
    CODE_MODE, CODE_MODE_SAFE_OPTIONS, CodeModeMatches, code_mode_calls, code_mode_close, evidence_text_bytes,
)
from aegis_core.team_native_rollout import (
    AGENT_NAMESPACE, AGENT_TOOL_NAMES, EXEC_SCHEMA, MAX_RECORD_BYTES, MAX_ROLLOUT_BYTES, MULTI_AGENT_SCHEMA, NATIVE_GAP,
    PATCH_CALLS, NativeRolloutRefusal, command_execution, event_type, patch_apply, response_patch,
    rollout_records, turn_start, witness_of,
)

__all__ = ["CODE_MODE", "CODE_MODE_SAFE_OPTIONS", "MAX_OBSERVATION_BYTES", "exec_events", "multi_agent_state"]

MAX_OBSERVATION_BYTES = 4 * MAX_ROLLOUT_BYTES
# Pending options occupy index entries as well as observation text.
_INDEX_OPTION_COST = 128
_STREAM_ITEMS = ("item.started", "item.updated", "item.completed")
_NON_AGENT = frozenset(("functions.exec", "functions.wait", "functions.request_user_input",
                        "functions.request_user_input_async", "clock.sleep"))
_DERIVED_FIELDS = ("turn_id", "call_id", "command", "command_text", "paths", "options",
                   "stdout", "stderr", "aggregated_output", "timestamp")


def _require(condition):
    if not condition:
        raise NativeRolloutRefusal("invalid_record")


def _request(cid, tolerant, *, optional_cid=False):
    _require((optional_cid and cid is None) or (type(cid) is str and bool(cid)))
    if cid is not None and len(cid) > MAX_RECORD_BYTES:
        raise NativeRolloutRefusal("too_large")
    _require(type(tolerant) is bool)


def _kind(mapping):
    kind = mapping.get("type")
    _require(kind is None or type(kind) is str)
    return kind


def _identity(payload, cid):
    _require(type(payload) is dict and (cid is None or payload.get("id") == cid))
    return payload


def _recorded_turn(payload, record):
    inside, outside = payload.get("turn_id"), record.get("turn_id")
    _require(inside is None or type(inside) is str)
    _require(outside is None or type(outside) is str)
    _require(inside is None or outside is None or inside == outside)
    return outside if inside is None else inside


class _ByteBudget:
    def __init__(self, limit):
        self.remaining = limit

    def reserve(self, size):
        if size > self.remaining:
            raise NativeRolloutRefusal("too_large")
        self.remaining -= size
        return True

    def release(self, size):
        # Caller has already dropped the retained object this charge described.
        self.remaining += size


def _value_size(value):
    """Measure derived data without serializing or copying it."""
    if type(value) is str:
        return 8 + evidence_text_bytes(value)
    if type(value) is dict:
        return 8 + sum(evidence_text_bytes(name) + _value_size(child) for name, child in value.items())
    if type(value) in (list, tuple):
        return 8 + sum(map(_value_size, value))
    return 8


class _ExecEvidence:
    def __init__(self, scope):
        self.scope = scope
        self.turn = None
        self.executions, self.patches, self.unparsed = [], [], []
        self.pending, self.scripts = {}, {}
        self.matches = CodeModeMatches()
        # Pending scripts, pending patches and emitted evidence share one ceiling.
        self.budget = _ByteBudget(MAX_OBSERVATION_BYTES)

    def retain_derived(self, entry, destination):
        # A rollout has one pathname. The remaining envelope fields are fixed
        # schema, digest, or line metadata. Charge data that can multiply when
        # one observation source yields many results.
        values = (entry.get(name) for name in _DERIVED_FIELDS)
        if self.budget.reserve(8 + sum(_value_size(value) for value in values if value is not None)):
            destination.append(entry)

    def open_call(self, payload, kind, call_id, recorded_turn, path, number, raw, record):
        _require(call_id not in self.pending)
        name = payload.get("name")
        size = 0
        if kind == "custom_tool_call" and name == "exec":
            self.open_script(payload, call_id, recorded_turn, path, number, raw, record)
            payload, witness = None, None
        elif kind in PATCH_CALLS and name == "apply_patch":
            witness = witness_of(path, number, raw, record)
            size = 8 + _value_size(payload) + _value_size(witness)
            self.budget.reserve(size)
        else:
            payload, witness = None, None
        self.pending[call_id] = (PATCH_CALLS.get(kind), recorded_turn, self.turn, payload, witness, size)

    def open_script(self, payload, call_id, recorded_turn, path, number, raw, record):
        # Legacy associates calls with the active task. The wire turn can
        # constrain correlation with output without overriding attribution.
        turn = self.turn
        calls, paired, skipped, unknown = code_mode_calls(payload.get("input"))
        for diagnostic in skipped:
            entry = {**diagnostic, "turn_id": turn, "call_id": call_id, "line": number}
            self.retain_derived(entry, self.unparsed)
        if calls or unknown:
            script = {"calls": calls, "paired": paired, "turn": turn, "call_id": call_id,
                      "covered": set(), "line": number, "witness": witness_of(path, number, raw, record)}
            remaining = self.budget.remaining
            for call in calls:
                self.budget.reserve(_value_size(call) + _INDEX_OPTION_COST * len(call.get("options", ())))
            script["size"] = remaining - self.budget.remaining
            self.matches.admit(script, unknown, recorded_turn)
            self.scripts[call_id] = script

    def close_script(self, script, payload, witness):
        code_mode_close(script, payload, witness, self.emit)
        self.matches.release(script)
        script["calls"] = ()
        self.budget.release(script["size"])

    def response(self, payload, path, number, raw, record):
        kind, call_id = _kind(payload), payload.get("call_id")
        if kind is None or type(call_id) is not str:
            return
        if kind.endswith("_call"):
            explicit_turn = _recorded_turn(payload, record)
            turn = self.turn if explicit_turn is None else explicit_turn
            self.open_call(payload, kind, call_id, turn, path, number, raw, record)
            return
        opened = self.pending.get(call_id)
        if opened is None or kind != opened[0]:
            return
        explicit_turn = _recorded_turn(payload, record)
        if explicit_turn is not None and explicit_turn != opened[1]:
            return
        script = self.scripts.get(call_id)
        if script is not None:
            del self.pending[call_id]
            del self.scripts[call_id]
            self.close_script(script, payload, witness_of(path, number, raw, record))
            return
        _opened_kind, _recorded, turn, found, witness, size = opened
        if witness is not None:
            # Charge the emission while the payload is still in self.pending.
            self._emit_pending_patch(found, payload, turn, {
                **witness_of(path, number, raw, record), "call_line": witness["line"]})
        del self.pending[call_id]
        del found, witness, opened
        self.budget.release(size)

    def record(self, kind, payload, path, number, raw, record):
        if kind == "response_item" and isinstance(payload, dict):
            self.response(payload, path, number, raw, record)
            return
        if kind == "event_msg" and isinstance(payload, dict):
            _kind(payload)
        event = event_type(record)
        if event == "task_started":
            self.turn = turn_start(payload)
        elif event in ("exec_command_end", "patch_apply_end"):
            self.typed(payload, payload.get("turn_id", self.turn), event,
                       witness_of(path, number, raw, record), event == "exec_command_end")
        elif event == "item_completed" and isinstance(payload.get("item"), dict):
            entry = payload["item"]
            item_kind = _kind(entry)
            if item_kind in ("CommandExecution", "FileChange"):
                self.typed(entry, payload.get("turn_id", self.turn), event,
                           witness_of(path, number, raw, record), item_kind == "CommandExecution")
        elif kind in _STREAM_ITEMS and isinstance(record.get("item"), dict):
            entry = record["item"]
            item_kind = _kind(entry)
            if item_kind in ("command_execution", "file_change"):
                self.typed(entry, self.turn, kind, witness_of(path, number, raw, record),
                           item_kind == "command_execution")

    def typed(self, payload, turn, source, witness, shell):
        _require(turn is None or type(turn) is str)
        reader = command_execution if shell else patch_apply
        evidence = reader(payload, turn, source, witness)
        self.matches.cover(self.scripts, evidence, shell, active_turn=self.turn, completed=source == "item_completed",
                           reserve=lambda size: self.budget.reserve(size))
        # This projection has one entry per bounded input record. The fixed
        # evidence envelope does not consume the amplification budget.
        (self.executions if shell else self.patches).append(evidence)

    def emit(self, entry, shell):
        self.retain_derived(entry, self.executions if shell else self.patches)

    def _emit_pending_patch(self, found, payload, turn, witness):
        self.retain_derived(response_patch(found, payload, turn, witness), self.patches)

    def finish(self, cid):
        for call_id in list(self.pending):
            _opened_kind, _recorded, turn, found, witness, size = self.pending[call_id]
            if witness is not None:
                self._emit_pending_patch(found, None, turn, witness)
            del self.pending[call_id]
            del found, witness
            self.budget.release(size)
        for call_id in list(self.scripts):
            script = self.scripts.pop(call_id)
            self.close_script(script, None, script["witness"])
        selected = self.scope == "current" and self.turn is not None
        result = {"schema": EXEC_SCHEMA, "cid": cid, "turn_scope": self.scope, "current_turn_id": self.turn,
                  "native_execution_qualified": False, "qualification_blocker": NATIVE_GAP}
        for key, entries in (("command_executions", self.executions), ("patch_applies", self.patches),
                             ("code_mode_unparsed", self.unparsed)):
            result[key] = ([entry for entry in entries if entry["turn_id"] == self.turn]
                           if selected else entries)
        return result


def exec_events(rollout, cid, scope="current", tolerant=False, *, qualification_gate=None):
    """Return the host's recorded shell and patch observations for one or all turns.

    Typed completed items take precedence over code-mode observations.
    The optional downstream gate does not change the status of this reader.
    One read correlates every script. Scope current only filters the result.
    """
    _request(cid, tolerant)
    _require(type(scope) is str and scope in ("current", "all"))
    _require(qualification_gate is None or callable(qualification_gate))
    evidence, metadata = _ExecEvidence(scope), None
    with closing(rollout_records(rollout, tolerant)) as records:
        for path, number, raw, record in records:
            kind, payload = _kind(record), record.get("payload")
            if kind == "session_meta":
                metadata = _identity(payload, cid)
            else:
                evidence.record(kind, payload, path, number, raw, record)
    _require(metadata is not None)
    return evidence.finish(cid)


class _Catalog:
    def __init__(self):
        self.found, self.unknown = set(), set()
        self.seen = set()
        self.budget = _ByteBudget(MAX_ROLLOUT_BYTES)

    def read(self, payload):
        entries = payload.get("tools")
        _require(type(entries) is list)
        for entry in entries:
            _require(type(entry) is dict and type(entry.get("name")) is str)
            name = entry["name"]
            if _kind(entry) == "namespace":
                self.namespace(name, entry.get("tools"))
            elif name not in _NON_AGENT:
                names = self.found if name in AGENT_TOOL_NAMES else self.unknown
                if name not in names:
                    self.budget.reserve(evidence_text_bytes(name))
                    names.add(name)

    def namespace(self, namespace, tools):
        _require(type(tools) is list)
        prefix_bytes = evidence_text_bytes(namespace) + 1
        for tool in tools:
            _require(type(tool) is dict and type(tool.get("name")) is str)
            name = tool["name"]
            key = namespace, name
            if key in self.seen:
                continue
            agent = namespace == AGENT_NAMESPACE or name in AGENT_TOOL_NAMES
            names = self.found if agent else self.unknown
            size = prefix_bytes + evidence_text_bytes(name)
            if not agent and self.contains(_NON_AGENT, namespace, name):
                self.seen.add(key)
                continue
            if size <= self.budget.remaining:
                qualified = namespace + "." + name
                if qualified not in names:
                    self.budget.reserve(size)
                    names.add(qualified)
            elif not self.contains(names, namespace, name):
                raise NativeRolloutRefusal("too_large")
            self.seen.add(key)

    @staticmethod
    def contains(names, namespace, name):
        dot = len(namespace)
        length = dot + 1 + len(name)
        return any(len(value) == length and value[dot] == "." and value.startswith(namespace)
                   and value.endswith(name) for value in names)


def multi_agent_state(rollout, cid=None, tolerant=False):
    """Report catalog evidence and the last version observed in a turn context."""
    _request(cid, tolerant, optional_cid=True)
    metadata, version, turns, count = None, None, 0, 0
    catalog = _Catalog()
    with closing(rollout_records(rollout, tolerant)) as records:
        for _path, _number, _raw, record in records:
            kind, payload = _kind(record), record.get("payload")
            if kind == "session_meta":
                metadata = _identity(payload, cid)
            elif kind == "turn_context" and isinstance(payload, dict):
                turns += 1
                version = payload.get("multi_agent_version")
            elif kind == "response_item" and isinstance(payload, dict) and _kind(payload) == "additional_tools":
                count += 1
                catalog.read(payload)
    _require(cid is None or metadata is not None)
    return {"schema": MULTI_AGENT_SCHEMA, "cid": None if metadata is None else metadata.get("id"), "version": version,
            "agent_tools": sorted(catalog.found), "turns": turns, "tool_records": count,
            **({"unknown_tools": sorted(catalog.unknown)} if catalog.unknown else {})}
