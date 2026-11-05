"""Scoped stdio access to the pilot's file protocol, outside Aegis core.

Launch through hierarchy_mailbox.py serve, which supports isolated Python imports.
The configured sender is provenance, not an authenticated native host identity.
ROOT gets only a decision adapter over the lifecycle journal, never the mailbox tools.
"""
import json
import os
import sys

from hierarchy_mailbox import (MAX_BYTES, Mailbox, _bounded_inbox, digest, endpoint_parts, fields, integer, matching,
                               require, SHA256, SLUG, strict_json, text, writer_lock)


def _response_line(response):
    return (json.dumps(response, sort_keys=True) + "\n").encode("utf-8")


def _tool_result(result):
    return {"content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}]}


def _error_text(exc):
    # Some errors repeat the input, and a response must stay within a page whatever was sent.
    return str(exc)[:1024]


MAX_OVERLAP_PATHS = 64
MAX_OVERLAP_PATH_CHARS = 1024
WORKSPACE_TOOL_SPECS = {
    "workspace_capacity": ("Read shared writer and heavy-job capacity and the queue. Grants nothing.", {}, []),
    "workspace_initiative": ("Read this connection's own initiative record. Changes nothing.", {}, []),
    "workspace_path_overlap": (
        "Check paths against live leases in every registered clone of this repository. A conflict is a normal "
        "answer. A clear result is advice: it claims nothing and is not a lock.",
        {"paths": {"type": "array", "minItems": 1, "maxItems": MAX_OVERLAP_PATHS,
                   "items": {"type": "string", "maxLength": MAX_OVERLAP_PATH_CHARS}}}, ["paths"]),
}


def role_workspace_tools(mailbox, endpoint):
    """Read-only views the registry gives this role. Grants are never offered to any role."""
    import hierarchy_roles
    return hierarchy_roles.workspace_tools(hierarchy_roles.role(endpoint, mailbox.endpoint(endpoint).get("kind")))


def definitions(extra=(), board_specs=None):
    """A connection is either a role's mailbox or the board, because they fail and change separately."""
    properties = {
        "message_id": {"type": "string", "maxLength": 80},
        "to": {"type": "string", "maxLength": 256},
        "type": {"type": "string", "enum": ["info", "brief", "dispatch", "result", "review", "escalation", "ack",
                                            "job_request", "job_receipt"]},
        "body": {"type": "string", "maxLength": 65536},
        "brief": {"type": "object"}, "in_reply_to": {"type": "string", "maxLength": 80},
        "acknowledgment": {"type": "string", "enum": ["received", "accepted", "completed"]},
        "readiness": {"type": "object"}, "result": {"type": "object"}, "receipt": {"type": "object"},
    }
    specs = [] if board_specs else [
        ("mailbox_inbox", True, "Read only this endpoint's mailbox; optionally include its hash-verified briefs. "
                                "binding_only returns just the binding, a hash check per checkpoint brief and the "
                                "message count.",
         {"include_briefs": {"type": "boolean"}, "limit": {"type": "integer", "minimum": 1, "maximum": 100},
          "after_message_id": {"type": "string", "maxLength": 80}, "binding_only": {"type": "boolean"}}, []),
        ("mailbox_publish", False, "Publish information under the configured sender; grants no approval or verified completion.",
         properties, ["message_id", "to", "type", "body"]),
        ("mailbox_ack_handoff", False, "Acknowledge this configured successor's checkpoint; grants no owner approval.",
         {"checkpoint_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}}, ["checkpoint_sha256"]),
    ]
    specs += [(name, True, *WORKSPACE_TOOL_SPECS[name]) for name in extra]
    specs += [(name, readonly, description, props, required)
              for name, (readonly, description, props, required) in (board_specs or {}).items()]
    return [{"name": name, "description": description, "annotations": {"readOnlyHint": readonly},
             "inputSchema": {"type": "object", "properties": props, "required": required,
                             "additionalProperties": False}}
            for name, readonly, description, props, required in specs]


MAILBOX_INSTRUCTIONS = ("File-mailbox convention only. Configured sender provenance is not authenticated identity. "
                        "Acknowledgments confer no approval, membership, execution proof or fitness credit.")
ROOT_ONLY_ADAPTER = ("ROOT takes only the decision adapter: give --lifecycle and --actor; "
                     "operational controller access is forbidden")
DECISION_TOOL = "root_decide"
DECISION_SPEC = (
    "Record ROOT's approve or deny on an existing canonical request in the lifecycle journal, under this "
    "connection's configured ROOT actor. The actor is configuration, not an authenticated identity. Approval is "
    "not admission, start, acceptance or delivery. Retrying the same event_id with the same values returns the "
    "original receipt.",
    {"event_id": {"type": "string", "maxLength": 80}, "request_id": {"type": "string", "maxLength": 80},
     "request_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
     "decision": {"type": "string", "enum": ["approve", "deny"]}, "reason": {"type": "string", "maxLength": 1024}},
    ["event_id", "request_id", "request_sha256", "decision", "reason"])


class DecisionConnection:
    """ROOT's only adapter: one tool that approves or denies a canonical request, and nothing else.

    This is the configuration-bound tier of owner decision 5. The ROOT actor is whatever the connection was
    configured with, so every answer says it is not authenticated. The strict H decision path is M4 work.
    """
    workspace_tools = ()
    board_specs = {}
    instructions = ("Decision-only ROOT adapter. The ROOT actor is configuration and is not authenticated. "
                    "It records approve or deny in the lifecycle journal and never publishes, reads mail, "
                    "executes, starts or stops anything.")

    def __init__(self, root, endpoint, host, session, generation, lifecycle, actor):
        import hierarchy_lifecycle
        self.journal = hierarchy_lifecycle
        self.root = root
        self.sender = {"from": endpoint, "host": host, "session": session, "binding_generation": generation}
        self.manifest_digest = digest(Mailbox(root).manifest)
        matching(actor, SLUG, "actor")
        self.actor = actor
        self.lifecycle = hierarchy_lifecycle.Lifecycle(lifecycle)
        self.checked_mailbox()
        self.root_actor()

    def checked_mailbox(self):
        mailbox = Mailbox(self.root)
        require(digest(mailbox.manifest) == self.manifest_digest, "mailbox manifest changed since server startup")
        binding = mailbox.current_binding(self.sender["from"])
        require(all(self.sender[key] == binding[source] for key, source in (
            ("binding_generation", "generation"), ("host", "host"), ("session", "session"))),
                "stale or mismatched sender binding")
        require(mailbox.ready(binding), "handoff checkpoint has not been acknowledged")
        return mailbox

    def root_actor(self):
        # The policy is written once at init and never changes, so this needs no journal replay and no
        # lock. Whether the actor still holds custody is the journal's check, made under its own lock.
        policy = self.journal.validate_policy(self.journal.load_json(self.lifecycle.root / "policy.json"))
        actor = policy["actors"].get(self.actor)
        require(actor is not None and actor["role"] == "root",
                "actor %s is not a ROOT actor in the lifecycle policy" % self.actor)
        return actor

    def definitions(self):
        description, properties, required = DECISION_SPEC
        return [{"name": DECISION_TOOL, "description": description, "annotations": {"readOnlyHint": False},
                 "inputSchema": {"type": "object", "properties": properties, "required": required,
                                 "additionalProperties": False}}]

    def call(self, name, arguments, render=None):
        text(name, "tool name", 128)
        require(name == DECISION_TOOL, "unknown ROOT tool: %s; ROOT only records decisions" % name)
        fields(arguments, set(DECISION_SPEC[2]))
        # Typed here, so a malformed value is a refusal and never reaches the journal's own code as a non-string.
        matching(arguments["event_id"], SLUG, "event id")
        matching(arguments["request_id"], SLUG, "request id")
        matching(arguments["request_sha256"], SHA256, "request sha256")
        require(arguments["decision"] in ("approve", "deny"), "decision must be approve or deny")
        text(arguments["reason"], "decision reason", 1024)
        # The journal checks the rest: that the request exists with these bytes and that this actor still
        # holds ROOT custody. Under the mailbox lock, so a rebinding cannot land between the fence check
        # and the record.
        with writer_lock(self.root):
            self.checked_mailbox()
            actor = self.root_actor()
            envelope = {"id": arguments["event_id"], "actor": self.actor, "generation": actor["generation"],
                        "custody": {"cid": self.actor, "generation": actor["generation"]},
                        "event": {"type": "decision", "request_id": arguments["request_id"],
                                  "request_sha256": arguments["request_sha256"], "decision": arguments["decision"],
                                  "reason": arguments["reason"]}}
            try:
                receipt = self.lifecycle.record(envelope)
            except ValueError as exc:
                # The journal shares the mailbox's lock helper, whose busy text names the mailbox. The mailbox
                # lock is already held here, so a busy lock at this point is the journal's.
                if str(exc).startswith("mailbox writer is busy"):
                    raise ValueError("lifecycle journal writer is busy; inspect an abandoned "
                                     + str(self.lifecycle.root / ".write.lock") + " before retrying") from exc
                raise
        return {"receipt": receipt, "identity": "configured", "authenticated": False, "execution_enabled": False}

    def record_read(self):
        pass

    def record_position(self):
        pass


class Connection:
    instructions = MAILBOX_INSTRUCTIONS

    def __init__(self, root, endpoint, host, session, generation, delivery_dir=None, workspace_store=None,
                 initiative=None, board=None):
        # Owner-facing ROOT gets only the decision adapter; configured-sender mail is not a decision boundary.
        require(endpoint_parts(endpoint)[1] != "root", ROOT_ONLY_ADAPTER)
        require(board is None or (delivery_dir is None and workspace_store is None), "a board connection takes no mailbox options")
        require((workspace_store is None) == (initiative is None),
                "workspace store and initiative must be given together")
        self.root = root
        self.sender = {"from": endpoint, "host": host, "session": session, "binding_generation": generation}
        mailbox = Mailbox(root)
        self.manifest_digest = digest(mailbox.manifest)
        self.delivery_dir = mailbox.delivery_directory(delivery_dir) if delivery_dir is not None else None
        self.returned = []
        self.checked_mailbox()
        self.initiative = initiative
        self.workspace_tools = ()
        if workspace_store is not None:
            # Imported only when configured, so a mailbox-only adapter does not load the workspace store.
            import hierarchy_workspace
            self.workspace = hierarchy_workspace
            self.store = hierarchy_workspace.Store(workspace_store)
            try:
                ledger = self.store.load()
            except ValueError as exc:
                # A session must keep its mail even if root's records are damaged. An absent store is a
                # wrong connection and refuses, while damage shows up on the workspace tools themselves.
                if "malformed" not in str(exc):
                    raise
            else:
                ledger.initiative(initiative)
            self.workspace_tools = role_workspace_tools(mailbox, endpoint)
        self.board = None
        self.board_specs = {}
        self.pending_position = None
        if board is not None:
            import hierarchy_board
            self.board = hierarchy_board.Board(board)
            self.board.load()
            self.board_specs = hierarchy_board.TOOL_SPECS

    def definitions(self):
        return definitions(self.workspace_tools, self.board_specs)

    def board_call(self, name, arguments, render):
        self.checked_mailbox()
        result, self.pending_position = self.board.call(self.sender["from"], name, arguments, render)
        return result

    def record_position(self):
        # Called only after the response is written and flushed, like record_read, so a page that
        # never arrived is offered again.
        position, self.pending_position = self.pending_position, None
        if position is None:
            return
        try:
            self.board.move_position(self.sender["from"], *position)
        except (ValueError, OSError, UnicodeError) as exc:
            print("board position not recorded: " + str(exc), file=sys.stderr, flush=True)

    def workspace_view(self, name, arguments):
        self.checked_mailbox()
        ledger = self.store.load()
        if name == "workspace_path_overlap":
            fields(arguments, {"paths"})
            paths = arguments["paths"]
            require(isinstance(paths, list) and len(paths) <= MAX_OVERLAP_PATHS, "invalid paths")
            for path in paths:
                text(path, "path", MAX_OVERLAP_PATH_CHARS)
            return self.workspace.check_paths(ledger, self.initiative, paths)[1]
        fields(arguments, set())
        if name == "workspace_capacity":
            return self.workspace.capacity_view(ledger)
        return self.workspace.initiative_view(ledger, self.initiative)

    def note_returned(self, page):
        self.returned = [row["message"]["message_id"] for row in page["messages"]]

    def record_read(self):
        # Called only after the response is written and flushed. A failure or crash before then
        # leaves the message unread, and a lost receipt must not cost the session its mail. Both
        # err toward waking the session again.
        identifiers, self.returned = self.returned, []
        if self.delivery_dir is None or not identifiers:
            return
        try:
            Mailbox(self.root).record_read(self.delivery_dir, self.sender, identifiers)
        except (ValueError, OSError, UnicodeError) as exc:
            print("read receipt not recorded: " + str(exc), file=sys.stderr, flush=True)

    def checked_mailbox(self):
        mailbox = Mailbox(self.root)
        require(digest(mailbox.manifest) == self.manifest_digest, "mailbox manifest changed since server startup")
        binding = mailbox.current_binding(self.sender["from"])
        require(all(self.sender[key] == binding[source] for key, source in (
            ("binding_generation", "generation"), ("host", "host"), ("session", "session"))),
                "stale or mismatched sender binding")
        return mailbox

    def call(self, name, arguments, render=None):
        text(name, "tool name", 128)
        if self.board is not None:
            require(name in self.board_specs, "unknown mailbox tool: " + name)
            return self.board_call(name, arguments, render)
        if name == "mailbox_inbox":
            fields(arguments, set(), {"include_briefs", "limit", "after_message_id", "binding_only"})
            binding_only = arguments.get("binding_only", False)
            require(type(binding_only) is bool, "binding_only must be boolean")
            if binding_only:
                require(arguments.keys() == {"binding_only"},
                        "binding_only takes no include_briefs, limit or after_message_id")
                return self.checked_mailbox().binding_view(self.sender["from"])
            include_briefs = arguments.get("include_briefs", False)
            require(type(include_briefs) is bool, "include_briefs must be boolean")
            return self.checked_mailbox().inbox(self.sender["from"], include_briefs=include_briefs,
                                               limit=arguments.get("limit", 20), after=arguments.get("after_message_id"))
        if name == "mailbox_publish":
            fields(arguments, {"message_id", "to", "type", "body"},
                   {"brief", "in_reply_to", "acknowledgment", "readiness", "result", "receipt"})
            with writer_lock(self.root):
                return self.checked_mailbox().publish({**arguments, **self.sender})
        if name == "mailbox_ack_handoff":
            fields(arguments, {"checkpoint_sha256"})
            matching(arguments["checkpoint_sha256"], SHA256, "checkpoint sha256")
            with writer_lock(self.root):
                return self.checked_mailbox().acknowledge_handoff({
                    "endpoint": self.sender["from"], "session": self.sender["session"],
                    "generation": self.sender["binding_generation"], **arguments})
        if name in self.workspace_tools:
            return self.workspace_view(name, arguments)
        raise ValueError("unknown mailbox tool: " + name)


def handle(connection, request):
    fields(request, {"jsonrpc", "method"}, {"id", "params"})
    require(request["jsonrpc"] == "2.0", "unsupported JSON-RPC version")
    text(request["method"], "method", 128)
    identifier = request.get("id")
    require(identifier is None or type(identifier) in (str, int), "invalid JSON-RPC id")
    if "id" not in request:
        return None
    params = request.get("params", {})
    require(isinstance(params, dict), "params must be an object")
    method = request["method"]
    if method == "initialize":
        connection.checked_mailbox()
        return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                "serverInfo": {"name": "aegis-hierarchy-mailbox", "version": "1"},
                "instructions": connection.instructions}
    if method == "ping":
        connection.checked_mailbox()
        return {}
    if method == "tools/list":
        connection.checked_mailbox()
        return {"tools": connection.definitions()}
    if method == "tools/call":
        fields(params, {"name"}, {"arguments", "_meta"})
        def render(page):
            return _response_line({"jsonrpc": "2.0", "id": identifier, "result": _tool_result(page)})

        try:
            result = connection.call(params["name"], params.get("arguments", {}), render)
            # A binding-only view has no messages to page and nothing to record as read.
            if params["name"] == "mailbox_inbox" and not params.get("arguments", {}).get("binding_only"):
                result = _bounded_inbox(result, render)
                connection.note_returned(result)
            return _tool_result(result)
        except (ValueError, OSError, UnicodeError, RecursionError) as exc:
            return {"content": [{"type": "text", "text": json.dumps({"error": _error_text(exc)})}], "isError": True}
    raise ValueError("unsupported mailbox method: " + method)


def serve(root, endpoint, host, session, generation, delivery_dir=None, workspace_store=None, initiative=None, board=None,
          lifecycle=None, actor=None):
    integer(generation, "binding generation")
    if endpoint_parts(endpoint)[1] == "root":
        require(lifecycle is not None and actor is not None, ROOT_ONLY_ADAPTER)
        require(delivery_dir is None and workspace_store is None and initiative is None and board is None,
                "the ROOT decision adapter takes no mailbox, workspace or board options")
        connection = DecisionConnection(root, endpoint, host, session, generation, lifecycle, actor)
    else:
        require(lifecycle is None and actor is None, "only ROOT takes --lifecycle and --actor")
        connection = Connection(root, endpoint, host, session, generation, delivery_dir=delivery_dir,
                                workspace_store=workspace_store, initiative=initiative, board=board)
    while True:
        raw = sys.stdin.buffer.readline(MAX_BYTES + 1)
        if not raw:
            return 0
        response = {"jsonrpc": "2.0", "id": None}
        oversized = len(raw) > MAX_BYTES
        try:
            require(not oversized, "mailbox frame exceeds 262144 bytes")
            request = strict_json(raw.decode("utf-8"))
        except (ValueError, UnicodeError, RecursionError) as exc:
            response["error"] = {"code": -32700, "message": _error_text(exc)}
        else:
            try:
                result = handle(connection, request)
                if result is None:
                    continue
                response["id"] = request["id"]
                response["result"] = result
            except (ValueError, OSError, UnicodeError, RecursionError) as exc:
                response["error"] = {"code": -32602, "message": _error_text(exc)}
                if isinstance(request, dict) and type(request.get("id")) in (str, int):
                    response["id"] = request["id"]
        try:
            sys.stdout.buffer.write(_response_line(response))
            sys.stdout.buffer.flush()
        except OSError:
            # The connection is gone, so nothing was delivered. Point stdout at nothing so the
            # interpreter's own flush at exit cannot fail too.
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
            return 0
        connection.record_read()
        connection.record_position()
        if oversized:
            return 0  # close the channel rather than interpret frame fragments as requests
