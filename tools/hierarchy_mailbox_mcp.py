"""Scoped stdio access to the pilot's file protocol, outside Aegis core.

Launch through hierarchy_mailbox.py serve, which supports isolated Python imports.
The configured sender is provenance, not an authenticated native host identity.
"""
import json
import os
import sys

from hierarchy_mailbox import (MAX_BYTES, Mailbox, _bounded_inbox, digest, endpoint_parts, fields, integer, matching,
                               require, SHA256, strict_json, text, writer_lock)


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
    """Read-only views by role. Reviewers get none, and grants are never offered to any role."""
    role = endpoint_parts(endpoint)[1]
    if role == "orchestrator":
        return ("workspace_capacity", "workspace_initiative")
    if role == "front-door":
        return ("workspace_initiative",)
    if mailbox.endpoint(endpoint).get("kind") in ("implementer", "integrator"):
        return ("workspace_path_overlap",)
    return ()


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
        ("mailbox_inbox", True, "Read only this endpoint's mailbox; optionally include its hash-verified briefs.",
         {"include_briefs": {"type": "boolean"}, "limit": {"type": "integer", "minimum": 1, "maximum": 100},
          "after_message_id": {"type": "string", "maxLength": 80}}, []),
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


class Connection:
    def __init__(self, root, endpoint, host, session, generation, delivery_dir=None, workspace_store=None,
                 initiative=None, board=None):
        # Grants and job runs stay out of anything a model session can call, so root has no adapter.
        require(endpoint_parts(endpoint)[1] != "root", "root uses the controller, not the mailbox adapter")
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
            # Imported only when configured, so the default adapter needs just the two mailbox files.
            import hierarchy_workspace
            self.workspace = hierarchy_workspace
            self.store = hierarchy_workspace.Store(workspace_store)
            self.store.load().initiative(initiative)
            self.workspace_tools = role_workspace_tools(mailbox, endpoint)
        self.board = None
        self.board_specs = {}
        self.pending_position = None
        if board is not None:
            import hierarchy_board
            self.board = hierarchy_board.Board(board)
            self.board.load()
            self.board_specs = hierarchy_board.TOOL_SPECS

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
            fields(arguments, set(), {"include_briefs", "limit", "after_message_id"})
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
                "instructions": "File-mailbox convention only. Configured sender provenance is not authenticated identity. "
                                "Acknowledgments confer no approval, membership, execution proof or fitness credit."}
    if method == "ping":
        connection.checked_mailbox()
        return {}
    if method == "tools/list":
        connection.checked_mailbox()
        return {"tools": definitions(connection.workspace_tools, connection.board_specs)}
    if method == "tools/call":
        fields(params, {"name"}, {"arguments", "_meta"})
        def render(page):
            return _response_line({"jsonrpc": "2.0", "id": identifier, "result": _tool_result(page)})

        try:
            result = connection.call(params["name"], params.get("arguments", {}), render)
            if params["name"] == "mailbox_inbox":
                result = _bounded_inbox(result, render)
                connection.note_returned(result)
            return _tool_result(result)
        except (ValueError, OSError, UnicodeError, RecursionError) as exc:
            return {"content": [{"type": "text", "text": json.dumps({"error": _error_text(exc)})}], "isError": True}
    raise ValueError("unsupported mailbox method: " + method)


def serve(root, endpoint, host, session, generation, delivery_dir=None, workspace_store=None, initiative=None, board=None):
    integer(generation, "binding generation")
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
