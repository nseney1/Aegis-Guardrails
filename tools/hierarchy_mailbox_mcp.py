"""Scoped stdio access to the pilot's file protocol, outside Aegis core.

Launch through hierarchy_mailbox.py serve, which supports isolated Python imports.
The configured sender is provenance, not an authenticated native host identity.
"""
import json
import sys

from hierarchy_mailbox import (MAX_BYTES, Mailbox, digest, fields, integer, matching,
                               require, SHA256, strict_json, text, writer_lock)


def definitions():
    properties = {
        "message_id": {"type": "string", "maxLength": 80},
        "to": {"type": "string", "maxLength": 256},
        "type": {"type": "string", "enum": ["info", "brief", "dispatch", "result", "review", "escalation", "ack"]},
        "body": {"type": "string", "maxLength": 65536},
        "brief": {"type": "object"}, "in_reply_to": {"type": "string", "maxLength": 80},
        "acknowledgment": {"type": "string", "enum": ["received", "accepted", "completed"]},
        "readiness": {"type": "object"}, "result": {"type": "object"},
    }
    specs = [
        ("mailbox_inbox", True, "Read only this endpoint's mailbox; optionally include its hash-verified briefs.",
         {"include_briefs": {"type": "boolean"}, "limit": {"type": "integer", "minimum": 1, "maximum": 100},
          "after_message_id": {"type": "string", "maxLength": 80}}, []),
        ("mailbox_publish", False, "Publish information under the configured sender; grants no approval or verified completion.",
         properties, ["message_id", "to", "type", "body"]),
        ("mailbox_ack_handoff", False, "Acknowledge this configured successor's checkpoint; grants no owner approval.",
         {"checkpoint_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}}, ["checkpoint_sha256"]),
    ]
    return [{"name": name, "description": description, "annotations": {"readOnlyHint": readonly},
             "inputSchema": {"type": "object", "properties": props, "required": required,
                             "additionalProperties": False}}
            for name, readonly, description, props, required in specs]


class Connection:
    def __init__(self, root, endpoint, host, session, generation):
        self.root = root
        self.sender = {"from": endpoint, "host": host, "session": session, "binding_generation": generation}
        mailbox = Mailbox(root)
        self.manifest_digest = digest(mailbox.manifest)
        self.checked_mailbox()

    def checked_mailbox(self):
        mailbox = Mailbox(self.root)
        require(digest(mailbox.manifest) == self.manifest_digest, "mailbox manifest changed since server startup")
        binding = mailbox.current_binding(self.sender["from"])
        require(all(self.sender[key] == binding[source] for key, source in (
            ("binding_generation", "generation"), ("host", "host"), ("session", "session"))),
                "stale or mismatched sender binding")
        return mailbox

    def call(self, name, arguments):
        text(name, "tool name", 128)
        if name == "mailbox_inbox":
            fields(arguments, set(), {"include_briefs", "limit", "after_message_id"})
            include_briefs = arguments.get("include_briefs", False)
            require(type(include_briefs) is bool, "include_briefs must be boolean")
            return self.checked_mailbox().inbox(self.sender["from"], include_briefs=include_briefs,
                                               limit=arguments.get("limit", 20), after=arguments.get("after_message_id"))
        if name == "mailbox_publish":
            fields(arguments, {"message_id", "to", "type", "body"},
                   {"brief", "in_reply_to", "acknowledgment", "readiness", "result"})
            with writer_lock(self.root):
                return self.checked_mailbox().publish({**arguments, **self.sender})
        if name == "mailbox_ack_handoff":
            fields(arguments, {"checkpoint_sha256"})
            matching(arguments["checkpoint_sha256"], SHA256, "checkpoint sha256")
            with writer_lock(self.root):
                return self.checked_mailbox().acknowledge_handoff({
                    "endpoint": self.sender["from"], "session": self.sender["session"],
                    "generation": self.sender["binding_generation"], **arguments})
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
        return {"tools": definitions()}
    if method == "tools/call":
        fields(params, {"name"}, {"arguments", "_meta"})
        try:
            result = connection.call(params["name"], params.get("arguments", {}))
            return {"content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}]}
        except (ValueError, OSError, UnicodeError, RecursionError) as exc:
            return {"content": [{"type": "text", "text": json.dumps({"error": str(exc)})}], "isError": True}
    raise ValueError("unsupported mailbox method: " + method)


def serve(root, endpoint, host, session, generation):
    integer(generation, "binding generation")
    connection = Connection(root, endpoint, host, session, generation)
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
            response["error"] = {"code": -32700, "message": str(exc)}
        else:
            try:
                result = handle(connection, request)
                if result is None:
                    continue
                response["id"] = request["id"]
                response["result"] = result
            except (ValueError, OSError, UnicodeError, RecursionError) as exc:
                response["error"] = {"code": -32602, "message": str(exc)}
                if isinstance(request, dict) and type(request.get("id")) in (str, int):
                    response["id"] = request["id"]
        print(json.dumps(response, sort_keys=True), flush=True)
        if oversized:
            return 0  # close the channel rather than interpret frame fragments as requests
