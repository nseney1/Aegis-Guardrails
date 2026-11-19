"""Product mailbox API over validated legacy records and injected policy.

Use a context manager. Roles, hosts and clock come from the owner-selected run
configuration. Host entries may supply git, git_is_ancestor, source_witness and
observe_readiness ports; this module never imports tools or launches processes.
Only the confined store performs file operations. A write holds exclusion from
fresh history validation through exclusive publication. Delivery directories,
receipts and evidence paths are MailboxDelivery methods.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
from threading import local
from types import MappingProxyType

from aegis_core.team_mailbox_primitives import (
    render_mailbox_refusal,
    MAX_BYTES, MAX_RECORDS, MAX_HISTORY_BYTES, MAX_DIRTY_ENTRIES, MAX_DELIVERY_IDS,
    MAX_RECENT_ACKNOWLEDGMENTS, MESSAGE_TYPES, STAGES, TERMINAL_JOB_STATES,
    VERIFICATION, SHA256, GIT_ID, SLUG,
    MailboxRefusal, RoleTables, bounded_tree, digest, encoded, fields, integer,
    matching, message_types, parse_time, record_types, reply_reference, require, safe_path,
    strict_json, strings, text, validation, validate_job_receipt, witness_record,
    binding_payload, binding_record, checkpoint_payload,
)
from aegis_core.team_mailbox_store import Store, initialize_store
from aegis_core.team_mailbox_service import operation, witnesses
from aegis_core.team_mailbox_delivery import MailboxDelivery
from aegis_core.team_mailbox_index_scan import pending_entry

__all__ = ["Mailbox", "MailboxRefusal", "initialize"]


class Mailbox(MailboxDelivery):
    def __init__(self, root, *, clock, roles, hosts, caller_role, host=None, delivery_roots=()):
        require(isinstance(roles, RoleTables))
        require(callable(clock) and type(hosts) is dict and bool(hosts))
        self.store = Store(root, delivery_roots=delivery_roots)
        self.delivery_roots = self.store.delivery_roots
        self.root = self.store.root
        self.roles, self.clock, self.caller_role = roles, clock, caller_role
        self.hosts = MappingProxyType(dict(hosts))
        self.calls = local()
        self.host = host if host is not None else next(iter(hosts)) if len(hosts) == 1 else None
        try:
            self.manifest = self.roles.validate_manifest(self.store.read_json(self.root / "manifest.json"))
        except BaseException:
            self.store.close()
            raise

    def refresh(self):
        self.manifest = self.roles.validate_manifest(self.store.read_json(self.root / "manifest.json"))

    def __enter__(self):
        self.store.__enter__()
        return self

    def __exit__(self, *error):
        self.close()

    def close(self):
        self.store.close()

    def now(self):
        moment = self.clock()
        require(isinstance(moment, datetime) and moment.tzinfo is not None)
        return moment.astimezone(timezone.utc)

    def timestamp(self):
        return self.now().isoformat(timespec="microseconds").replace("+00:00", "Z")

    def require_host(self, host):
        text(host, "host", 128)
        require(host in self.hosts, reason="unknown_host")

    def host_call(self, name, *args):
        require(self.host is None or type(self.host) is str)
        require(self.host in self.hosts, reason="unknown_host")
        port = getattr(self.hosts[self.host], name, None)
        require(callable(port), reason="host_unavailable")
        try:
            return port(*args)
        except MailboxRefusal as error:
            render_mailbox_refusal(error, reraise=True)
        except (OSError, TimeoutError, ValueError):
            raise MailboxRefusal("host_unavailable") from None

    @operation(write=False)
    def require_independent_session(self, endpoint, host, session):
        kind = self.endpoint(endpoint).get("kind", self.roles.endpoint_parts(endpoint)[1])
        for other in self.manifest["endpoints"]:
            if other == endpoint:
                continue
            history = self.bindings(other)
            if not history or (history[-1]["host"], history[-1]["session"]) != (host, session):
                continue
            other_kind = self.endpoint(other).get("kind", self.roles.endpoint_parts(other)[1])
            require(kind == other_kind or not {kind, other_kind} & self.roles.independent)

    @operation(write=False)
    def endpoint(self, endpoint):
        self.roles.endpoint_parts(endpoint)
        require(endpoint in self.manifest["endpoints"], "unknown endpoint: " + endpoint)
        return self.manifest["endpoints"][endpoint]

    @operation(write=False)
    def require_kind(self, endpoint, kind):
        """Bind-by-kind interim (T112 H1): a request that names a kind is refused when the manifest disagrees.

        Only lanes declare a kind, so a kind given for any other role is refused too.
        """
        text(kind, "kind", 64)
        declared = self.endpoint(endpoint).get("kind")
        require(kind == declared, "kind " + repr(kind) + " does not match the manifest kind "
                + ("(none)" if declared is None else repr(declared)) + " of " + endpoint)

    @operation(write=False)
    def route(self, sender, recipient):
        self.endpoint(sender)
        self.endpoint(recipient)
        left, right = self.roles.endpoint_parts(sender), self.roles.endpoint_parts(recipient)
        vertical = left[0] == right[0] and any({left[1], right[1]} == set(pair) for pair in self.roles.vertical_routes)
        across = any({sender, recipient} == set(pair) for pair in self.manifest["counterparts"])
        require(vertical or across, "route is not vertical or an explicit counterpart")
        return self.root / ("across" if across else right[0]) / right[1]

    @operation(write=False)
    def brief(self, brief, *, verify=True):
        fields(brief, {"path", "sha256"})
        matching(brief["sha256"], SHA256, "brief sha256")
        path = safe_path(text(brief["path"], "brief path"))
        require(path.suffix == ".md", "brief must be a Markdown file")
        try:
            path.relative_to(self.root.parent)
        except ValueError as exc:
            raise MailboxRefusal("invalid_record") from None
        if verify:
            raw = self.store.read(path)
            require(hashlib.sha256(raw).hexdigest() == brief["sha256"], "brief sha256 mismatch")
            return raw

    @operation(write=False)
    def checkpoint(self, checkpoint, messages, *, verify=True, stored=False):
        checkpoint = checkpoint if stored else checkpoint_payload(checkpoint)
        bounded_tree(checkpoint)
        fields(checkpoint, {"outgoing_stopped", "briefs", "sources", "lease_refs", "completed_checks",
                            "pending_message_ids", "last_acknowledgment_ids"})
        require(checkpoint["outgoing_stopped"] is True, "outgoing session must be stopped before replacement")
        require(isinstance(checkpoint["briefs"], list) and 0 < len(checkpoint["briefs"]) <= 256,
                "checkpoint requires brief references")
        for brief in checkpoint["briefs"]:
            self.brief(brief, verify=verify)
        sources = checkpoint["sources"]
        require(isinstance(sources, list) and len(sources) <= 256, "invalid checkpoint sources")
        for source in sources:
            fields(source, {"worktree", "source_revision", "source_tree"},
                   {"dirty_state", "dirty_state_sha256", "dirty_entries", "dirty_evidence"})
            text(source["worktree"], "checkpoint worktree")
            matching(source["source_revision"], GIT_ID, "source revision")
            matching(source["source_tree"], GIT_ID, "source tree")
            if "dirty_state" in source:
                # Earlier bindings hold the literal status. Its 4096 limit blocked real rotations,
                # so new checkpoints use the digest form, but history must stay readable.
                require(not {"dirty_state_sha256", "dirty_entries", "dirty_evidence"} & source.keys(),
                        "checkpoint source mixes literal and digest dirty state")
                text(source["dirty_state"], "dirty state")
            else:
                matching(source.get("dirty_state_sha256"), SHA256, "dirty state digest")
                integer(source.get("dirty_entries"), "dirty entries", minimum=0, maximum=MAX_DIRTY_ENTRIES)
                if "dirty_evidence" in source:
                    text(source["dirty_evidence"], "dirty evidence")
        for name in ("lease_refs", "completed_checks", "pending_message_ids", "last_acknowledgment_ids"):
            strings(checkpoint[name], name)
        if verify:
            record_types(messages)
            for name in ("pending_message_ids", "last_acknowledgment_ids"):
                for identifier in checkpoint[name]:
                    require(identifier in messages, "checkpoint references an unknown message")
                    if name == "last_acknowledgment_ids":
                        require(messages[identifier]["message"]["type"] == "ack", "checkpoint acknowledgment is not an ack")

    @operation(write=False)
    def bindings(self, endpoint):
        self.endpoint(endpoint)
        directory = safe_path(self.root / "bindings" / endpoint)
        result, total_bytes = [], 0
        entries = self.store.entries(directory, missing=True)
        for path in entries:
            safe_path(path)
            require(re.fullmatch(r"\d{6}\.(json|ack)", path.name) is not None
                    or pending_entry(path, self.root),
                    "unexpected binding history entry")
        for path in (p for p in entries if p.suffix == ".json"):
            require(len(result) < MAX_RECORDS, "binding history exceeds record limit")
            raw = self.store.read(path, limit=min(MAX_BYTES, MAX_HISTORY_BYTES - total_bytes))
            total_bytes += len(raw)
            record = strict_json(raw)
            fields(record, {"schema", "endpoint", "host", "session", "generation", "created_at", "checkpoint", "checkpoint_sha256"})
            require(record["schema"] == "aegis.role-binding/v1" and record["endpoint"] == endpoint,
                    "malformed role binding")
            integer(record["generation"], "binding generation")
            require(record["generation"] == len(result) + 1 and path.name == "%06d.json" % record["generation"],
                    "nonconsecutive binding history")
            self.require_host(record["host"])
            text(record["session"], "session", 256)
            parse_time(record["created_at"])
            if record["generation"] == 1:
                require(record["checkpoint"] is None and record["checkpoint_sha256"] is None, "invalid initial binding")
            else:
                self.checkpoint(record["checkpoint"], {}, verify=False, stored=True)
                require(digest(record["checkpoint"]) == record["checkpoint_sha256"], "checkpoint digest mismatch")
            result.append(record)
        for path in (p for p in entries if p.suffix == ".ack"):
            generation = int(path.stem)
            require(1 < generation <= len(result), "handoff acknowledgment has no replacement binding")
            raw = self.store.read(path, limit=min(MAX_BYTES, MAX_HISTORY_BYTES - total_bytes))
            total_bytes += len(raw)
            ack = strict_json(raw)
            fields(ack, {"endpoint", "generation", "session", "checkpoint_sha256"})
            require(ack == {key: result[generation - 1][key] for key in ack},
                    "handoff acknowledgment does not match binding")
        self.calls.history_bytes[directory] = total_bytes
        return result

    @operation(write=False, input_record=(0, "binding", binding_record))
    def ready(self, binding):
        fields(binding, {"schema", "endpoint", "host", "session", "generation", "created_at",
                         "checkpoint", "checkpoint_sha256"})
        integer(binding["generation"], "binding generation")
        history = self.bindings(binding["endpoint"])
        return self._ready(binding, history)

    def _ready(self, binding, history):
        """Inspect readiness using history already validated in this operation."""
        require(binding["generation"] <= len(history))
        stored = history[binding["generation"] - 1]
        require(all(binding[key] == value for key, value in stored.items()))
        if binding["generation"] == 1:
            return True
        path = safe_path(self.root / "bindings" / binding["endpoint"] / ("%06d.ack" % binding["generation"]))
        if not self.store.exists(path):
            return False
        ack = self.store.read_json(path)
        fields(ack, {"endpoint", "generation", "session", "checkpoint_sha256"})
        require(ack == {key: binding[key] for key in ack}, "handoff acknowledgment does not match binding")
        return True

    @operation(write=False)
    def fence(self, sender, *, ready=True):
        """The check every write makes: the configured sender is its endpoint's current binding and, unless the
        write is the acknowledgment itself, that binding has acknowledged its handoff checkpoint.

        Callers hold self.store.lock(root), so a rebinding cannot land between this check and the write. The sender is
        configuration, so this refuses a stale or unacknowledged session; it does not authenticate one."""
        require(type(sender) is dict)
        binding, history = self._current_binding(sender["from"])
        expected = {"host": binding["host"], "session": binding["session"], "binding_generation": binding["generation"]}
        require(all(type(sender.get(key)) is type(value) and sender.get(key) == value for key, value in expected.items()),
                "stale or mismatched sender binding")
        require(not ready or self._ready(binding, history), "handoff checkpoint has not been acknowledged")
        return binding

    @operation(write=False)
    def current_binding(self, endpoint):
        binding, _history = self._current_binding(endpoint)
        return binding

    def _current_binding(self, endpoint):
        history = self.bindings(endpoint)
        require(bool(history), "endpoint has no session binding: " + endpoint)
        return history[-1], history

    @operation(write=False)
    def validate_message(self, message, *, stored=False):
        required = {"message_id", "from", "to", "host", "session", "binding_generation", "type", "body"}
        optional = {"brief", "in_reply_to", "acknowledgment", "readiness", "result", "receipt"}
        if stored:
            required |= {"schema", "created_at", "authority", "verification"}
        fields(message, required, optional)
        matching(message["message_id"], SLUG, "message_id")
        destination = self.route(message["from"], message["to"])
        self.require_host(message["host"])
        text(message["session"], "session", 256)
        integer(message["binding_generation"], "binding generation")
        require(isinstance(message["type"], str) and message["type"] in MESSAGE_TYPES, "unsupported message type")
        text(message["body"], "body", 65536)
        if "brief" in message:
            self.brief(message["brief"], verify=not stored)
        if "in_reply_to" in message:
            matching(message["in_reply_to"], SLUG, "in_reply_to")
        if message["type"] == "job_request":
            left, right = self.roles.endpoint_parts(message["from"]), self.roles.endpoint_parts(message["to"])
            require(left[0] == right[0] and left[1] == "orchestrator" and right[1] == "root",
                    "only an orchestrator can request a job from its own root")
            require("brief" in message, "job request requires a hash-bound packet")
        if message["type"] == "job_receipt":
            left, right = self.roles.endpoint_parts(message["from"]), self.roles.endpoint_parts(message["to"])
            require(left[1] == "root" and right[1] == "orchestrator" and "in_reply_to" in message,
                    "job receipt must come from root and reply to a job request")
            self.job_receipt(message.get("receipt"))
        elif "receipt" in message:
            raise MailboxRefusal("invalid_record")
        if message["type"] in {"brief", "dispatch"}:
            require("brief" in message, "brief or dispatch message requires a brief hash")
        if message["type"] == "dispatch":
            left, right = self.roles.endpoint_parts(message["from"]), self.roles.endpoint_parts(message["to"])
            require(left[0] == right[0] and left[1] == "orchestrator" and right[1] == "lane",
                    "only an orchestrator can dispatch its own lane")
        if message["type"] == "ack":
            require(isinstance(message.get("acknowledgment"), str) and message["acknowledgment"] in STAGES and "in_reply_to" in message,
                    "ack requires a stage and referenced message")
        else:
            require("acknowledgment" not in message, "acknowledgment field requires ack type")
        if "readiness" in message and self.endpoint(message["from"]).get("kind") == "reviewer":
            raise MailboxRefusal("invalid_record")
        if stored:
            require(message["schema"] == "aegis.mailbox/v1" and message["authority"] == "information_only",
                    "malformed mailbox authority or schema")
            parse_time(message["created_at"])
            require(message["verification"] in (VERIFICATION, {**VERIFICATION, "git_identity": "observed"}),
                    "unsupported verification claim")
            if "readiness" in message:
                require(message["type"] == "ack" and message.get("acknowledgment") == "accepted",
                        "readiness requires dispatch acceptance")
                self.readiness(message["readiness"], observe=False)
            if "result" in message:
                self.completion(message["result"], self.endpoint(message["from"]).get("kind"))
        return destination

    @operation(write=False)
    def messages(self):
        records, total_bytes = {}, 0
        folders = {self.root / endpoint.split("/")[0] / endpoint.split("/")[1]
                   for endpoint in self.manifest["endpoints"]}
        folders |= {self.root / "across" / role for role in self.roles.across_roles}
        for folder in sorted(folders):
            safe_path(folder)
            for path in self.store.entries(folder):
                safe_path(path)
                if pending_entry(path, self.root, message_folders=folders):
                    continue
                require(path.suffix == ".md", "unexpected mailbox entry: " + str(path))
                require(len(records) < MAX_RECORDS, "mailbox exceeds record limit")
                raw_bytes = self.store.read(path, limit=min(MAX_BYTES, MAX_HISTORY_BYTES - total_bytes))
                total_bytes += len(raw_bytes)
                raw = raw_bytes.decode("utf-8")
                try:
                    require(raw.startswith("---\n"), "missing header")
                    header, body = raw[4:].split("\n---\n\n", 1)
                    message = strict_json(header)
                    require(type(message) is dict)
                    message["body"] = body
                    destination = self.validate_message(message, stored=True)
                    require(destination == folder, "message is in the wrong routing folder")
                    require(message["message_id"] not in records, "duplicate message_id in history")
                    records[message["message_id"]] = {"path": str(path), "message": message}
                except MailboxRefusal as error:
                    render_mailbox_refusal(error, reraise=True)
                except (ValueError, KeyError):
                    raise MailboxRefusal("invalid_record") from None
        for record in records.values():
            message = record["message"]
            if "in_reply_to" in message:
                reply_reference(message, records)
        self.calls.history_bytes["messages"] = total_bytes
        return records

    @staticmethod
    @validation
    def reply(message, records):
        message_types(message)
        record_types(records)
        return reply_reference(message, records)

    @staticmethod
    @validation
    def dispatch_history(records):
        record_types(records)
        closed = {r["message"]["in_reply_to"] for r in records.values()
                  if "in_reply_to" in r["message"] and (r["message"]["type"] in {"result", "review"}
                  or (r["message"].get("acknowledgment") == "completed"
                      and records[r["message"]["in_reply_to"]]["message"]["type"] == "dispatch"))}
        accepted = [r["message"] for r in records.values() if r["message"].get("acknowledgment") == "accepted"
                    and records[r["message"]["in_reply_to"]]["message"]["type"] == "dispatch"]
        return closed, accepted

    @staticmethod
    @validation
    def job_receipt(receipt):
        return validate_job_receipt(receipt)

    @staticmethod
    @validation
    def open_job_requests(records):
        record_types(records)
        terminal = {r["message"]["in_reply_to"] for r in records.values() if r["message"]["type"] == "job_receipt"
                    and r["message"]["receipt"]["state"] in TERMINAL_JOB_STATES}
        return sorted((r["message"] for r in records.values()
                       if r["message"]["type"] == "job_request" and r["message"]["message_id"] not in terminal),
                      key=lambda message: (message["created_at"], message["message_id"]))

    @operation(write=False)
    def checkpoint_assignments(self, endpoint, checkpoint, records, *, lineage=False):
        """Exact by default: bind and draft-handoff anchor the snapshot. With lineage (ack-handoff only),
        a still-open lane may have moved forward on its branch since then; the observed witnesses are returned."""
        checkpoint = checkpoint_payload(checkpoint)
        self.checkpoint(checkpoint, records, verify=False)
        witnesses = {}
        for job in self.open_job_requests(records):
            if endpoint in (job["from"], job["to"]):
                require(job["message_id"] in checkpoint["pending_message_ids"], "checkpoint omits open job request")
        closed, accepted = self.dispatch_history(records)
        pending = [r["message"] for r in records.values() if r["message"]["type"] == "dispatch"
                   and r["message"]["message_id"] not in closed and endpoint in (r["message"]["from"], r["message"]["to"])]
        for dispatch in pending:
            identifier = dispatch["message_id"]
            require(identifier in checkpoint["pending_message_ids"], "checkpoint omits active dispatch")
            require(dispatch["brief"] in checkpoint["briefs"], "checkpoint omits active brief")
            readiness = next((m["readiness"] for m in accepted if m["in_reply_to"] == identifier and "readiness" in m), None)
            if readiness is not None:
                require(readiness["lease_ref"] in checkpoint["lease_refs"], "checkpoint omits active lease")
                source = next((s for s in checkpoint["sources"] if s["worktree"] == readiness["worktree"]), None)
                require(source is not None, "checkpoint omits active source snapshot")
                worktree = safe_path(source["worktree"])
                require(self.git(worktree, "branch", "--show-current") == readiness["branch"],
                        "checkpoint branch changed since acceptance")
                if lineage:
                    if source["worktree"] not in witnesses:
                        witnesses[source["worktree"]] = self.source_witness(worktree)
                    # Test the HEAD the witness recorded, so the reported state is the state that passed.
                    require(self.git_is_ancestor(worktree, source["source_revision"],
                                                 witnesses[source["worktree"]]["source_revision"]),
                            "checkpoint source moved off its snapshot: " + str(worktree))
                    continue
                if "dirty_state" in source:
                    observed = {"source_revision": self.git(worktree, "rev-parse", "HEAD"),
                                "source_tree": self.git(worktree, "rev-parse", "HEAD^{tree}"),
                                "dirty_state": self.git(worktree, "status", "--porcelain=v1", "--untracked-files=all") or "clean"}
                else:
                    witness = self.source_witness(worktree)
                    observed = {key: witness[key] for key in ("source_revision", "source_tree",
                                                              "dirty_state_sha256", "dirty_entries")}
                require(all(source[key] == value for key, value in observed.items()),
                        "checkpoint source snapshot does not match worktree")
        keys = ("worktree", "source_revision", "source_tree", "dirty_entries", "dirty_state_sha256")
        return [{key: witnesses[name][key] for key in keys}
                for name in dict.fromkeys(source["worktree"] for source in checkpoint["sources"]) if name in witnesses]

    @operation(write=False)
    def wake_marker(self, endpoint):
        """Sits beside .write.lock, outside the routing folders, and is held from launch until the turn ends."""
        return safe_path(self.root / (".wake-" + endpoint.replace("/", "%2F") + ".lock"))

    @operation(write=True, envelope=True, input_record=(0, "request", binding_payload))
    def bind(self, request):
        fields(request, {"endpoint", "host", "session", "expected_generation"}, {"checkpoint"})
        self.endpoint(request["endpoint"])
        require(not self.store.exists(self.wake_marker(request["endpoint"])),
                "a wake is in progress for this endpoint; stop it and remove its lock before replacing the session")
        self.require_host(request["host"])
        text(request["session"], "session", 256)
        integer(request["expected_generation"], "expected generation", minimum=0)
        history = self.bindings(request["endpoint"])
        require(request["expected_generation"] == len(history), "binding generation changed")
        require(len(history) < MAX_RECORDS, "binding history limit reached")
        checkpoint = request.get("checkpoint")
        records = self.messages()
        if history:
            require(checkpoint is not None, "replacement requires a checkpoint")
            self.checkpoint(checkpoint, records)
            self.checkpoint_assignments(request["endpoint"], checkpoint, records)
        else:
            require(checkpoint is None, "initial binding cannot contain a replacement checkpoint")
        self.require_independent_session(request["endpoint"], request["host"], request["session"])
        record = {"schema": "aegis.role-binding/v1", "endpoint": request["endpoint"],
                  "host": request["host"], "session": request["session"], "generation": len(history) + 1,
                  "created_at": self.timestamp(), "checkpoint": checkpoint,
                  "checkpoint_sha256": digest(checkpoint) if checkpoint else None}
        path = self.root / "bindings" / request["endpoint"] / ("%06d.json" % record["generation"])
        raw = encoded(record) + b"\n"
        self.store.admit(path, raw, self.calls.history_bytes[path.parent], MAX_HISTORY_BYTES)
        self.store.publish(path, raw)
        return {**record, "ready": not history}

    @operation(write=True, envelope=True)
    def acknowledge_handoff(self, request):
        fields(request, {"endpoint", "generation", "session", "checkpoint_sha256"})
        binding = self.current_binding(request["endpoint"])
        require(binding["generation"] > 1 and request == {key: binding[key] for key in request},
                "handoff acknowledgment does not match binding")
        records = self.messages()
        self.checkpoint(binding["checkpoint"], records)
        observed = self.checkpoint_assignments(request["endpoint"], binding["checkpoint"], records, lineage=True)
        path = self.root / "bindings" / request["endpoint"] / ("%06d.ack" % request["generation"])
        raw = encoded(request) + b"\n"
        self.store.admit(path, raw, self.calls.history_bytes[path.parent], MAX_HISTORY_BYTES)
        self.store.publish(path, raw)
        # The witness is output only: the .ack file and the immutable binding keep their strict shapes.
        return {"endpoint": request["endpoint"], "generation": request["generation"], "ready": True,
                "observed_sources": observed}

    @operation(evidence=True, authorization=(0, "request", "evidence_dir", "source_witness"), envelope=True)
    def draft_handoff(self, request):
        """Build a complete replacement binding request from the record, so no model has to author one."""
        bounded_tree(request)
        fields(request, {"endpoint", "host", "session", "outgoing_stopped"},
               {"completed_checks", "briefs", "evidence_dir", "delivery_dir"})
        endpoint = request["endpoint"]
        self.endpoint(endpoint)
        require(request["outgoing_stopped"] is True, "outgoing session must be stopped before replacement")
        self.require_host(request["host"])
        text(request["session"], "session", 256)
        require(type(request.get("briefs", [])) is list, "invalid briefs")
        require(len(request.get("briefs", [])) <= 256, reason="too_large")
        strings(request.get("completed_checks", []), "completed checks")
        for brief in request.get("briefs", []):
            self.brief(brief)
        for name in ("evidence_dir", "delivery_dir"):
            if name in request:
                text(request[name], name)
        if "evidence_dir" in request:
            self.roles.authorize(self.caller_role, "source_witness")
            self.evidence_directory(request["evidence_dir"])
        if "delivery_dir" in request:
            self.delivery_directory(request["delivery_dir"])
            if "evidence_dir" in request:
                self.store.disjoint_directories(request["delivery_dir"], request["evidence_dir"])
        history = self.bindings(endpoint)
        require(bool(history), "endpoint has no binding to replace: " + endpoint)
        records = self.messages()
        closed, accepted = self.dispatch_history(records)
        touching = sorted((r["message"] for r in records.values() if endpoint in (r["message"]["from"], r["message"]["to"])),
                          key=lambda message: (message["created_at"], message["message_id"]))
        active = [m for m in touching if m["type"] == "dispatch" and m["message_id"] not in closed]
        briefs = []

        def add_brief(brief):
            if brief not in briefs:
                briefs.append(brief)

        jobs = [job for job in self.open_job_requests(records) if endpoint in (job["from"], job["to"])]
        for assignment in active + jobs:
            add_brief(assignment["brief"])
        for brief in request.get("briefs", []):
            add_brief(brief)
        for brief in (history[-1]["checkpoint"] or {}).get("briefs", []):
            add_brief(brief)
        for message in reversed(touching):
            if "brief" in message:
                add_brief(message["brief"])
                break
        pending, lease_refs, sources, worktrees = [], [], [], set()
        for dispatch in active:
            pending.append(dispatch["message_id"])
            readiness = next((m["readiness"] for m in accepted
                              if m["in_reply_to"] == dispatch["message_id"] and "readiness" in m), None)
            if readiness is None:
                continue
            if readiness["lease_ref"] not in lease_refs:
                lease_refs.append(readiness["lease_ref"])
            if readiness["worktree"] not in worktrees:
                worktrees.add(readiness["worktree"])
                sources.append(self.source_witness(readiness["worktree"]))
        pending.extend(job["message_id"] for job in jobs)
        if "delivery_dir" in request:
            delivery, _ = self.endpoint_delivery(request["delivery_dir"], endpoint, records)
            # The status summary is capped for display. A handoff must retain every unread obligation.
            unread = [identifier for identifier, row in delivery.items() if row["state"] != "read"]
            pending.extend(identifier for identifier in unread if identifier not in pending)
            # Keep ordinary unread briefs on the paged inbox surface; making all of them mandatory
            # checkpoint metadata could prevent the successor from reading even its first page.
        require(len(pending) <= 256, "handoff exceeds 256 pending messages")
        require(len(briefs) <= 256, "handoff exceeds 256 brief references")
        acknowledgments = [m["message_id"] for m in touching if m["type"] == "ack"]
        checkpoint = {"outgoing_stopped": True, "briefs": briefs, "sources": sources, "lease_refs": lease_refs,
                      "completed_checks": request.get("completed_checks", []), "pending_message_ids": pending,
                      "last_acknowledgment_ids": acknowledgments[-MAX_RECENT_ACKNOWLEDGMENTS:]}
        self.checkpoint(checkpoint, records)
        self.checkpoint_assignments(endpoint, checkpoint, records)
        if "evidence_dir" in request:
            sources[:] = witnesses(self.store, [source["worktree"] for source in sources],
                                   request["evidence_dir"], self.host_call, expected=sources)
        result = {"endpoint": endpoint, "host": request["host"], "session": request["session"],
                  "expected_generation": len(history), "checkpoint": checkpoint}
        return result

    @operation(write=False)
    def readiness(self, readiness, *, observe=True):
        fields(readiness, {"worktree", "branch", "base_revision", "lease_ref", "lease_oid", "lease_expires_at",
                           "owned_paths", "scan_workspace", "scan_evidence", "enforcement_tier", "hook_evidence"})
        worktree = safe_path(text(readiness["worktree"], "worktree"))
        text(readiness["branch"], "branch", 256)
        matching(readiness["base_revision"], GIT_ID, "base revision")
        matching(readiness["lease_oid"], GIT_ID, "lease oid")
        require(isinstance(readiness["lease_ref"], str) and re.fullmatch(r"refs/aegis/lanes/[a-z0-9][a-z0-9_-]{0,79}",
                                                                       readiness["lease_ref"]), "invalid lease ref")
        expiry = parse_time(readiness["lease_expires_at"])
        strings(readiness["owned_paths"], "owned paths", nonempty=True)
        for pattern in readiness["owned_paths"]:
            require(not pattern.startswith(("/", "\\")) and ":" not in pattern and "\\" not in pattern
                    and ".." not in pattern.split("/"),
                    "owned paths must be repository relative")
        require(safe_path(text(readiness["scan_workspace"], "scan workspace")) == worktree,
                "scan workspace does not match lane worktree")
        for name in ("scan_evidence", "hook_evidence"):
            text(readiness[name], name)
        require(isinstance(readiness["enforcement_tier"], str) and readiness["enforcement_tier"] in {"advisory", "best-effort"},
                "invalid enforcement tier")
        if not observe:
            return
        require(self.host_call("observe_readiness", readiness) is True, reason="host_unavailable")
        require(expiry > self.now(), "readiness lease has expired")
        require(Path(self.git(worktree, "rev-parse", "--show-toplevel")) == worktree,
                "readiness must name the exact worktree root")
        require(self.git(worktree, "branch", "--show-current") == readiness["branch"],
                "readiness branch does not match worktree")
        self.git(worktree, "merge-base", "--is-ancestor", readiness["base_revision"], "HEAD")

    @operation(write=False)
    def completion(self, result, kind):
        require(result is not None, "lane completion requires source and check evidence")
        fields(result, {"source_revision", "source_tree", "checks"}, {"lane_check"})
        matching(result["source_revision"], GIT_ID, "source revision")
        matching(result["source_tree"], GIT_ID, "source tree")
        require(isinstance(result["checks"], list) and 0 < len(result["checks"]) <= 256, "completion requires checks")
        for check in result["checks"]:
            fields(check, {"check", "outcome", "reference"})
            for name in check:
                text(check[name], "check " + name)
            require(check["outcome"] in {"pass", "fail", "not_run", "partial"}, "invalid check outcome")
        if kind != "reviewer":
            text(result.get("lane_check"), "lane check reference")
        elif "lane_check" in result:
            text(result["lane_check"], "lane check reference")

    @operation(write=True, envelope=True)
    def publish(self, request):
        destination = self.validate_message(request)
        records = self.messages()
        require(request["message_id"] not in records, "message_id already exists: " + request["message_id"])
        require(len(records) < MAX_RECORDS, "mailbox history limit reached")
        self.fence(request)
        recipient, history = self._current_binding(request["to"])
        if request["type"] == "dispatch":
            require(self._ready(recipient, history), "recipient has not acknowledged its handoff checkpoint")
        original = self.reply(request, records) if "in_reply_to" in request else None
        if request["type"] == "job_receipt":
            require(original["type"] == "job_request", "job receipt must reply to a job request")
            require(any(job["message_id"] == original["message_id"] for job in self.open_job_requests(records)),
                    "job request already has a terminal receipt")
        kind = self.endpoint(request["from"]).get("kind")
        stage = request.get("acknowledgment")
        observed_git = False
        closed, accepted = self.dispatch_history(records)
        if stage == "accepted" and original["type"] == "dispatch":
            require(original["message_id"] not in closed, "dispatch is already completed")
            require(not any(m["in_reply_to"] == original["message_id"] for m in accepted), "dispatch is already accepted")
            self.brief(original["brief"])
            if kind != "reviewer":
                require("readiness" in request, "writing lane acceptance requires readiness")
                self.readiness(request["readiness"])
                active = [m for m in accepted if "readiness" in m and m["in_reply_to"] not in closed]
                require(not any(m["from"] == request["from"] for m in active), "writing lane already has an accepted dispatch")
                require(len(active) < self.manifest["writer_limit"], "concurrent writer limit reached")
                require(not any(any(m["readiness"][key] == request["readiness"][key]
                                    for key in ("worktree", "branch", "lease_ref")) for m in active),
                        "writing lanes must use separate worktrees, branches and leases")
                observed_git = True
        elif "readiness" in request:
            raise MailboxRefusal("invalid_record")
        completing = request["type"] in {"result", "review"} or (stage == "completed" and original["type"] == "dispatch")
        if completing:
            require(kind is not None and original is not None and original["type"] == "dispatch",
                    "lane completion must reply to its dispatch")
            self.completion(request.get("result"), kind)
            self.brief(original["brief"])
            require(original["message_id"] not in closed, "dispatch is already completed")
            require(any(m["in_reply_to"] == original["message_id"] for m in accepted), "dispatch has not been accepted")
        elif "result" in request:
            raise MailboxRefusal("invalid_record")
        message = {**request, "schema": "aegis.mailbox/v1", "created_at": self.timestamp(),
                   "authority": "information_only", "verification": dict(VERIFICATION)}
        if observed_git:
            message["verification"]["git_identity"] = "observed"
        header = {key: value for key, value in message.items() if key != "body"}
        header_raw = encoded(header)
        body_size = sum(1 if ord(c) < 128 else 2 if ord(c) < 2048 else 3 if ord(c) < 65536 else 4
                        for c in message["body"])
        require(10 + len(header_raw) + body_size <= MAX_BYTES, reason="too_large")
        raw = b"---\n" + header_raw + b"\n---\n\n" + message["body"].encode("utf-8")
        require(len(raw) <= MAX_BYTES, "message exceeds 262144 bytes")
        stamp = self.now().strftime("%Y%m%dT%H%M%S%fZ")
        name = "-".join((stamp, request["from"].split("/")[1], "to", request["to"].split("/")[1], request["message_id"]))
        path = destination / (name + ".md")
        self.store.admit(path, raw, self.calls.history_bytes["messages"], MAX_HISTORY_BYTES)
        self.store.publish(path, raw)
        return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "message": message}

    @operation(write=False, envelope=True)
    def status(self):
        records = self.messages()
        bindings = {}
        for endpoint in self.manifest["endpoints"]:
            history = self.bindings(endpoint)
            bindings[endpoint] = {**history[-1], "ready": self._ready(history[-1], history)} if history else None
        counts = {"by_host": {}, "by_endpoint": {}}
        for record in records.values():
            message = record["message"]
            for category, field in (("by_host", "host"), ("by_endpoint", "from")):
                key = message[field]
                counts[category][key] = counts[category].get(key, 0) + 1
        closed, accepted = self.dispatch_history(records)
        writers = [{"endpoint": m["from"], "dispatch": m["in_reply_to"], "accepted_host": m["host"],
                    "accepted_generation": m["binding_generation"]}
                   for m in accepted if "readiness" in m and m["in_reply_to"] not in closed]
        return {"schema": "aegis.hierarchy-status/v1", "manifest_sha256": digest(self.manifest),
                "bindings": bindings, "messages": len(records), "verification": dict(VERIFICATION),
                "mailbox_message_counts": counts, "accepted_writers": writers,
                "open_job_requests": [{key: job[key] for key in ("message_id", "from", "to", "created_at")}
                                      for job in self.open_job_requests(records)][:MAX_DELIVERY_IDS],
                "native_enforcement_ready": False, "manager_membership": "unchanged"}

    @operation(write=False, envelope=True)
    def inbox(self, endpoint, *, include_briefs=False, limit=20, after=None):
        """Validate and expand the count-limited result before transport byte paging."""
        self.endpoint(endpoint)
        integer(limit, "inbox limit", maximum=100)
        records = sorted((r for r in self.messages().values() if r["message"]["to"] == endpoint),
                         key=lambda r: (r["message"]["created_at"], r["message"]["message_id"]))
        if after is not None:
            matching(after, SLUG, "after message id")
            positions = [i for i, r in enumerate(records) if r["message"]["message_id"] == after]
            require(bool(positions), "inbox cursor does not name a received message")
            records = records[positions[0] + 1:]
        selected = records[:limit]
        if include_briefs:
            for record in selected:
                brief = record["message"].get("brief")
                if brief is not None:
                    record["brief_text"] = self.brief(brief).decode("utf-8")
        history = self.bindings(endpoint)
        binding = {**history[-1], "ready": self._ready(history[-1], history)} if history else None
        checkpoint_briefs = []
        if include_briefs and binding is not None and binding["checkpoint"] is not None:
            for brief in binding["checkpoint"]["briefs"]:
                checkpoint_briefs.append({**brief, "text": self.brief(brief).decode("utf-8")})
        return {"endpoint": endpoint, "messages": selected, "remaining": max(0, len(records) - limit),
                "binding": binding, "checkpoint_briefs": checkpoint_briefs,
                "next_after": selected[-1]["message"]["message_id"] if len(records) > limit else None}

    @operation(write=False, envelope=True)
    def binding_view(self, endpoint):
        """Startup and triage view (T23): pages ran past 100 KB, and every rotation read them.

        Each checkpoint brief is re-hashed and reported as `ok` instead of refusing, so a
        changed brief is visible here without its text. No message is returned, so an
        adapter has nothing to record as read.
        """
        self.endpoint(endpoint)
        total = sum(1 for record in self.messages().values() if record["message"]["to"] == endpoint)
        history = self.bindings(endpoint)
        binding = {**history[-1], "ready": self._ready(history[-1], history)} if history else None
        briefs = []
        for brief in binding["checkpoint"]["briefs"] if binding is not None and binding["checkpoint"] is not None else ():
            try:
                self.brief(brief)
            except (ValueError, OSError):
                briefs.append({**brief, "ok": False})
            else:
                briefs.append({**brief, "ok": True})
        return {"endpoint": endpoint, "binding": binding, "checkpoint_briefs": briefs, "messages_total": total}

    @operation()
    def git(self, worktree, *arguments):
        result = self.host_call("git", safe_path(worktree), *arguments)
        require(type(result) is str and len(result) <= MAX_BYTES, reason="host_unavailable")
        return result

    @operation()
    def git_is_ancestor(self, worktree, ancestor, descendant):
        result = self.host_call("git_is_ancestor", safe_path(worktree), ancestor, descendant)
        require(type(result) is bool, reason="host_unavailable")
        return result

    @operation(evidence=True, authorization=(1, "evidence_dir", None, "source_witness"), envelope=True)
    def source_witness(self, worktree, evidence_dir=None):
        if evidence_dir is not None:
            self.roles.authorize(self.caller_role, "source_witness")
            directory = self.evidence_directory(evidence_dir)
            return witnesses(self.store, [worktree], directory, self.host_call)[0]
        return witness_record(self.host_call("source_witness", safe_path(worktree), None), worktree)


def initialize(root, request, *, roles, caller_role):
    """Initialize only after bounded validation and explicit injected write policy."""
    require(isinstance(roles, RoleTables))
    roles.authorize(caller_role, "initialize")
    roles.validate_manifest(request)
    raw = encoded(request) + b"\n"
    require(len(raw) <= MAX_BYTES, reason="too_large")
    folders = {tuple(endpoint.split("/")[:2]) for endpoint in request["endpoints"]}
    folders |= {("across", role) for role in roles.across_roles}
    warnings = initialize_store(root, raw, sorted(folders))
    root = safe_path(root)
    result = {"root": str(root), "manifest_sha256": digest(request), "authority": "information_only"}
    if warnings:
        result["warnings"] = warnings
    return result
