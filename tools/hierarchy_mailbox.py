#!/usr/bin/env python3
"""Local, host-neutral pilot convention; deliberately outside the Aegis runtime.

All acknowledgments, checkpoints and evidence are claims. This tool never claims
leases, edits implementation repositories, executes evidence, or grants approval.
Run from a source-pinned checkout; the installed Aegis distribution is unchanged.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid


MAX_BYTES = 262144
MAX_INBOX_RESPONSE_BYTES = 4194304
MAX_RECORDS = 10000
# The owner's writer ceiling (owner-writers-5, requests/root-c6-owner-decisions-20261102.json). The
# workspace ledger imports it, so a manifest and the store it is built from cannot disagree.
MAX_WRITERS = 5
SLUG = re.compile(r"[a-z0-9][a-z0-9_-]{0,79}")
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_ID = re.compile(r"[0-9a-f]{40}")
MESSAGE_TYPES = {"info", "brief", "dispatch", "result", "review", "escalation", "ack", "job_request", "job_receipt"}
STAGES = {"received", "accepted", "completed"}
JOB_STATES = {"started", "unknown", "refused", "completed", "failed"}
# "unknown" stays open on purpose: an uncertain job keeps its reservation until terminal evidence exists.
TERMINAL_JOB_STATES = {"refused", "completed", "failed"}
MAX_JOB_EVIDENCE = 64
VERIFICATION = {"lease": "reference_only", "scan": "sender_claim", "hook": "sender_claim",
                "tests": "sender_claim", "human_approval": "not_established", "fitness_credit": 0}
DELIVERY_RECEIPT = "aegis.hierarchy-delivery-receipt/v1"
WAKE_STATES = {"started", "exited", "timed_out", "failed_to_start"}
MAX_DELIVERY_IDS = 100
MAX_STATUS_EVIDENCE_BYTES = 67108864
MAX_DIRTY_ENTRIES = 100000000
GIT_STATUS_TIMEOUT_SECONDS = 60
MAX_RECENT_ACKNOWLEDGMENTS = 20
DELIVERY_MEANING = ("read means the adapter returned the message to the connection configured for this binding; "
                    "it does not prove the session understood or acted on it. woken means a host process was started "
                    "for a turn; hosts offer no handshake, so it does not prove the turn ran.")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fields(value, required, optional=()):
    require(isinstance(value, dict), "expected a JSON object")
    require(set(required) <= value.keys(), "missing fields: " + ", ".join(sorted(set(required) - value.keys())))
    require(value.keys() <= set(required) | set(optional),
            "unexpected fields: " + ", ".join(sorted(value.keys() - set(required) - set(optional))))


def text(value, label, limit=4096):
    require(isinstance(value, str) and 0 < len(value) <= limit and "\x00" not in value,
            "invalid " + label)
    return value


def integer(value, label, minimum=1, maximum=1000000):
    require(type(value) is int and minimum <= value <= maximum, "invalid " + label)
    return value


def matching(value, pattern, label):
    require(isinstance(value, str) and pattern.fullmatch(value) is not None, "invalid " + label)
    return value


def strings(value, label, *, nonempty=False):
    require(isinstance(value, list) and len(value) <= 256 and (bool(value) or not nonempty), "invalid " + label)
    for item in value:
        text(item, label)


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_time(value):
    text(value, "UTC timestamp", 64)
    require(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value) is not None,
            "invalid UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("invalid UTC timestamp") from exc
    return parsed


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def _cli_line(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def _bounded_inbox(result, render):
    """Page a fully validated count-limited inbox using its actual transport bytes.

    The caller has already checked history and expanded every requested brief in
    the count-limited selection. Byte paging must not hide any of those errors.
    Binding and checkpoint briefs are mandatory, including duplicate references.
    """
    messages = result["messages"]
    total = len(messages) + result["remaining"]

    def page(count):
        remaining = total - count
        return {**result, "messages": messages[:count], "remaining": remaining,
                "next_after": messages[count - 1]["message"]["message_id"] if count and remaining else None}

    selected = page(0)
    require(len(render(selected)) <= MAX_INBOX_RESPONSE_BYTES,
            "inbox response metadata exceeds 4194304 bytes")
    for count in range(1, len(messages) + 1):
        candidate = page(count)
        if len(render(candidate)) > MAX_INBOX_RESPONSE_BYTES:
            require(count > 1, "inbox first message cannot fit 4194304 byte response budget")
            # A complete validated message/path record adds more bytes in either
            # transport than any reduction of the bounded cursor/count fields.
            break
        selected = candidate
    return selected


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result

    def nonfinite(_value):
        raise ValueError("non-finite JSON is not supported")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def safe_path(path):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "path must be absolute without traversal")
    for part in (path, *path.parents):
        require(not part.is_symlink(), "symlink paths are not supported: " + str(part))
    return path


def read_bytes(path):
    path = safe_path(path)
    try:
        require(stat.S_ISREG(path.stat().st_mode), "input must be a regular file")
        with path.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
    except FileNotFoundError as exc:
        raise ValueError("file unavailable: " + str(path)) from exc
    require(len(raw) <= MAX_BYTES, "input exceeds 262144 bytes")
    return raw


def read_json(path):
    return strict_json(read_bytes(path).decode("utf-8"))


def endpoint_parts(endpoint):
    require(isinstance(endpoint, str), "invalid endpoint")
    parts = endpoint.split("/")
    require(len(parts) in (2, 3), "invalid endpoint")
    matching(parts[0], SLUG, "hierarchy")
    require(parts[0] not in {"across", "bindings"}, "reserved hierarchy name")
    require(parts[1] in {"front-door", "orchestrator", "root", "lane"}, "invalid endpoint role")
    require((parts[1] == "lane") == (len(parts) == 3), "invalid endpoint")
    if len(parts) == 3:
        matching(parts[2], SLUG, "lane id")
    return parts


def validate_manifest(manifest):
    fields(manifest, {"schema", "endpoints", "counterparts", "writer_limit"})
    require(manifest["schema"] == "aegis.hierarchy-pilot/v1", "unsupported manifest schema")
    integer(manifest["writer_limit"], "writer_limit", maximum=MAX_WRITERS)
    endpoints = manifest["endpoints"]
    require(isinstance(endpoints, dict) and 0 < len(endpoints) <= 256, "invalid endpoints")
    hierarchies = set()
    for endpoint, definition in endpoints.items():
        parts = endpoint_parts(endpoint)
        hierarchies.add(parts[0])
        if parts[1] == "lane":
            fields(definition, {"kind"})
            require(isinstance(definition["kind"], str) and definition["kind"] in {"implementer", "integrator", "reviewer"},
                    "invalid lane kind")
        else:
            fields(definition, set())
    for hierarchy in hierarchies:
        require(hierarchy + "/front-door" in endpoints and hierarchy + "/orchestrator" in endpoints,
                "each hierarchy requires a front door and orchestrator")
    counterparts = manifest["counterparts"]
    require(isinstance(counterparts, list) and len(counterparts) <= 256, "invalid counterparts")
    paired = set()
    for pair in counterparts:
        require(isinstance(pair, list) and len(pair) == 2 and all(isinstance(p, str) and p in endpoints for p in pair),
                "counterparts must name two endpoints")
        left, right = (endpoint_parts(p) for p in pair)
        require("root" not in (left[1], right[1]), "root endpoints cannot be counterparts")
        require(left[0] != right[0] and left[1] == right[1], "counterparts must have the same role across hierarchies")
        require(not any(p in paired for p in pair), "endpoint has more than one counterpart")
        paired.update(pair)
    return manifest


@contextmanager
def writer_lock(root):
    lock = safe_path(root / ".write.lock")
    try:
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValueError("mailbox writer is busy; inspect an abandoned lock before retrying") from exc
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded({"pid": os.getpid(), "created_at": timestamp()}))
        yield
    finally:
        lock.unlink()


def status_entries(raw):
    """Count `git status --porcelain=v1 -z` entries; a rename or copy carries an extra path field."""
    tokens = raw.split(b"\0")
    count = index = 0
    while index < len(tokens):
        token = tokens[index]
        index += 1
        if token:
            count += 1
            if token[:1] in (b"R", b"C") or token[1:2] in (b"R", b"C"):
                index += 1
    return count


def publish_status_evidence(directory, raw, sha256):
    """Content-addressed raw status, kept outside the checkpoint so its size cannot block a rotation."""
    path = safe_path(Path(directory) / (sha256 + ".status"))
    if path.exists():
        require(hashlib.sha256(path.read_bytes()).hexdigest() == sha256,
                "status evidence exists with different bytes: " + str(path))
    else:
        publish_file(path, raw, limit=MAX_STATUS_EVIDENCE_BYTES)
    return str(path)


def publish_file(path, raw, *, limit=MAX_BYTES):
    """Publish a complete file with hard-link no-replace semantics on the same FS.

    No non-atomic fallback: an unsupported filesystem fails explicitly. Same-user
    storage is not a hostile-process security boundary or authenticated transport.
    """
    require(len(raw) <= limit, "record exceeds %d bytes" % limit)
    path = safe_path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    pending = path.parent / (".pending-" + uuid.uuid4().hex)
    try:
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(pending, path)
    finally:
        if pending.exists():
            pending.unlink()


class Mailbox:
    def __init__(self, root):
        self.root = safe_path(root)
        self.manifest = validate_manifest(read_json(self.root / "manifest.json"))

    def endpoint(self, endpoint):
        endpoint_parts(endpoint)
        require(endpoint in self.manifest["endpoints"], "unknown endpoint: " + endpoint)
        return self.manifest["endpoints"][endpoint]

    def route(self, sender, recipient):
        self.endpoint(sender)
        self.endpoint(recipient)
        left, right = endpoint_parts(sender), endpoint_parts(recipient)
        vertical = left[0] == right[0] and {left[1], right[1]} in (
            {"front-door", "orchestrator"}, {"orchestrator", "lane"}, {"orchestrator", "root"})
        across = any({sender, recipient} == set(pair) for pair in self.manifest["counterparts"])
        require(vertical or across, "route is not vertical or an explicit counterpart")
        return self.root / ("across" if across else right[0]) / right[1]

    def brief(self, brief, *, verify=True):
        fields(brief, {"path", "sha256"})
        matching(brief["sha256"], SHA256, "brief sha256")
        path = safe_path(text(brief["path"], "brief path"))
        require(path.suffix == ".md", "brief must be a Markdown file")
        try:
            path.relative_to(self.root.parent)
        except ValueError as exc:
            raise ValueError("brief must be within the mailbox parent directory") from exc
        if verify:
            raw = read_bytes(path)
            require(hashlib.sha256(raw).hexdigest() == brief["sha256"], "brief sha256 mismatch")
            return raw

    def checkpoint(self, checkpoint, messages, *, verify=True):
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
            for name in ("pending_message_ids", "last_acknowledgment_ids"):
                for identifier in checkpoint[name]:
                    require(identifier in messages, "checkpoint references an unknown message")
                    if name == "last_acknowledgment_ids":
                        require(messages[identifier]["message"]["type"] == "ack", "checkpoint acknowledgment is not an ack")

    def bindings(self, endpoint):
        self.endpoint(endpoint)
        directory = safe_path(self.root / "bindings" / endpoint)
        result = []
        entries = sorted(directory.iterdir()) if directory.exists() else []
        for path in entries:
            safe_path(path)
            require(re.fullmatch(r"\d{6}\.(json|ack)", path.name) is not None or path.name.startswith(".pending-"),
                    "unexpected binding history entry")
        for path in (p for p in entries if p.suffix == ".json"):
            require(len(result) < MAX_RECORDS, "binding history exceeds record limit")
            record = read_json(path)
            fields(record, {"schema", "endpoint", "host", "session", "generation", "created_at", "checkpoint", "checkpoint_sha256"})
            require(record["schema"] == "aegis.role-binding/v1" and record["endpoint"] == endpoint,
                    "malformed role binding")
            integer(record["generation"], "binding generation")
            require(record["generation"] == len(result) + 1 and path.name == "%06d.json" % record["generation"],
                    "nonconsecutive binding history")
            text(record["host"], "host", 128)
            text(record["session"], "session", 256)
            parse_time(record["created_at"])
            if record["generation"] == 1:
                require(record["checkpoint"] is None and record["checkpoint_sha256"] is None, "invalid initial binding")
            else:
                self.checkpoint(record["checkpoint"], {}, verify=False)
                require(digest(record["checkpoint"]) == record["checkpoint_sha256"], "checkpoint digest mismatch")
            result.append(record)
        for path in (p for p in entries if p.suffix == ".ack"):
            generation = int(path.stem)
            require(1 < generation <= len(result), "handoff acknowledgment has no replacement binding")
            ack = read_json(path)
            fields(ack, {"endpoint", "generation", "session", "checkpoint_sha256"})
            require(ack == {key: result[generation - 1][key] for key in ack},
                    "handoff acknowledgment does not match binding")
        return result

    def ready(self, binding):
        if binding["generation"] == 1:
            return True
        path = safe_path(self.root / "bindings" / binding["endpoint"] / ("%06d.ack" % binding["generation"]))
        if not path.exists():
            return False
        ack = read_json(path)
        fields(ack, {"endpoint", "generation", "session", "checkpoint_sha256"})
        require(ack == {key: binding[key] for key in ack}, "handoff acknowledgment does not match binding")
        return True

    def current_binding(self, endpoint):
        history = self.bindings(endpoint)
        require(bool(history), "endpoint has no session binding: " + endpoint)
        return history[-1]

    def validate_message(self, message, *, stored=False):
        required = {"message_id", "from", "to", "host", "session", "binding_generation", "type", "body"}
        optional = {"brief", "in_reply_to", "acknowledgment", "readiness", "result", "receipt"}
        if stored:
            required |= {"schema", "created_at", "authority", "verification"}
        fields(message, required, optional)
        matching(message["message_id"], SLUG, "message_id")
        destination = self.route(message["from"], message["to"])
        text(message["host"], "host", 128)
        text(message["session"], "session", 256)
        integer(message["binding_generation"], "binding generation")
        require(isinstance(message["type"], str) and message["type"] in MESSAGE_TYPES, "unsupported message type")
        text(message["body"], "body", 65536)
        if "brief" in message:
            self.brief(message["brief"], verify=not stored)
        if "in_reply_to" in message:
            matching(message["in_reply_to"], SLUG, "in_reply_to")
        if message["type"] == "job_request":
            left, right = endpoint_parts(message["from"]), endpoint_parts(message["to"])
            require(left[0] == right[0] and left[1] == "orchestrator" and right[1] == "root",
                    "only an orchestrator can request a job from its own root")
            require("brief" in message, "job request requires a hash-bound packet")
        if message["type"] == "job_receipt":
            left, right = endpoint_parts(message["from"]), endpoint_parts(message["to"])
            require(left[1] == "root" and right[1] == "orchestrator" and "in_reply_to" in message,
                    "job receipt must come from root and reply to a job request")
            self.job_receipt(message.get("receipt"))
        elif "receipt" in message:
            raise ValueError("receipt field requires job_receipt type")
        if message["type"] in {"brief", "dispatch"}:
            require("brief" in message, "brief or dispatch message requires a brief hash")
        if message["type"] == "dispatch":
            left, right = endpoint_parts(message["from"]), endpoint_parts(message["to"])
            require(left[0] == right[0] and left[1] == "orchestrator" and right[1] == "lane",
                    "only an orchestrator can dispatch its own lane")
        if message["type"] == "ack":
            require(isinstance(message.get("acknowledgment"), str) and message["acknowledgment"] in STAGES and "in_reply_to" in message,
                    "ack requires a stage and referenced message")
        else:
            require("acknowledgment" not in message, "acknowledgment field requires ack type")
        if "readiness" in message and self.endpoint(message["from"]).get("kind") == "reviewer":
            raise ValueError("reviewer acceptance must not include writing readiness")
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

    def messages(self):
        records = {}
        folders = {self.root / endpoint.split("/")[0] / endpoint.split("/")[1]
                   for endpoint in self.manifest["endpoints"]}
        folders |= {self.root / "across" / role for role in ("front-door", "orchestrator", "lane")}
        for folder in sorted(folders):
            safe_path(folder)
            for path in sorted(folder.iterdir()):
                require(not path.is_symlink(), "symlink mailbox entry is not supported")
                if path.name.startswith(".pending-"):
                    continue
                require(path.suffix == ".md", "unexpected mailbox entry: " + str(path))
                require(len(records) < MAX_RECORDS, "mailbox exceeds record limit")
                raw = read_bytes(path).decode("utf-8")
                try:
                    require(raw.startswith("---\n"), "missing header")
                    header, body = raw[4:].split("\n---\n\n", 1)
                    message = strict_json(header)
                    message["body"] = body
                    destination = self.validate_message(message, stored=True)
                    require(destination == folder, "message is in the wrong routing folder")
                    require(message["message_id"] not in records, "duplicate message_id in history")
                    records[message["message_id"]] = {"path": str(path), "message": message}
                except (ValueError, TypeError, KeyError) as exc:
                    raise ValueError("malformed mailbox message: " + str(path) + ": " + str(exc)) from exc
        for record in records.values():
            message = record["message"]
            if "in_reply_to" in message:
                self.reply(message, records)
        return records

    @staticmethod
    def reply(message, records):
        reference = records.get(message.get("in_reply_to"))
        require(reference is not None, "referenced message does not exist")
        original = reference["message"]
        require(message["from"] == original["to"] and message["to"] == original["from"],
                "reply endpoints do not reverse the referenced message")
        return original

    @staticmethod
    def dispatch_history(records):
        closed = {r["message"]["in_reply_to"] for r in records.values()
                  if "in_reply_to" in r["message"] and (r["message"]["type"] in {"result", "review"}
                  or (r["message"].get("acknowledgment") == "completed"
                      and records[r["message"]["in_reply_to"]]["message"]["type"] == "dispatch"))}
        accepted = [r["message"] for r in records.values() if r["message"].get("acknowledgment") == "accepted"
                    and records[r["message"]["in_reply_to"]]["message"]["type"] == "dispatch"]
        return closed, accepted

    @staticmethod
    def job_receipt(receipt):
        """Structure only. Evidence paths stay inert: nothing here reads them or trusts the claim."""
        fields(receipt, {"state"}, {"exit_code", "evidence", "reason"})
        state = receipt["state"]
        require(isinstance(state, str) and state in JOB_STATES, "invalid job state")
        exit_code = receipt.get("exit_code")
        if state == "completed":
            require(type(exit_code) is int and exit_code == 0, "completed job requires exit code 0")
        elif state == "failed":
            require(type(exit_code) is int and exit_code != 0, "failed job requires a nonzero exit code")
        else:
            require(exit_code is None or type(exit_code) is int, "invalid exit code")
        if state in {"completed", "failed"}:
            require(isinstance(receipt.get("evidence"), list) and bool(receipt["evidence"]),
                    "job receipt requires evidence")
        if state in {"refused", "unknown"}:
            require(isinstance(receipt.get("reason"), str) and bool(receipt["reason"]), "job receipt requires a reason")
        if "reason" in receipt:
            text(receipt["reason"], "reason")
        evidence = receipt.get("evidence", [])
        require(isinstance(evidence, list) and len(evidence) <= MAX_JOB_EVIDENCE, "invalid evidence list")
        for item in evidence:
            fields(item, {"path", "sha256"})
            matching(item["sha256"], SHA256, "evidence sha256")
            path = Path(text(item["path"], "evidence path"))
            require(path.is_absolute() and ".." not in path.parts, "evidence path must be absolute")

    @staticmethod
    def open_job_requests(records):
        terminal = {r["message"]["in_reply_to"] for r in records.values() if r["message"]["type"] == "job_receipt"
                    and r["message"]["receipt"]["state"] in TERMINAL_JOB_STATES}
        return sorted((r["message"] for r in records.values()
                       if r["message"]["type"] == "job_request" and r["message"]["message_id"] not in terminal),
                      key=lambda message: (message["created_at"], message["message_id"]))

    def checkpoint_assignments(self, endpoint, checkpoint, records):
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

    def wake_marker(self, endpoint):
        """Sits beside .write.lock, outside the routing folders, and is held from launch until the turn ends."""
        return safe_path(self.root / (".wake-" + endpoint.replace("/", "%2F") + ".lock"))

    def bind(self, request):
        fields(request, {"endpoint", "host", "session", "expected_generation"}, {"checkpoint"})
        self.endpoint(request["endpoint"])
        require(not self.wake_marker(request["endpoint"]).exists(),
                "a wake is in progress for this endpoint; stop it and remove its lock before replacing the session")
        text(request["host"], "host", 128)
        text(request["session"], "session", 256)
        integer(request["expected_generation"], "expected generation", minimum=0)
        history = self.bindings(request["endpoint"])
        require(request["expected_generation"] == len(history), "binding generation changed")
        require(len(history) < MAX_RECORDS, "binding history limit reached")
        checkpoint = request.get("checkpoint")
        if history:
            require(checkpoint is not None, "replacement requires a checkpoint")
            records = self.messages()
            self.checkpoint(checkpoint, records)
            self.checkpoint_assignments(request["endpoint"], checkpoint, records)
        else:
            require(checkpoint is None, "initial binding cannot contain a replacement checkpoint")
        record = {"schema": "aegis.role-binding/v1", "endpoint": request["endpoint"],
                  "host": request["host"], "session": request["session"], "generation": len(history) + 1,
                  "created_at": timestamp(), "checkpoint": checkpoint,
                  "checkpoint_sha256": digest(checkpoint) if checkpoint else None}
        path = self.root / "bindings" / request["endpoint"] / ("%06d.json" % record["generation"])
        publish_file(path, encoded(record) + b"\n")
        return {**record, "ready": self.ready(record)}

    def acknowledge_handoff(self, request):
        fields(request, {"endpoint", "generation", "session", "checkpoint_sha256"})
        binding = self.current_binding(request["endpoint"])
        require(binding["generation"] > 1 and request == {key: binding[key] for key in request},
                "handoff acknowledgment does not match binding")
        records = self.messages()
        self.checkpoint(binding["checkpoint"], records)
        self.checkpoint_assignments(request["endpoint"], binding["checkpoint"], records)
        path = self.root / "bindings" / request["endpoint"] / ("%06d.ack" % request["generation"])
        publish_file(path, encoded(request) + b"\n")
        return {"endpoint": request["endpoint"], "generation": request["generation"], "ready": True}

    @staticmethod
    def git(worktree, *arguments):
        try:
            result = subprocess.run(["git", "--no-optional-locks", "-c", "core.fsmonitor=false", *arguments],
                                    cwd=worktree, capture_output=True, text=True, timeout=5)
        except subprocess.TimeoutExpired as exc:
            raise ValueError("git identity check timed out") from exc
        require(result.returncode == 0, "git identity check failed")
        return result.stdout.rstrip("\r\n")

    def source_witness(self, worktree, evidence_dir=None):
        """Revision, tree and an exact-byte status digest. Nothing is trimmed before hashing."""
        worktree = safe_path(worktree)
        try:
            status = subprocess.run(["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "status",
                                     "--porcelain=v1", "-z", "--untracked-files=all"], cwd=worktree,
                                    capture_output=True, timeout=GIT_STATUS_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as exc:
            raise ValueError("git identity check timed out") from exc
        require(status.returncode == 0, "git identity check failed")
        sha256 = hashlib.sha256(status.stdout).hexdigest()
        witness = {"worktree": str(worktree), "source_revision": self.git(worktree, "rev-parse", "HEAD"),
                   "source_tree": self.git(worktree, "rev-parse", "HEAD^{tree}"),
                   "dirty_state_sha256": sha256, "dirty_entries": status_entries(status.stdout)}
        if evidence_dir is not None and status.stdout:
            witness["dirty_evidence"] = publish_status_evidence(evidence_dir, status.stdout, sha256)
        return witness

    def draft_handoff(self, request):
        """Build a complete replacement binding request from the record, so no model has to author one."""
        fields(request, {"endpoint", "host", "session", "outgoing_stopped"},
               {"completed_checks", "briefs", "evidence_dir", "delivery_dir"})
        endpoint = request["endpoint"]
        self.endpoint(endpoint)
        require(request["outgoing_stopped"] is True, "outgoing session must be stopped before replacement")
        text(request["host"], "host", 128)
        text(request["session"], "session", 256)
        require(isinstance(request.get("briefs", []), list), "invalid briefs")
        for name in ("evidence_dir", "delivery_dir"):
            if name in request:
                text(request[name], name)
        if "evidence_dir" in request:
            self.outside_mailbox(request["evidence_dir"], "evidence directory")
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
                sources.append(self.source_witness(readiness["worktree"], request.get("evidence_dir")))
        pending.extend(job["message_id"] for job in jobs)
        if "delivery_dir" in request:
            _, summary = self.endpoint_delivery(request["delivery_dir"], endpoint, records)
            pending.extend(identifier for identifier in summary["unread"] if identifier not in pending)
        acknowledgments = [m["message_id"] for m in touching if m["type"] == "ack"]
        checkpoint = {"outgoing_stopped": True, "briefs": briefs[:256], "sources": sources, "lease_refs": lease_refs,
                      "completed_checks": request.get("completed_checks", []), "pending_message_ids": pending[:256],
                      "last_acknowledgment_ids": acknowledgments[-MAX_RECENT_ACKNOWLEDGMENTS:]}
        self.checkpoint(checkpoint, records)
        self.checkpoint_assignments(endpoint, checkpoint, records)
        return {"endpoint": endpoint, "host": request["host"], "session": request["session"],
                "expected_generation": len(history), "checkpoint": checkpoint}

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
        require(worktree.is_dir(), "readiness worktree is unavailable")
        require(expiry > datetime.now(timezone.utc), "readiness lease has expired")
        require(Path(self.git(worktree, "rev-parse", "--show-toplevel")) == worktree,
                "readiness must name the exact worktree root")
        require(self.git(worktree, "branch", "--show-current") == readiness["branch"],
                "readiness branch does not match worktree")
        self.git(worktree, "merge-base", "--is-ancestor", readiness["base_revision"], "HEAD")

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

    def publish(self, request):
        destination = self.validate_message(request)
        records = self.messages()
        require(request["message_id"] not in records, "message_id already exists: " + request["message_id"])
        require(len(records) < MAX_RECORDS, "mailbox history limit reached")
        binding = self.current_binding(request["from"])
        require(all(request[key] == binding[source] for key, source in (
            ("binding_generation", "generation"), ("host", "host"), ("session", "session"))),
                "stale or mismatched sender binding")
        require(self.ready(binding), "handoff checkpoint has not been acknowledged")
        recipient = self.current_binding(request["to"])
        if request["type"] == "dispatch":
            require(self.ready(recipient), "recipient has not acknowledged its handoff checkpoint")
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
            raise ValueError("readiness is only valid when accepting a lane dispatch")
        completing = request["type"] in {"result", "review"} or (stage == "completed" and original["type"] == "dispatch")
        if completing:
            require(kind is not None and original is not None and original["type"] == "dispatch",
                    "lane completion must reply to its dispatch")
            self.completion(request.get("result"), kind)
            self.brief(original["brief"])
            require(original["message_id"] not in closed, "dispatch is already completed")
            require(any(m["in_reply_to"] == original["message_id"] for m in accepted), "dispatch has not been accepted")
        elif "result" in request:
            raise ValueError("result evidence requires lane completion")
        message = {**request, "schema": "aegis.mailbox/v1", "created_at": timestamp(),
                   "authority": "information_only", "verification": dict(VERIFICATION)}
        if observed_git:
            message["verification"]["git_identity"] = "observed"
        header = {key: value for key, value in message.items() if key != "body"}
        raw = b"---\n" + encoded(header) + b"\n---\n\n" + message["body"].encode("utf-8")
        require(len(raw) <= MAX_BYTES, "message exceeds 262144 bytes")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        name = "-".join((stamp, request["from"].split("/")[1], "to", request["to"].split("/")[1], request["message_id"]))
        path = destination / (name + ".md")
        publish_file(path, raw)
        return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "message": message}

    def status(self):
        records = self.messages()
        bindings = {}
        for endpoint in self.manifest["endpoints"]:
            history = self.bindings(endpoint)
            bindings[endpoint] = {**history[-1], "ready": self.ready(history[-1])} if history else None
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
        binding = {**history[-1], "ready": self.ready(history[-1])} if history else None
        checkpoint_briefs = []
        if include_briefs and binding is not None and binding["checkpoint"] is not None:
            for brief in binding["checkpoint"]["briefs"]:
                checkpoint_briefs.append({**brief, "text": self.brief(brief).decode("utf-8")})
        return {"endpoint": endpoint, "messages": selected, "remaining": max(0, len(records) - limit),
                "binding": binding, "checkpoint_briefs": checkpoint_briefs,
                "next_after": selected[-1]["message"]["message_id"] if len(records) > limit else None}

    def binding_view(self, endpoint):
        """Startup and triage view (T23): pages ran past 100 KB, and every rotation read them.

        Each checkpoint brief is re-hashed and reported as `ok` instead of refusing, so a
        changed brief is visible here without its text. No message is returned, so an
        adapter has nothing to record as read.
        """
        self.endpoint(endpoint)
        total = sum(1 for record in self.messages().values() if record["message"]["to"] == endpoint)
        history = self.bindings(endpoint)
        binding = {**history[-1], "ready": self.ready(history[-1])} if history else None
        briefs = []
        for brief in binding["checkpoint"]["briefs"] if binding is not None and binding["checkpoint"] is not None else ():
            try:
                self.brief(brief)
            except (ValueError, OSError):
                briefs.append({**brief, "ok": False})
            else:
                briefs.append({**brief, "ok": True})
        return {"endpoint": endpoint, "binding": binding, "checkpoint_briefs": briefs, "messages_total": total}

    def outside_mailbox(self, directory, label):
        """Derived files must never reach mailbox history, so overlap is refused in both directions.

        A directory above the root is unsafe too: a derived folder name can equal the root's own name.
        """
        directory = safe_path(directory)
        require(directory != self.root and self.root not in directory.parents,
                label + " must be outside the mailbox root")
        require(directory not in self.root.parents, label + " must not contain the mailbox root")
        return directory

    def delivery_directory(self, directory):
        return self.outside_mailbox(directory, "delivery directory")

    @staticmethod
    def _delivery_receipt(receipt, kind, endpoint, history, records):
        extra = {"wake_id", "state", "exit_code", "timed_out"} if kind == "wakes" else set()
        fields(receipt, {"schema", "endpoint", "host", "session", "generation", "at", "message_ids"}, extra)
        require(receipt["schema"] == DELIVERY_RECEIPT and receipt["endpoint"] == endpoint,
                "wrong receipt schema or endpoint")
        integer(receipt["generation"], "receipt generation")
        require(receipt["generation"] <= len(history) and all(
            history[receipt["generation"] - 1][key] == receipt[key] for key in ("host", "session")),
                "receipt does not match binding history")
        parse_time(receipt["at"])
        strings(receipt["message_ids"], "receipt message ids")
        for identifier in receipt["message_ids"]:
            record = records.get(identifier)
            require(record is not None and record["message"]["to"] == endpoint,
                    "receipt names a message not addressed to this endpoint")
        if kind == "wakes":
            matching(receipt.get("wake_id"), SLUG, "wake id")
            require(receipt.get("state") in WAKE_STATES, "invalid wake state")
        return receipt

    def delivery_receipts(self, directory, kind, endpoint, records):
        folder = safe_path(self.delivery_directory(directory) / kind / endpoint)
        if not folder.exists():
            return []
        history = self.bindings(endpoint)
        receipts = []
        for path in sorted(folder.iterdir()):
            safe_path(path)
            if path.name.startswith("."):
                continue
            require(len(receipts) < MAX_RECORDS, "delivery receipt history exceeds record limit")
            try:
                receipts.append(self._delivery_receipt(read_json(path), kind, endpoint, history, records))
            except (ValueError, TypeError, KeyError, UnicodeError) as exc:
                raise ValueError("malformed delivery receipt: " + str(path) + ": " + str(exc)) from exc
        return receipts

    def require_receipt_room(self, directory, kind, endpoint, needed=1):
        folder = safe_path(self.delivery_directory(directory) / kind / endpoint)
        count = sum(1 for path in folder.iterdir() if not path.name.startswith(".")) if folder.exists() else 0
        require(count + needed <= MAX_RECORDS, "delivery receipt history limit reached")

    def write_delivery_receipt(self, directory, kind, receipt):
        folder = safe_path(self.delivery_directory(directory) / kind / receipt["endpoint"])
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Each ledger has its own lock, so adapter reads never contend with mailbox publishers. Past
        # the limit the reader would refuse the whole ledger, so a full one refuses here instead.
        with writer_lock(folder):
            self.require_receipt_room(directory, kind, receipt["endpoint"])
            name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex + ".json"
            publish_file(folder / name, encoded({"schema": DELIVERY_RECEIPT, "at": timestamp(), **receipt}) + b"\n")

    def record_read(self, directory, sender, message_ids):
        """Record what the adapter returned to this connection, never what the session did with it."""
        endpoint = sender["from"]
        records = self.messages()
        seen = {identifier for receipt in self.delivery_receipts(directory, "reads", endpoint, records)
                if receipt["generation"] == sender["binding_generation"] for identifier in receipt["message_ids"]}
        fresh = [identifier for identifier in message_ids if identifier not in seen]
        if fresh:
            self.write_delivery_receipt(directory, "reads", {
                "endpoint": endpoint, "host": sender["host"], "session": sender["session"],
                "generation": sender["binding_generation"], "message_ids": fresh})

    def endpoint_delivery(self, directory, endpoint, records):
        """Per-message rows and an endpoint summary; published, woken and read stay separate."""
        reads = self.delivery_receipts(directory, "reads", endpoint, records)
        wakes = self.delivery_receipts(directory, "wakes", endpoint, records)
        failed = {wake["wake_id"] for wake in wakes if wake["state"] == "failed_to_start"}
        read_at, read_by, woken_at = {}, {}, {}
        for receipt in reads:
            for identifier in receipt["message_ids"]:
                if identifier not in read_at:
                    read_at[identifier] = receipt["at"]
                    read_by[identifier] = {key: receipt[key] for key in ("host", "session", "generation")}
        for wake in wakes:
            if wake["state"] == "started" and wake["wake_id"] not in failed:
                for identifier in wake["message_ids"]:
                    woken_at.setdefault(identifier, wake["at"])
        incoming = sorted((r["message"] for r in records.values() if r["message"]["to"] == endpoint),
                          key=lambda message: (message["created_at"], message["message_id"]))
        rows = {}
        for message in incoming:
            identifier = message["message_id"]
            state = "read" if identifier in read_at else "woken" if identifier in woken_at else "published"
            rows[identifier] = {"message_id": identifier, "to": endpoint, "state": state,
                                "published_at": message["created_at"], "woken_at": woken_at.get(identifier),
                                "read_at": read_at.get(identifier), "read_by": read_by.get(identifier)}
        unread = [message["message_id"] for message in incoming if message["message_id"] not in read_at]
        history = self.bindings(endpoint)
        binding = None
        if history:
            binding = {"host": history[-1]["host"], "session": history[-1]["session"],
                       "generation": history[-1]["generation"], "ready": self.ready(history[-1])}
        last_wake = None
        if wakes:
            last_wake = {key: wakes[-1].get(key) for key in ("wake_id", "state", "at", "exit_code", "timed_out")}
        return rows, {"binding": binding, "published": len(incoming), "read": len(incoming) - len(unread),
                      "unread_count": len(unread), "unread": unread[:MAX_DELIVERY_IDS],
                      "woken_unread": [i for i in unread if i in woken_at][:MAX_DELIVERY_IDS],
                      "oldest_unread_at": rows[unread[0]]["published_at"] if unread else None,
                      "last_read_at": reads[-1]["at"] if reads else None, "last_wake": last_wake}

    def delivery(self, directory, endpoint=None, message_id=None):
        self.delivery_directory(directory)
        records = self.messages()
        answer = {"schema": "aegis.hierarchy-delivery/v1", "meaning": DELIVERY_MEANING}
        if message_id is not None:
            matching(message_id, SLUG, "message id")
            require(message_id in records, "unknown message: " + message_id)
            rows, _ = self.endpoint_delivery(directory, records[message_id]["message"]["to"], records)
            return {**answer, "message": rows[message_id]}
        if endpoint is not None:
            self.endpoint(endpoint)
        names = [endpoint] if endpoint is not None else sorted(self.manifest["endpoints"])
        return {**answer, "endpoints": {name: self.endpoint_delivery(directory, name, records)[1] for name in names}}


def initialize(root, request):
    validate_manifest(request)
    root = safe_path(root)
    require(not root.exists(), "mailbox root already exists")
    root.mkdir(mode=0o700)
    with writer_lock(root):
        for endpoint in request["endpoints"]:
            (root / endpoint.split("/")[0] / endpoint.split("/")[1]).mkdir(parents=True, exist_ok=True, mode=0o700)
        for role in ("front-door", "orchestrator", "lane"):
            (root / "across" / role).mkdir(parents=True, mode=0o700)
        publish_file(root / "manifest.json", encoded(request) + b"\n")
    return {"root": str(root), "manifest_sha256": digest(request), "authority": "information_only"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, help="Absolute path to the external pilot mailbox")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "bind", "publish", "ack-handoff", "draft-handoff"):
        commands.add_parser(name).add_argument("--request", "--request-file", required=True,
                                              help="Absolute path to a strict JSON request file")
    inbox = commands.add_parser("inbox")
    inbox.add_argument("--endpoint", required=True)
    inbox.add_argument("--include-briefs", action="store_true")
    inbox.add_argument("--binding-only", action="store_true",
                       help="Only the binding, a hash check per checkpoint brief and the message count; no messages")
    inbox.add_argument("--limit", type=int, default=None)
    inbox.add_argument("--after", default=None)
    inbox.add_argument("--delivery-dir", default=None, help="With --mark-read, where root's read receipts go")
    inbox.add_argument("--mark-read", action="store_true", help="Root only: record what this page returned as read")
    commands.add_parser("status")
    delivery = commands.add_parser("delivery", help="Report published, woken and read states separately")
    delivery.add_argument("--delivery-dir", required=True)
    delivery.add_argument("--endpoint", default=None)
    delivery.add_argument("--message-id", default=None)
    server = commands.add_parser("serve", help="Scoped mailbox-only stdio MCP adapter")
    server.add_argument("--endpoint", required=True)
    server.add_argument("--host", required=True)
    server.add_argument("--session", required=True)
    server.add_argument("--generation", required=True, type=int)
    server.add_argument("--delivery-dir", default=None, help="Record read receipts here; omitted means no receipts")
    server.add_argument("--workspace-store", default=None, help="Offer this role's read-only workspace views")
    server.add_argument("--initiative", default=None, help="The initiative these views belong to")
    server.add_argument("--board", default=None, help="Serve only the workspace board tools, from this board folder")
    args = parser.parse_args(argv)
    try:
        root = safe_path(args.root)
        if args.command == "serve":
            # With -I the script directory is absent from sys.path. Add only the
            # exact reviewed sibling-tool directory, never cwd or PYTHONPATH.
            sys.dont_write_bytecode = True
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            from hierarchy_mailbox_mcp import serve

            return serve(root, args.endpoint, args.host, args.session, args.generation, delivery_dir=args.delivery_dir,
                         workspace_store=args.workspace_store, initiative=args.initiative, board=args.board)
        if args.command == "init":
            result = initialize(root, read_json(args.request))
        elif args.command == "draft-handoff":
            result = Mailbox(root).draft_handoff(read_json(args.request))
        elif args.command in {"status", "inbox", "delivery"}:
            mailbox = Mailbox(root)
            if args.command == "status":
                result = mailbox.status()
            elif args.command == "delivery":
                result = mailbox.delivery(args.delivery_dir, endpoint=args.endpoint, message_id=args.message_id)
            elif args.binding_only:
                require(not (args.include_briefs or args.limit is not None or args.after is not None or args.mark_read),
                        "--binding-only takes no --include-briefs, --limit, --after or --mark-read")
                result = mailbox.binding_view(args.endpoint)
            else:
                if args.mark_read:
                    require(args.delivery_dir is not None, "--mark-read needs --delivery-dir")
                    require(endpoint_parts(args.endpoint)[1] == "root",
                            "only root reads through the CLI with a receipt; a session's adapter records its own")
                result = mailbox.inbox(args.endpoint, include_briefs=args.include_briefs,
                                       limit=20 if args.limit is None else args.limit, after=args.after)
                result = _bounded_inbox(result, _cli_line)
        else:
            with writer_lock(root):
                mailbox = Mailbox(root)
                request = read_json(args.request)
                if args.command == "bind":
                    result = mailbox.bind(request)
                elif args.command == "ack-handoff":
                    result = mailbox.acknowledge_handoff(request)
                else:
                    result = mailbox.publish(request)
        sys.stdout.buffer.write(_cli_line(result))
        if args.command == "inbox" and args.mark_read:
            # Root has no adapter, so this does the adapter's job in the same order: flushed first,
            # and a lost receipt only means root sees the message listed as unread again.
            sys.stdout.buffer.flush()
            binding = result["binding"]
            try:
                mailbox.record_read(args.delivery_dir, {"from": args.endpoint, "host": binding["host"], "session": binding["session"],
                                                        "binding_generation": binding["generation"]},
                                    [row["message"]["message_id"] for row in result["messages"]])
            except (ValueError, OSError, UnicodeError) as exc:
                print("read receipt not recorded: " + str(exc), file=sys.stderr, flush=True)
        return 0
    except (ValueError, OSError, UnicodeError, RecursionError) as exc:
        sys.stdout.buffer.write(_cli_line({"error": str(exc)}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
