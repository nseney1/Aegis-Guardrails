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
MAX_RECORDS = 10000
SLUG = re.compile(r"[a-z0-9][a-z0-9_-]{0,79}")
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_ID = re.compile(r"[0-9a-f]{40}")
MESSAGE_TYPES = {"info", "brief", "dispatch", "result", "review", "escalation", "ack"}
STAGES = {"received", "accepted", "completed"}
VERIFICATION = {"lease": "reference_only", "scan": "sender_claim", "hook": "sender_claim",
                "tests": "sender_claim", "human_approval": "not_established", "fitness_credit": 0}


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
    require(parts[1] in {"front-door", "orchestrator", "lane"}, "invalid endpoint role")
    require((parts[1] == "lane") == (len(parts) == 3), "invalid endpoint")
    if len(parts) == 3:
        matching(parts[2], SLUG, "lane id")
    return parts


def validate_manifest(manifest):
    fields(manifest, {"schema", "endpoints", "counterparts", "writer_limit"})
    require(manifest["schema"] == "aegis.hierarchy-pilot/v1", "unsupported manifest schema")
    integer(manifest["writer_limit"], "writer_limit", maximum=3)
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


def publish_file(path, raw):
    """Publish a complete file with hard-link no-replace semantics on the same FS.

    No non-atomic fallback: an unsupported filesystem fails explicitly. Same-user
    storage is not a hostile-process security boundary or authenticated transport.
    """
    require(len(raw) <= MAX_BYTES, "record exceeds 262144 bytes")
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
            {"front-door", "orchestrator"}, {"orchestrator", "lane"})
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
            fields(source, {"worktree", "source_revision", "source_tree", "dirty_state"})
            text(source["worktree"], "checkpoint worktree")
            matching(source["source_revision"], GIT_ID, "source revision")
            matching(source["source_tree"], GIT_ID, "source tree")
            text(source["dirty_state"], "dirty state")
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
        optional = {"brief", "in_reply_to", "acknowledgment", "readiness", "result"}
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

    def checkpoint_assignments(self, endpoint, checkpoint, records):
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
                observed = {"source_revision": self.git(worktree, "rev-parse", "HEAD"),
                            "source_tree": self.git(worktree, "rev-parse", "HEAD^{tree}"),
                            "dirty_state": self.git(worktree, "status", "--porcelain=v1", "--untracked-files=all") or "clean"}
                require(all(source[key] == value for key, value in observed.items()),
                        "checkpoint source snapshot does not match worktree")

    def bind(self, request):
        fields(request, {"endpoint", "host", "session", "expected_generation"}, {"checkpoint"})
        self.endpoint(request["endpoint"])
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
                "native_enforcement_ready": False, "manager_membership": "unchanged"}

    def inbox(self, endpoint, *, include_briefs=False, limit=20, after=None):
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
    for name in ("init", "bind", "publish", "ack-handoff"):
        commands.add_parser(name).add_argument("--request", "--request-file", required=True,
                                              help="Absolute path to a strict JSON request file")
    inbox = commands.add_parser("inbox")
    inbox.add_argument("--endpoint", required=True)
    inbox.add_argument("--include-briefs", action="store_true")
    inbox.add_argument("--limit", type=int, default=20)
    inbox.add_argument("--after", default=None)
    commands.add_parser("status")
    server = commands.add_parser("serve", help="Scoped mailbox-only stdio MCP adapter")
    server.add_argument("--endpoint", required=True)
    server.add_argument("--host", required=True)
    server.add_argument("--session", required=True)
    server.add_argument("--generation", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        root = safe_path(args.root)
        if args.command == "serve":
            # With -I the script directory is absent from sys.path. Add only the
            # exact reviewed sibling-tool directory, never cwd or PYTHONPATH.
            sys.dont_write_bytecode = True
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            from hierarchy_mailbox_mcp import serve

            return serve(root, args.endpoint, args.host, args.session, args.generation)
        if args.command == "init":
            result = initialize(root, read_json(args.request))
        elif args.command in {"status", "inbox"}:
            mailbox = Mailbox(root)
            if args.command == "status":
                result = mailbox.status()
            else:
                result = mailbox.inbox(args.endpoint, include_briefs=args.include_briefs,
                                       limit=args.limit, after=args.after)
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
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return 0
    except (ValueError, OSError, UnicodeError, RecursionError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    sys.exit(main())
