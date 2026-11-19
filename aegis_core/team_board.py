"""Validated board over TA-1a descriptor storage and injected owner policy.

Posts are untrusted information. No tools imports, processes or implicit clocks.
Use Board as a context manager; initialize creates the complete legacy wire tree.
"""
from __future__ import annotations

from contextlib import contextmanager, nullcontext, ExitStack
from datetime import datetime, timedelta, timezone
from functools import wraps
import hashlib
import os
import re
from threading import local
from types import MappingProxyType
import uuid

from aegis_core.primitives import sanitize_display
from aegis_core.redaction import SECRET_REPLACEMENTS, guidance_value
from aegis_core import team_mailbox_store as mailbox_storage
from aegis_core.team_mailbox_primitives import (
    render_mailbox_refusal,
    BusyError, MailboxRefusal, RoleTables, MAX_BYTES, MAX_RECORDS, MAX_HISTORY_BYTES,
    SHA256, GIT_ID, SLUG, bounded_tree, encoded, fields, integer, matching,
    parse_time, require, safe_path, strict_json, text, validation,
)
from aegis_core.team_mailbox_store import Store

__all__ = ["Board", "initialize", "MailboxRefusal", "BusyError", "digest_text"]

SCHEMA = "aegis.hierarchy-board-event/v1"
# Every field has a budget so that the largest legal post, at worst-case escaping, fits a page alone.
# Otherwise a reader's cursor could never pass it.
MAX_PAGE_BYTES = 32768
MAX_BODY_BYTES = 4096
MAX_REFERENCES = 8
MAX_REFERENCE_BYTES = 256
MAX_DESCRIPTION_BYTES = 128
MAX_NOTE_BYTES = 128
MAX_LISTED_BLOCKERS = 16
DEFAULT_PAGE_POSTS = 20
MAX_PAGE_POSTS = 50
RATE_LIMIT_ACTIONS = 30
RATE_WINDOW_SECONDS = 60
DIGEST_RECENT_POSTS = 50
DIGEST_LINE_CHARS = 160
KINDS = ("note", "blocker")
REFERENCE_KINDS = ("file", "url", "revision")
ACCESS = ("read", "post")
# One answer for forbidden and missing, so a refusal says nothing about what exists.
NOT_AVAILABLE = "that channel or post is not available to this endpoint"
CLOSING = ("resolved", "withdrawn")
EVENT_NAME = re.compile(r"(\d{8})\.json")
# Newline and tab stay. C0, DEL, C1 and bidirectional overrides can hide or reorder text for a reader.
FORBIDDEN = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f‪-‮⁦-⁩]")


@validation
def clean_text(value, label, limit):
    """Reject key-shaped credentials as written (whitespace runs as one space); deliberate transformations are out of scope, as in the legacy board."""
    require(type(value) is str)
    require(len(value) <= limit, reason="too_large")
    text(value, label, limit)
    require(len(value.encode("utf-8")) <= limit, reason="too_large")
    require(FORBIDDEN.search(value) is None)
    for view in (value, re.sub(r"\s+", " ", value)):
        require(not any(pattern.search(view) for pattern, _ in SECRET_REPLACEMENTS))
    return value


def clean_reference(reference):
    bounded_tree(reference)
    fields(reference, {"kind", "value"}, {"sha256", "description"})
    require(isinstance(reference["kind"], str) and reference["kind"] in REFERENCE_KINDS, "invalid reference kind")
    clean_text(reference["value"], "reference value", MAX_REFERENCE_BYTES)
    if reference["kind"] == "revision":
        matching(reference["value"], GIT_ID, "revision value")
    if "sha256" in reference:
        matching(reference["sha256"], SHA256, "reference sha256")
    if "description" in reference:
        clean_text(reference["description"], "reference description", MAX_DESCRIPTION_BYTES)


def checked_time(value, label):
    return parse_time(value)


def checked_endpoint(value, roles):
    require(roles.endpoint_parts(value)[1] != "root")
    return value


class State:
    """Rebuilt by replaying immutable records. Every rule runs on replay too, so damage fails loudly."""

    def __init__(self, roles):
        self.roles = roles
        self.seq = 0
        self.ready = False
        self.channels = {}
        self.posts = {}
        self.keys = {}
        self.activity = {}

    def access(self, channel, endpoint):
        found = self.channels.get(channel) if isinstance(channel, str) else None
        return found["grants"].get(endpoint) if found else None

    def channel_posts(self, channel):
        return [post for post in self.posts.values() if post["channel"] == channel]

    def post_for(self, identifier, endpoint):
        post = self.posts.get(identifier) if isinstance(identifier, str) else None
        require(post is not None and self.access(post["channel"], endpoint) is not None, NOT_AVAILABLE)
        return post

    def channel(self, name):
        require(isinstance(name, str) and name in self.channels, "unknown channel: " + str(name)[:128])
        return self.channels[name]

    def apply(self, kind, data, event):
        require(kind == "init" or self.ready, "board is not initialized")
        validate_data(self, kind, data)
        APPLY[kind](self, data, event)
        self.seq = event["seq"]
        if kind in ("post", "disposition"):
            self.activity.setdefault(data["from"], []).append(event["at"])


def is_open(post):
    return post["kind"] == "blocker" and (post["disposition"] is None or post["disposition"]["state"] not in CLOSING)


def apply_init(state, data, _event):
    fields(data, set())
    require(not state.ready, "board is already initialized")
    state.ready = True


def apply_channel(state, data, _event):
    fields(data, {"channel", "orchestrator", "source"})
    matching(data["channel"], SLUG, "channel")
    checked_endpoint(data["orchestrator"], state.roles)
    text(data["source"], "source")
    require(data["channel"] not in state.channels, "channel already exists: " + data["channel"])
    state.channels[data["channel"]] = {"orchestrator": data["orchestrator"], "grants": {data["orchestrator"]: "post"}}


def apply_grant(state, data, _event):
    fields(data, {"channel", "endpoint", "access", "source"})
    channel = state.channel(data["channel"])
    checked_endpoint(data["endpoint"], state.roles)
    require(isinstance(data["access"], str) and data["access"] in ACCESS, "invalid access")
    text(data["source"], "source")
    channel["grants"][data["endpoint"]] = data["access"]


def apply_revoke(state, data, _event):
    fields(data, {"channel", "endpoint", "source"})
    channel = state.channel(data["channel"])
    text(data["source"], "source")
    require(data["endpoint"] in channel["grants"], "endpoint has no grant here: " + str(data["endpoint"])[:256])
    del channel["grants"][data["endpoint"]]


def apply_post(state, data, event):
    fields(data, {"post_id", "channel", "from", "key", "kind", "content_sha256"}, {"thread", "expires_at"})
    require(data["post_id"] == "post-%08d" % event["seq"], "wrong post id")
    require(state.access(data["channel"], data["from"]) == "post", "post without post access")
    matching(data["key"], SLUG, "key")
    require(data["kind"] in KINDS, "invalid kind")
    matching(data["content_sha256"], SHA256, "content sha256")
    root = data["post_id"]
    if "thread" in data:
        parent = state.posts.get(data["thread"])
        require(parent is not None and parent["channel"] == data["channel"], "reply to an unknown post")
        root = parent["thread_root"]
    if "expires_at" in data:
        checked_time(data["expires_at"], "expires_at")
    identity = (data["channel"], data["from"], data["key"])
    require(identity not in state.keys, "duplicate key")
    state.keys[identity] = data["post_id"]
    state.posts[data["post_id"]] = {**data, "seq": event["seq"], "at": event["at"], "thread_root": root, "disposition": None,
                                    "tombstone": False}


def apply_disposition(state, data, event):
    fields(data, {"post_id", "state", "from"}, {"note"})
    post = state.posts.get(data["post_id"])
    require(post is not None and post["kind"] == "blocker", "disposition on something other than a blocker")
    channel = state.channels[post["channel"]]
    require(data["from"] in (post["from"], channel["orchestrator"]), "disposition by another endpoint")
    record = {"state": data["state"], "by": data["from"], "at": event["at"]}
    if "note" in data:
        record["note"] = data["note"]
    post["disposition"] = record


def apply_tombstone(state, data, _event):
    fields(data, {"post_id", "reason", "source"})
    post = state.posts.get(data["post_id"])
    require(post is not None and not post["tombstone"], "tombstone on an unknown or removed post")
    post["tombstone"] = True


APPLY = {"init": apply_init, "channel": apply_channel, "grant": apply_grant, "revoke": apply_revoke, "post": apply_post,
         "disposition": apply_disposition, "tombstone": apply_tombstone}


def event_digest(event):
    return hashlib.sha256(encoded({key: value for key, value in event.items() if key != "digest"})).hexdigest()


def validate_data(state, kind, data):
    """Validate replay fields before hashing or indexing them."""
    bounded_tree(data)
    require(type(kind) is str and kind in APPLY and type(data) is dict)
    for name in ("post_id", "thread"):
        if name in data:
            matching(data[name], re.compile(r"post-[0-9]{8}"), name)
    for name in ("from", "endpoint", "orchestrator"):
        if name in data:
            checked_endpoint(data[name], state.roles)
    if "channel" in data:
        matching(data["channel"], SLUG, "channel")
    if kind == "post":
        require(type(data.get("kind")) is str and data["kind"] in KINDS)
    if kind == "disposition":
        require(type(data.get("state")) is str and data["state"] in (*CLOSING, "reopened"))
        post = state.posts.get(data.get("post_id"))
        require(post is not None and state.access(post["channel"], data.get("from")) == "post")
        require((data["state"] == "reopened") != is_open(post))
        if "note" in data:
            clean_text(data["note"], "note", MAX_NOTE_BYTES)
    if kind == "tombstone":
        clean_text(data.get("reason"), "reason", MAX_NOTE_BYTES)
        text(data.get("source"), "source")


def board_operation(write=False):
    """Authorize before exclusion; normalize all expected operational failures."""
    def decorate(function):
        @wraps(function)
        def call(self, *args, **kwargs):
            try:
                require(self.store.fd is not None, reason="closed")
                for value in (*args, *kwargs.values()):
                    if type(value) in (dict, list, tuple, str):
                        bounded_tree(value)
                if write:
                    self.roles.authorize(self.caller_role, function.__name__)
                self._cursor_arguments(function.__name__, args, kwargs)
                with self.lock() if write else nullcontext():
                    with self.anchors():
                        if not write:
                            return function(self, *args, **kwargs)
                        undo = []
                        with self.store.directory(self.events, undo=undo,
                                                  parent=self.calls.directories[self.events], held=True):
                            self.calls.event_undo = undo
                            try:
                                result = function(self, *args, **kwargs)
                            finally:
                                self.calls.event_undo = None
                # Both board and owner exclusions have now exited. A warning
                # describes a committed result, never a failed publication.
                warnings = self.store.drain_warnings()
                if warnings:
                    result = {**({} if result is None else result), "warnings": warnings}
                return result
            except MailboxRefusal as error:
                render_mailbox_refusal(error, reraise=True)
            except OSError:
                raise MailboxRefusal("io") from None
            except (ValueError, KeyError, UnicodeError, RecursionError, OverflowError):
                raise MailboxRefusal("invalid_record") from None
        return call
    return decorate


@validation
def initialize(path, *, clock, roles, hosts, caller_role):
    """Create a complete board or roll back only entries created by this call."""
    require(isinstance(roles, RoleTables) and callable(clock) and type(hosts) is dict and bool(hosts))
    roles.authorize(caller_role, "initialize")
    require(mailbox_storage.descriptor_supported(), reason="unsupported_platform")
    path = safe_path(path)
    moment = clock()
    require(isinstance(moment, datetime) and moment.tzinfo is not None)
    event = {"schema": SCHEMA, "seq": 1, "at": moment.astimezone(timezone.utc).isoformat(
        timespec="microseconds").replace("+00:00", "Z"), "kind": "init", "data": {}, "prev": None}
    event["digest"] = event_digest(event)
    with Store.from_parent(path.parent) as store, store.creation("mailbox"), store.evidence_transaction():
        require(not store.exists(path), reason="exists")
        with store.directory(path, create=True, undo=[]) as root, ExitStack() as stack:
            for name in ("content", "positions", "events"):
                undo = []
                fd = stack.enter_context(store.directory(path / name, create=True, undo=undo, parent=root))
                if name == "events":
                    store.publish(path / name / "00000001.json", encoded(event) + b"\n", parent=fd, undo=undo)
    result = {"board": guidance_value(str(path), limit=1024, canonicalize=sanitize_display)}
    warnings = store.drain_warnings()
    if warnings:
        result["warnings"] = warnings
    return result


class Board:
    writer_guard = staticmethod(nullcontext)

    def __init__(self, path, *, clock, roles, hosts, caller_role):
        require(isinstance(roles, RoleTables) and callable(clock) and type(hosts) is dict and bool(hosts))
        require(mailbox_storage.descriptor_supported(), reason="unsupported_platform")
        self.roles, self.clock, self.caller_role = roles, clock, caller_role
        self.hosts = MappingProxyType(dict(hosts))
        self.path = safe_path(path)
        self.events, self.content, self.positions = (self.path / name for name in ("events", "content", "positions"))
        self.store = Store(self.path)
        self.calls = local()

    def __enter__(self):
        self.store.__enter__()
        return self

    def __exit__(self, *error):
        self.close()

    def close(self):
        self.store.close()

    def now(self):
        if getattr(self.calls, "moment", None) is not None:
            return self.calls.moment
        moment = self.clock()
        require(isinstance(moment, datetime) and moment.tzinfo is not None)
        return moment.astimezone(timezone.utc)

    def timestamp(self):
        return self.now().isoformat(timespec="microseconds").replace("+00:00", "Z")

    @contextmanager
    def anchors(self):
        if getattr(self.calls, "directories", None) is not None:
            yield
            return
        with ExitStack() as stack:
            self.calls.directories = {}
            try:
                self.calls.moment = self.now()
                for path in (self.events, self.content, self.positions):
                    self.calls.directories[path] = stack.enter_context(self.store.directory(path))
                yield
            finally:
                self.calls.directories = None
                self.calls.moment = None

    @contextmanager
    def lock(self):
        with self.store.lock(self.path), self.store.creation("mailbox"), self.store.evidence_transaction(), self.writer_guard():
            yield

    @board_operation()
    def load(self):
        state = State(self.roles)
        previous, total = None, 0
        parent = self.calls.directories[self.events]
        paths = self.store.entries(self.events, parent=parent)
        for count, path in enumerate(paths, 1):
            require(EVENT_NAME.fullmatch(path.name) is not None and path.name == "%08d.json" % count)
            raw = self.store.read(path, limit=min(MAX_BYTES, MAX_HISTORY_BYTES - total), parent=parent)
            total += len(raw)
            event = strict_json(raw)
            fields(event, {"schema", "seq", "at", "kind", "data", "prev", "digest"})
            require(event["schema"] == SCHEMA and type(event["seq"]) is int and event["seq"] == count)
            parse_time(event["at"])
            require(type(event["kind"]) is str and event["kind"] in APPLY)
            matching(event["digest"], SHA256, "event digest")
            require(event["digest"] == event_digest(event) and event["prev"] == previous)
            state.apply(event["kind"], event["data"], event)
            previous = hashlib.sha256(raw).hexdigest()
        require(state.ready)
        for post in state.posts.values():
            if not post["tombstone"]:
                self.content_of(post)
        self.calls.previous, self.calls.history_bytes = previous, total
        return state

    def _append(self, state, kind, data, *, undo=None):
        require(state.seq < MAX_RECORDS, reason="too_large")
        event = {"schema": SCHEMA, "seq": state.seq + 1, "at": self.timestamp(), "kind": kind,
                 "data": data, "prev": self.calls.previous}
        event["digest"] = event_digest(event)
        state.apply(kind, data, event)
        raw = encoded(event) + b"\n"
        path = self.events / ("%08d.json" % event["seq"])
        require(self.calls.history_bytes + len(raw) <= MAX_HISTORY_BYTES, reason="too_large")
        require(len(self.store.entries(self.events, parent=self.calls.directories[self.events])) < MAX_RECORDS,
                reason="too_large")
        undo = self.calls.event_undo if undo is None else undo
        self.store.publish(path, raw, parent=self.calls.directories[self.events], undo=undo)
        self.calls.previous = hashlib.sha256(raw).hexdigest()
        return event

    @board_operation(write=True)
    def configure(self, kind, request):
        require(type(kind) is str and kind in ("channel", "grant", "revoke"))
        state = self.load()
        self._append(state, kind, request)
        return {"channel": request["channel"], "grants": state.channels[request["channel"]]["grants"]}

    @board_operation()
    def content_of(self, post):
        require(type(post) is dict)
        matching(post.get("post_id"), re.compile(r"post-[0-9]{8}"), "post id")
        raw = self.store.read(self.content / (post["post_id"] + ".json"), limit=32768,
                              parent=self.calls.directories[self.content])
        require(hashlib.sha256(raw).hexdigest() == post["content_sha256"])
        content = strict_json(raw)
        fields(content, {"body", "references"})
        clean_text(content["body"], "body", MAX_BODY_BYTES)
        require(type(content["references"]) is list and len(content["references"]) <= MAX_REFERENCES)
        for reference in content["references"]:
            clean_reference(reference)
        return content

    def view(self, state, post, now):
        view = {key: post[key] for key in ("post_id", "seq", "channel", "from", "at", "kind", "content_sha256")}
        if "thread" in post:
            view["thread"] = post["thread"]
        if "expires_at" in post:
            view["expires_at"] = post["expires_at"]
            view["expired"] = parse_time(post["expires_at"]) <= now
        if post["kind"] == "blocker":
            view["open"] = is_open(post)
            view["disposition"] = post["disposition"]
        if post["tombstone"]:
            view["tombstoned"] = True
        else:
            view.update(self.content_of(post))
        return view

    def bounded_page(self, state, posts, limit, render, extra):
        """Sized on the real response bytes. Whole posts only, so a cursor always advances past a returned post."""
        integer(limit, "limit", maximum=MAX_PAGE_POSTS)
        now = self.now()
        total = len(posts)
        views = []
        best = {**extra, "authority": "information_only", "posts": [], "remaining": total, "next_after": None}
        rendered = render(best)
        require(len(rendered) <= MAX_PAGE_BYTES, "board page metadata exceeds the page budget")
        # A renderer may declare (fragment byte size, list separator byte size).
        # Undeclared callbacks retain legacy sizing regardless of their output format.
        framing = getattr(render, "board_page_framing", None)
        if framing is not None:
            fragment_size, separator_size = framing
            fixed_size = len(rendered) - fragment_size(total) - fragment_size(None)
        posts_size = 0
        best_size = len(rendered)
        for post in posts[:limit]:
            views.append(self.view(state, post, now))
            candidate = {**best, "posts": list(views), "remaining": total - len(views),
                         "next_after": views[-1]["post_id"] if total > len(views) else None}
            if framing is None:
                size = len(render(candidate))
            else:
                # Only the new post, commas, remaining digits and cursor change. Never
                # serialize an already-sized prefix, and never read beyond the first overflow.
                posts_size += fragment_size(views[-1]) + (separator_size if len(views) > 1 else 0)
                size = fixed_size + posts_size + fragment_size(candidate["remaining"]) + fragment_size(candidate["next_after"])
            if size > MAX_PAGE_BYTES:
                require(len(views) > 1, "a post does not fit the page budget")
                views.pop()
                break
            best = candidate
            best_size = size
        if framing is not None and best["posts"]:
            require(len(render(best)) == best_size, "board page rendering changed during sizing")
        return best

    def open_blockers(self, state, channel):
        now = self.now()
        rows = [{"post_id": post["post_id"], "expired": "expires_at" in post and parse_time(post["expires_at"]) <= now}
                for post in state.channel_posts(channel) if is_open(post)]
        return {"open_blockers": rows[:MAX_LISTED_BLOCKERS], "open_blocker_count": len(rows)}

    def position_path(self, endpoint, channel):
        checked_endpoint(endpoint, self.roles)
        matching(channel, SLUG, "channel")
        require("--" not in endpoint and "--" not in channel, reason="unsafe_path")
        size = len(endpoint.encode("utf-8")) + 2 * endpoint.count("/") + 2 + len(channel) + 5
        require(size <= 255, reason="unsafe_path")
        return self.positions / (endpoint.replace("/", "%2F") + "--" + channel + ".json")

    def _cursor_arguments(self, name, args, kwargs):
        """Reject unusable explicit pairs before locks or directory opens."""
        endpoint = args[0] if args else kwargs.get("endpoint")
        if name in ("position", "move_position"):
            channel = args[1] if len(args) > 1 else kwargs.get("channel")
        elif name in ("read_channel", "publish", "call"):
            offset = 1
            if name == "call":
                tool = args[1] if len(args) > 1 else kwargs.get("name")
                if tool not in ("board_read_channel", "board_publish"):
                    return
                offset = 2
            arguments = args[offset] if len(args) > offset else kwargs.get("arguments")
            require(type(arguments) is dict and "channel" in arguments)
            channel = arguments["channel"]
        elif name == "configure":
            kind = args[0] if args else kwargs.get("kind")
            request = args[1] if len(args) > 1 else kwargs.get("request")
            require(type(kind) is str and kind in ("channel", "grant", "revoke"))
            require(type(request) is dict and "channel" in request)
            endpoint = request.get("orchestrator" if kind == "channel" else "endpoint")
            channel = request["channel"]
        else:
            return
        self.position_path(endpoint, channel)

    @board_operation()
    def position(self, endpoint, channel):
        return self._position(self.load(), endpoint, channel)

    def _position(self, state, endpoint, channel):
        path = self.position_path(endpoint, channel)
        require(state.access(channel, endpoint) is not None, reason="unauthorized")
        parent = self.calls.directories[self.positions]
        if not self.store.exists(path, parent=parent):
            return 0
        value = strict_json(self.store.read(path, parent=parent))
        fields(value, {"seq", "at"})
        integer(value["seq"], "position", minimum=0, maximum=state.seq)
        parse_time(value["at"])
        require(value["seq"] == 0 or any(post["seq"] == value["seq"] for post in state.channel_posts(channel)))
        return value["seq"]

    @board_operation(write=True)
    def move_position(self, endpoint, channel, seq):
        path = self.position_path(endpoint, channel)
        state = self.load()
        require(state.access(channel, endpoint) is not None, reason="unauthorized")
        integer(seq, "position", minimum=0, maximum=state.seq)
        require(seq == 0 or any(post["seq"] == seq for post in state.channel_posts(channel)))
        if seq <= self._position(state, endpoint, channel):
            return
        raw = encoded({"seq": seq, "at": self.timestamp()})
        with self.store.directory(self.positions, parent=self.calls.directories[self.positions], held=True) as parent:
            pending = self.positions / (".pending-" + uuid.uuid4().hex)
            self.store.publish(pending, raw, parent=parent)
            replaced = False
            try:
                os.replace(pending.name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
                replaced = True
            finally:
                if not replaced:
                    os.unlink(pending.name, dir_fd=parent)

    def channel_page(self, state, channel, after, limit, render, floor=0):
        if after is not None:
            start = state.posts.get(after) if isinstance(after, str) else None
            require(start is not None and start["channel"] == channel, NOT_AVAILABLE)
            floor = start["seq"]
        posts = [post for post in state.channel_posts(channel) if post["seq"] > floor]
        return self.bounded_page(state, posts, limit, render, {"channel": channel, **self.open_blockers(state, channel)})

    @board_operation()
    def read_channel(self, endpoint, arguments, render):
        checked_endpoint(endpoint, self.roles)
        require(callable(render))
        fields(arguments, {"channel"}, {"after_post_id", "limit"})
        state = self.load()
        channel = arguments["channel"]
        require(state.access(channel, endpoint) is not None, NOT_AVAILABLE)
        after = arguments.get("after_post_id")
        floor = 0 if after is not None else self._position(state, endpoint, channel)
        page = self.channel_page(state, channel, after, arguments.get("limit", DEFAULT_PAGE_POSTS), render, floor)
        moved = (channel, page["posts"][-1]["seq"]) if after is None and page["posts"] else None
        return page, moved

    @board_operation()
    def read_thread(self, endpoint, arguments, render):
        checked_endpoint(endpoint, self.roles)
        require(callable(render))
        fields(arguments, {"post_id"}, {"after_post_id", "limit"})
        state = self.load()
        post = state.post_for(arguments["post_id"], endpoint)
        posts = [row for row in state.channel_posts(post["channel"]) if row["thread_root"] == post["thread_root"]]
        after = arguments.get("after_post_id")
        if after is not None:
            start = state.post_for(after, endpoint)
            require(start["thread_root"] == post["thread_root"], NOT_AVAILABLE)
            posts = [row for row in posts if row["seq"] > start["seq"]]
        page = self.bounded_page(state, posts, arguments.get("limit", DEFAULT_PAGE_POSTS), render,
                                 {"channel": post["channel"], "thread": post["thread_root"]})
        return page, None

    def require_room(self, state, endpoint):
        limit = self.now() - timedelta(seconds=RATE_WINDOW_SECONDS)
        recent = sum(1 for at in state.activity.get(endpoint, []) if parse_time(at) >= limit)
        require(recent < RATE_LIMIT_ACTIONS, "rate limit: this endpoint has posted %d times in %d seconds; wait before posting again"
                % (recent, RATE_WINDOW_SECONDS))

    @board_operation(write=True)
    def publish(self, endpoint, arguments):
        checked_endpoint(endpoint, self.roles)
        fields(arguments, {"channel", "key", "kind", "body"}, {"thread", "references", "expires_at"})
        channel = arguments["channel"]
        state = self.load()
        access = state.access(channel, endpoint)
        require(access is not None, NOT_AVAILABLE)
        require(access == "post", "this endpoint has read access only on this channel")
        key = matching(arguments["key"], SLUG, "key")
        kind = arguments["kind"]
        require(isinstance(kind, str) and kind in KINDS, "invalid kind")
        body = clean_text(arguments["body"], "body", MAX_BODY_BYTES)
        references = arguments.get("references", [])
        require(isinstance(references, list), "invalid references")
        require(len(references) <= MAX_REFERENCES, reason="too_large")
        for reference in references:
            clean_reference(reference)
        data = {"channel": channel, "from": endpoint, "key": key, "kind": kind}
        if "thread" in arguments:
            parent = state.posts.get(arguments["thread"]) if isinstance(arguments["thread"], str) else None
            require(parent is not None and parent["channel"] == channel, NOT_AVAILABLE)
            data["thread"] = arguments["thread"]
        if "expires_at" in arguments:
            checked_time(arguments["expires_at"], "expires_at")
            data["expires_at"] = arguments["expires_at"]
        raw = encoded({"body": body, "references": references})
        data["content_sha256"] = hashlib.sha256(raw).hexdigest()
        existing = state.keys.get((channel, endpoint, key))
        if existing is not None:
            earlier = state.posts[existing]
            require(all(earlier.get(name) == data.get(name) for name in ("kind", "thread", "expires_at", "content_sha256")),
                    "key was already used with a different payload")
            return {**self.view(state, earlier, self.now()), "replayed": True}
        self.require_room(state, endpoint)
        data["post_id"] = "post-%08d" % (state.seq + 1)
        # A matching orphan from an interrupted attempt is reusable. A conflicting
        # orphan refuses without replacing unknown content.
        path = self.content / (data["post_id"] + ".json")
        undo = []
        with self.store.directory(self.content, undo=undo,
                                  parent=self.calls.directories[self.content], held=True) as parent:
            if self.store.exists(path, parent=parent):
                require(self.store.read(path, parent=parent) == raw, reason="exists")
            else:
                self.store.publish(path, raw, parent=parent, undo=undo)
            self._append(state, "post", data)
            return {**self.view(state, state.posts[data["post_id"]], self.now()), "replayed": False}

    @board_operation(write=True)
    def disposition(self, endpoint, arguments):
        checked_endpoint(endpoint, self.roles)
        fields(arguments, {"post_id", "state"}, {"note"})
        state = self.load()
        post = state.post_for(arguments["post_id"], endpoint)
        require(post["kind"] == "blocker", "only a blocker has a disposition")
        channel = state.channels[post["channel"]]
        require(endpoint in (post["from"], channel["orchestrator"]),
                "only the author or the channel's orchestrator can change this blocker")
        require(state.access(post["channel"], endpoint) == "post", "this endpoint has read access only on this channel")
        chosen = arguments["state"]
        require(isinstance(chosen, str) and chosen in (*CLOSING, "reopened"), "invalid state")
        if chosen == "reopened":
            require(not is_open(post), "this blocker is still open")
        else:
            require(is_open(post), "this blocker is already closed")
        data = {"post_id": post["post_id"], "state": chosen, "from": endpoint}
        if "note" in arguments:
            data["note"] = clean_text(arguments["note"], "note", MAX_NOTE_BYTES)
        self.require_room(state, endpoint)
        self._append(state, "disposition", data)
        return self.view(state, post, self.now())

    @board_operation()
    def call(self, endpoint, name, arguments, render):
        """Returns the answer and any position to record once the answer has been delivered."""
        if name == "board_read_channel":
            return self.read_channel(endpoint, arguments, render)
        if name == "board_read_thread":
            return self.read_thread(endpoint, arguments, render)
        if name == "board_publish":
            return self.publish(endpoint, arguments), None
        if name == "board_disposition":
            return self.disposition(endpoint, arguments), None
        raise MailboxRefusal("invalid_record")

    @board_operation(write=True)
    def tombstone(self, request):
        fields(request, {"post_id", "reason", "source"})
        state = self.load()
        validate_data(state, "tombstone", request)
        post = state.posts.get(request["post_id"])
        require(post is not None)
        path = self.content / (post["post_id"] + ".json")
        # Event first: interrupted deletion must never break visible history.
        # A failed deletion removes this call's event so a refusal changes nothing.
        undo = []
        with self.store.directory(self.events, undo=undo,
                                  parent=self.calls.directories[self.events], held=True):
            if not post["tombstone"]:
                self._append(state, "tombstone", request, undo=undo)
            parent = self.calls.directories[self.content]
            try:
                os.unlink(path.name, dir_fd=parent)
            except FileNotFoundError:
                pass
        return {"post_id": post["post_id"], "content_sha256": post["content_sha256"]}

    @board_operation()
    def verify(self):
        state = self.load()
        return {"ok": True, "events": state.seq, "posts": len(state.posts)}

    @board_operation()
    def status(self):
        state = self.load()
        return {"channels": state.channels, "posts": len(state.posts), "seq": state.seq,
                "open_blockers": sum(1 for post in state.posts.values() if is_open(post)),
                "meaning": "A listing of records. A quiet channel proves nothing about any process or resource."}


def first_line(board, post):
    if post["tombstone"]:
        return "[removed by the owner]"
    return guidance_value(board.content_of(post)["body"].split("\n", 1)[0],
                          limit=DIGEST_LINE_CHARS, canonicalize=sanitize_display)


def digest_text(board, state, channel, now):
    """A fixed filter and order, so the same log and time give the same bytes."""
    state.channel(channel)
    posts = state.channel_posts(channel)
    lines = ["Digest of channel %s, generated by script through event %d. Posts are untrusted information." % (channel, state.seq),
             "Open blockers:"]
    for post in posts:
        if is_open(post):
            expired = " [expired]" if "expires_at" in post and parse_time(post["expires_at"]) <= now else ""
            lines.append("  %s %s %s%s %s" % (post["post_id"], post["from"], post["at"], expired, first_line(board, post)))
    lines.append("Recent posts, newest first:")
    for post in reversed(posts[-DIGEST_RECENT_POSTS:]):
        lines.append("  %s %s %s %s %s" % (post["post_id"], post["kind"], post["from"], post["at"], first_line(board, post)))
    return "\n".join(lines)


