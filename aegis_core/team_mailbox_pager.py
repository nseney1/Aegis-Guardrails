"""Planned inbox selection and delivery state, outside the MCP transport.

The adapter supplies fenced snapshots, brief readers, a trusted clock and wire sizes.
Only commit() after a successful flush retains cursors, freezes cutoffs or suppresses
previously delivered checkpoint metadata.
"""
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import math
import re
from typing import Optional
from collections.abc import Sized
from functools import wraps

from aegis_core.team_mailbox_primitives import (
    MAX_BYTES, MAX_INBOX_RESPONSE_BYTES, MAX_RECORDS, MAX_JSON_DEPTH, MAX_JSON_NODES, MAX_JSON_ITEMS, SLUG,
    MailboxRefusal, bounded_tree, integer, matching, require, text, validation,
)

__all__ = ["InboxPager", "InboxRequest", "assemble_inbox", "bounded_inbox", "parse_inbox_time", "ordered_history"]

MAX_CURSOR_PAIRS = 4 * MAX_RECORDS
STORED_RECORD_BYTES = MAX_BYTES
MAX_PAGE_RECORDS = 100
MAX_CHECKPOINT_REFS = 256
# Structural limits count decoded characters/nodes, never serialized bytes.
# One record adds a path/wrapper and one expanded brief to its stored message.
HISTORY_MESSAGE_TEXT_LIMIT = STORED_RECORD_BYTES
HISTORY_MESSAGE_NODE_LIMIT = MAX_JSON_NODES + 2
HISTORY_RECORD_TEXT_LIMIT = 2 * STORED_RECORD_BYTES + 32768
HISTORY_RECORD_NODE_LIMIT = MAX_JSON_NODES + 8
RESPONSE_META_TEXT_LIMIT = (MAX_CHECKPOINT_REFS + 1) * STORED_RECORD_BYTES + 32768
RESPONSE_META_NODE_LIMIT = 2 * MAX_JSON_NODES
MAX_DECODED_BRIEF_BYTES = (MAX_PAGE_RECORDS + MAX_CHECKPOINT_REFS) * STORED_RECORD_BYTES


def _boundary(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except MailboxRefusal:
            raise
        except OSError:
            raise MailboxRefusal("io") from None
        except (ValueError, KeyError, UnicodeError, RecursionError, OverflowError, AttributeError):
            raise MailboxRefusal("invalid_record") from None
    return call


@validation
def parse_inbox_time(value):
    """Parse the pinned UTC grammar without version-dependent fromisoformat fractions."""
    require(type(value) is str and len(value) <= 27)
    match = re.fullmatch(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
                         r"(?:\.([0-9]{1,6}))?Z", value) if type(value) is str else None
    require(match is not None, "invalid UTC timestamp")
    try:
        parts = [int(part) for part in match.groups()[:6]]
        microsecond = int((match.group(7) or "").ljust(6, "0"))
        return datetime(*parts, microsecond=microsecond, tzinfo=timezone.utc)
    except ValueError as exc:
        raise MailboxRefusal("invalid_record") from None


@_boundary
def bounded_inbox(result, render, *, max_response_bytes=MAX_INBOX_RESPONSE_BYTES):
    """Match the pinned linear pager with logarithmically many transport renders.

    All selected records/briefs are validated before paging. Check metadata and
    the first message separately: neither may be skipped to make another fit.
    For validated mailbox records, each added message/path outweighs any shrink
    in remaining/next_after, including the final cursor becoming null.
    """
    require(type(result) is dict and callable(render))
    integer(max_response_bytes, "response budget", maximum=MAX_INBOX_RESPONSE_BYTES)
    require(type(result.get("messages")) is list)
    require(len(result["messages"]) <= MAX_PAGE_RECORDS, reason="too_large")
    require(len(result) <= MAX_JSON_ITEMS, reason="too_large")
    # Per-record structure admits a large combined candidate; actual expanded
    # transport bytes are checked only by size()/paging below.
    metadata = {key: value for key, value in result.items() if key != "messages"}
    _structure(metadata, text_limit=RESPONSE_META_TEXT_LIMIT, node_limit=RESPONSE_META_NODE_LIMIT)
    integer(result.get("remaining"), "remaining", minimum=0, maximum=MAX_RECORDS)
    messages = result["messages"]
    _history_rows(messages)
    _response_rows(messages)
    total = len(messages) + result["remaining"]
    require(total <= MAX_RECORDS, reason="too_large")

    def size(value):
        raw = render(value)
        require(type(raw) is bytes)
        return len(raw)

    def page(count):
        remaining = total - count
        return {**result, "messages": messages[:count], "remaining": remaining,
                "next_after": messages[count - 1]["message"]["message_id"] if count and remaining else None}

    empty = page(0)
    require(size(empty) <= max_response_bytes, reason="too_large", message=
            "inbox response metadata exceeds 4194304 bytes")
    if not messages:
        return empty
    require(size(page(1)) <= max_response_bytes, reason="too_large", message=
            "inbox first message cannot fit 4194304 byte response budget")
    low, high = 1, len(messages)
    while low < high:
        middle = (low + high + 1) // 2
        if size(page(middle)) <= max_response_bytes:
            low = middle
        else:
            high = middle - 1
    return page(low)


@_boundary
def assemble_inbox(result, render, *, bound, note_returned):
    """Size and stage one response through the same live/preview assembly path."""
    require(type(result) is dict and callable(render) and callable(bound) and callable(note_returned))
    sizes = {}

    def measured(page):
        raw = render(page)
        require(type(raw) is bytes)
        sizes[len(page["messages"])] = len(raw)
        return raw

    result = bound(result, measured)
    # Both bounds rendered each selected count; retain logarithmic rendering.
    note_returned(result, sizes[len(result["messages"])])
    return result



def _structure(value, *, text_limit, node_limit):
    """Bound decoded structure before copying/rendering without ASCII encoding.

    Each record keeps the store's structural limits plus wrapper/brief fields;
    a page does not inherit one record's node ceiling. Character accounting is
    independent of the publisher's stored bytes and the renderer's wire bytes.
    """
    budget = [text_limit, node_limit]
    def visit(item, depth):
        require(depth <= MAX_JSON_DEPTH + 2)
        budget[1] -= 1
        require(budget[1] >= 0, reason="too_large")
        if type(item) is str:
            require(len(item) <= budget[0], reason="too_large")
            budget[0] -= len(item)
            require(not any(0xD800 <= ord(char) <= 0xDFFF for char in item))
        elif type(item) in (dict, list, tuple):
            require(len(item) <= MAX_JSON_ITEMS, reason="too_large")
            for key in item:
                if type(item) is dict:
                    require(type(key) is str)
                    visit(key, depth + 1)
                    visit(item[key], depth + 1)
                else:
                    visit(key, depth + 1)
        else:
            require(item is None or type(item) in (bool, int, float))
            require(type(item) is not int or item.bit_length() <= 64)
            require(type(item) is not float or math.isfinite(item))
    visit(value, 0)


def _history_rows(records):
    # The store supplies a sized collection. Refuse arbitrary streams before
    # iteration so an infinite producer cannot allocate an unbounded history.
    require(isinstance(records, Sized))
    require(len(records) <= MAX_RECORDS, reason="too_large")
    rows, identifiers = [], set()
    for record in records:
        require(len(rows) < MAX_RECORDS, reason="too_large")
        require(type(record) is dict and type(record.get("message")) is dict)
        require(len(record) <= MAX_JSON_ITEMS, reason="too_large")
        message = record["message"]
        _structure(message, text_limit=HISTORY_MESSAGE_TEXT_LIMIT, node_limit=HISTORY_MESSAGE_NODE_LIMIT)
        if "path" in record:
            text(record["path"], "record path", 32768)
        for field in ("to", "from", "created_at", "message_id", "type"):
            text(message.get(field), field, 256)
        matching(message["message_id"], SLUG, "message id")
        parse_inbox_time(message["created_at"])
        require(message["message_id"] not in identifiers)
        identifiers.add(message["message_id"])
        rows.append(record)
    return rows


def _response_rows(rows):
    # Only selected endpoint rows reach expanded-response structural checks.
    for row in rows:
        _structure(row, text_limit=HISTORY_RECORD_TEXT_LIMIT, node_limit=HISTORY_RECORD_NODE_LIMIT)


@validation
def ordered_history(records, endpoint, order):
    """Validate the entire capped history before filtering and sorting once."""
    text(endpoint, "endpoint", 256)
    require(type(order) is str and order in ("oldest", "newest"))
    return sorted((r for r in _history_rows(records) if r["message"]["to"] == endpoint),
                  key=lambda r: (r["message"]["created_at"], r["message"]["message_id"]),
                  reverse=order == "newest")


def _checked_snapshot(snapshot):
    require(type(snapshot) is dict)
    _structure(snapshot, text_limit=HISTORY_RECORD_TEXT_LIMIT, node_limit=HISTORY_RECORD_NODE_LIMIT)
    for field in ("endpoint", "host", "session", "created_at"):
        text(snapshot.get(field), field, 256)
    integer(snapshot.get("generation"), "generation")
    require("checkpoint_sha256" in snapshot and "checkpoint" in snapshot)
    require(snapshot["checkpoint_sha256"] is None or type(snapshot["checkpoint_sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", snapshot["checkpoint_sha256"]) is not None)
    parse_inbox_time(snapshot["created_at"])
    checkpoint = snapshot["checkpoint"]
    require(checkpoint is None or type(checkpoint) is dict)
    if checkpoint:
        require(type(checkpoint.get("pending_message_ids", [])) is list)
        require(type(checkpoint.get("briefs", [])) is list)
        require(len(checkpoint.get("pending_message_ids", [])) <= MAX_CHECKPOINT_REFS
                and len(checkpoint.get("briefs", [])) <= MAX_CHECKPOINT_REFS, reason="too_large")
        for reference in checkpoint.get("briefs", []):
            _reference(reference)
        for identifier in checkpoint.get("pending_message_ids", []):
            matching(identifier, SLUG, "pending message id")


def _reference(reference):
    require(type(reference) is dict and set(reference) == {"path", "sha256"})
    text(reference["path"], "brief path")
    require(type(reference["sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", reference["sha256"]) is not None)


def _brief_text(reader, reference, budget):
    require(callable(reader))
    _reference(reference)
    raw = reader(reference)
    require(type(raw) is bytes)
    require(len(raw) <= min(STORED_RECORD_BYTES, budget[0]), reason="too_large")
    budget[0] -= len(raw)
    return raw.decode("utf-8")


def _binding_identity(binding):
    """Binding identity excludes its editable cutoff and checkpoint contents."""
    return tuple(binding[key] for key in ("endpoint", "host", "session", "generation"))


@dataclass(frozen=True)
class InboxRequest:
    """Validated view options and the trusted request-time clock snapshot."""
    include_briefs: bool
    force_full: bool
    order: str
    since: bool
    call_time: Optional[datetime]


class InboxPager:
    """Own planned selection, cursor provenance and post-flush metadata delivery.

    A validated host plan opts into this service. The adapter retains legacy
    inbox/binding readers when no plan exists. Metadata deduplication is per
    binding identity, checkpoint hash and recorded timestamp; only flushed
    responses within brief_dedupe_max_bytes count. briefs=full forces recovery,
    and binding_only never advances this state.

    Each flushed cursor is associated with (order, since, snapshot, cutoff).
    All pairs share a capacity with no live eviction. Retries remain valid until
    their walk drains, even when other walks issue the same message ID. Unknown
    IDs are compatible only with oldest and no since. Filtered pages disclose
    excluded counts before cursor selection.

    The first flushed page freezes created_at per endpoint/host/session/generation,
    independently of its editable checkpoint hash. Cutoff drift, future times
    beyond since_clock_skew_seconds and UTC comparisons disagreeing with the
    pinned string sort refuse. Equal timestamps and checkpoint pending IDs are
    included. Timestamp filtering never proves all mail read; recover from wake
    holds by reading oldest without since.
    """

    def __init__(self, *, clock, brief_dedupe_max_bytes, since_clock_skew_seconds, capacity_error):
        require(callable(clock))
        integer(brief_dedupe_max_bytes, "brief budget", maximum=MAX_INBOX_RESPONSE_BYTES)
        integer(since_clock_skew_seconds, "clock skew", minimum=0, maximum=86400)
        text(capacity_error, "capacity error")
        self.clock = clock
        self.brief_dedupe_max_bytes = brief_dedupe_max_bytes
        self.since_clock_skew_seconds = since_clock_skew_seconds
        self.capacity_error = capacity_error
        self.session = None
        self.briefs_session = None
        self.offered = None
        self._offered_page = None
        self.pending = None
        self.cutoffs = {}
        self.cursors = {}
        self.retained_cursor_pairs = 0

    def begin_response(self):
        """Abandon an unflushed response without changing committed state."""
        self.pending = None
        self.offered = None
        self._offered_page = None

    def _checked_request(self, arguments, checked_binding):
        request = self.prepare(arguments)
        require(callable(checked_binding))
        pair = checked_binding()
        require(type(pair) in (tuple, list) and len(pair) == 2)
        mailbox, snapshot = pair
        _checked_snapshot(snapshot)
        require(callable(getattr(mailbox, "ready", None)))
        ready = mailbox.ready(snapshot)
        require(type(ready) is bool)
        return request, mailbox, snapshot, ready

    @_boundary
    def inbox(self, arguments, *, checked_binding, slim_metadata, brief_status):
        """Fence once before reading and selecting the live mailbox history."""
        request, mailbox, snapshot, ready = self._checked_request(arguments, checked_binding)
        slimming = slim_metadata()
        limit = arguments.get("limit", 20)
        integer(limit, "inbox limit", maximum=MAX_PAGE_RECORDS)
        return self.page(request, snapshot=snapshot, ready=ready, records=mailbox.messages().values(),
                         limit=limit, after=arguments.get("after_message_id"), read_brief=mailbox.brief,
                         brief_status=lambda brief: brief_status(mailbox, brief), slimming=slimming)

    @_boundary
    def preview(self, arguments, records, message_id, *, checked_binding, slimming, render, bound,
                max_cursor_pairs, brief_status=None):
        """Walk validated history on an isolated pager; never receive delivery authority.

        A digest cursor has no inbox ordering/filter provenance. Planned retries
        restart oldest-first; the caller's arguments and live pager stay intact.
        Only this copy commits cursors, with no connection or read-receipt access.
        """
        self.prepare(arguments)
        require(type(slimming) is bool and callable(render) and callable(bound))
        matching(message_id, SLUG, "message id")
        integer(max_cursor_pairs, "cursor capacity", maximum=MAX_CURSOR_PAIRS)
        scratch = deepcopy(self)
        retry = dict(arguments)
        restart = "after_message_id" in retry and slimming
        if restart:
            del retry["after_message_id"]
        request, mailbox, snapshot, ready = scratch._checked_request(retry, checked_binding)
        _checked_snapshot(snapshot)
        snapshot = deepcopy(snapshot)
        records = ordered_history(records, snapshot["endpoint"], request.order)

        def stage(page, rendered_bytes):
            if slimming:
                scratch.stage(page, rendered_bytes, max_cursor_pairs=max_cursor_pairs)

        for _ in range(MAX_RECORDS):
            scratch.begin_response()
            page = scratch._page(request, snapshot=snapshot, ready=ready, records=records,
                                limit=retry.get("limit", 20), after=retry.get("after_message_id"),
                                read_brief=mailbox.brief, brief_status=brief_status, slimming=slimming)
            page = assemble_inbox(page, render, bound=bound, note_returned=stage)
            raw = render(page)
            scratch.commit()
            if any(row["message"]["message_id"] == message_id for row in page["messages"]):
                return raw, restart
            if page["next_after"] is None:
                return None
            retry["after_message_id"] = page["next_after"]
        return None

    @_boundary
    def prepare(self, arguments):
        require(type(arguments) is dict)
        bounded_tree(arguments)
        require(arguments.keys() <= {"include_briefs", "briefs", "order", "since", "limit", "after_message_id"})
        integer(arguments.get("limit", 20), "inbox limit", maximum=MAX_PAGE_RECORDS)
        if "after_message_id" in arguments:
            matching(arguments["after_message_id"], SLUG, "cursor")
        include_briefs = arguments.get("include_briefs", False)
        require(type(include_briefs) is bool, "include_briefs must be boolean")
        force_full = "briefs" in arguments
        if force_full:
            require(type(arguments["briefs"]) is str and arguments["briefs"] == "full",
                    "briefs must be full; use that exact string or omit briefs")
            require("include_briefs" not in arguments or include_briefs,
                    "briefs full requires include_briefs; omit include_briefs or use true")
            include_briefs = True
        order = arguments.get("order", "oldest")
        require(type(order) is str and order in ("oldest", "newest"),
                "order must be oldest or newest; use an exact string")
        since = "since" in arguments
        if since:
            require(type(arguments["since"]) is str and arguments["since"] == "current_generation",
                    "since must be current_generation; use that exact string or omit since")
        call_time = self.clock() if since else None
        require(not since or isinstance(call_time, datetime) and call_time.tzinfo is not None)
        return InboxRequest(include_briefs, force_full, order, since, call_time)

    @_boundary
    def page(self, request, *, snapshot, ready, records, limit, after, read_brief, brief_status, slimming):
        """Select only after checking the entire history; commit after flush."""
        require(type(request) is InboxRequest)
        require(all(type(value) is bool for value in
                    (request.include_briefs, request.force_full, request.since)))
        require(not request.since or isinstance(request.call_time, datetime)
                and request.call_time.tzinfo is not None)
        _checked_snapshot(snapshot)
        integer(limit, "inbox limit", maximum=MAX_PAGE_RECORDS)
        require(type(ready) is bool and type(slimming) is bool)
        records = ordered_history(records, snapshot["endpoint"], request.order)
        return self._page(request, snapshot=snapshot, ready=ready, records=records,
                          limit=limit, after=after, read_brief=read_brief,
                          brief_status=brief_status, slimming=slimming)

    def _page(self, request, *, snapshot, ready, records, limit, after, read_brief, brief_status, slimming):
        brief_budget = [MAX_DECODED_BRIEF_BYTES]
        include_briefs, force_full = request.include_briefs, request.force_full
        order, since, call_time = request.order, request.since, request.call_time
        endpoint = snapshot["endpoint"]
        binding = {**snapshot, "ready": ready}
        identity = _binding_identity(snapshot)
        session = (*identity, snapshot["checkpoint_sha256"], snapshot["created_at"])
        cutoff = None
        excluded = 0
        if since:
            cutoff = snapshot["created_at"]
            previous = self.cutoffs.get(identity)
            require(previous is None or previous == cutoff,
                    "current_generation cutoff changed; omit since to read the full inbox")
            boundary = parse_inbox_time(cutoff)
            require(boundary <= call_time + timedelta(seconds=self.since_clock_skew_seconds),
                    "current_generation cutoff is in the future; omit since to read the full inbox")
            pending = set((snapshot["checkpoint"] or {}).get("pending_message_ids", []))
            eligible = []
            for record in records:
                stamp = record["message"]["created_at"]
                included = parse_inbox_time(stamp) >= boundary
                require(included == (stamp >= cutoff),
                        "current_generation timestamp order is ambiguous; omit since to read the full inbox")
                if included or record["message"]["message_id"] in pending:
                    eligible.append(record)
            excluded = len(records) - len(eligible)
        else:
            eligible = records
        walk = (order, "current_generation" if since else None, session, cutoff)
        if after is not None:
            matching(after, SLUG, "after message id")
            issued = self.cursors.get(after)
            require((walk in issued) if issued is not None else (order == "oldest" and not since),
                    "inbox cursor does not match this walk; restart the walk without after_message_id")
            require(any(r["message"]["message_id"] == after for r in records),
                    "inbox cursor does not name a received message")
            positions = [i for i, r in enumerate(eligible) if r["message"]["message_id"] == after]
            require(bool(positions), "inbox cursor is outside current_generation; omit after_message_id")
            eligible = eligible[positions[0] + 1:]
        selected = eligible[:limit]
        _response_rows(selected)
        selected = deepcopy(selected)
        if include_briefs:
            for record in selected:
                brief = record["message"].get("brief")
                if brief is not None:
                    record["brief_text"] = _brief_text(read_brief, brief, brief_budget)
        checkpoint_briefs = []
        if include_briefs:
            for brief in (snapshot["checkpoint"] or {}).get("briefs", []):
                if force_full or not slimming or self.briefs_session != session:
                    checkpoint_briefs.append({**brief, "text": _brief_text(read_brief, brief, brief_budget)})
                else:
                    require(callable(brief_status))
                    checkpoint_briefs.append(brief_status(brief))
        if slimming and not force_full and self.session == session:
            # Preserve current identity, checkpoint identity and current acknowledgment;
            # omit the schema, timestamp and bulky checkpoint already delivered.
            binding = {key: binding[key] for key in
                       ("endpoint", "host", "session", "generation", "checkpoint_sha256", "ready")}
        self.offered = {"session": session, "include_briefs": include_briefs, "walk": walk,
                        "binding": identity, "cutoff": snapshot["created_at"], "slimming": slimming}
        result = {"endpoint": endpoint, "messages": selected, "remaining": max(0, len(eligible) - limit),
                  "binding": binding, "checkpoint_briefs": checkpoint_briefs,
                  "next_after": selected[-1]["message"]["message_id"] if len(eligible) > limit else None}
        if order != "oldest":
            result["order"] = order
        if since:
            result.update(since="current_generation", excluded=excluded)
        self._offered_page = deepcopy(result)
        return result

    @_boundary
    def stage(self, page, rendered_bytes, *, max_cursor_pairs):
        """Stage the transport-sized page; capacity checks never recount live pairs."""
        require(self.offered is not None and self.pending is None)
        require(type(page) is dict and page.get("endpoint") == self._offered_page["endpoint"]
                and type(page.get("messages")) is list
                and len(page["messages"]) <= len(self._offered_page["messages"])
                and page["messages"] == self._offered_page["messages"][:len(page["messages"])])
        integer(rendered_bytes, "rendered bytes", minimum=0, maximum=MAX_INBOX_RESPONSE_BYTES)
        integer(max_cursor_pairs, "cursor capacity", maximum=MAX_CURSOR_PAIRS)
        offered = self.offered
        require(offered["binding"] in self.cutoffs or len(self.cutoffs) < MAX_RECORDS, reason="too_large")
        count = len(page["messages"])
        total = len(self._offered_page["messages"]) + self._offered_page["remaining"]
        integer(page.get("remaining"), "remaining", minimum=0, maximum=MAX_RECORDS)
        require(page["remaining"] == total - count)
        expected_cursor = page["messages"][-1]["message"]["message_id"] if count and total > count else None
        require("next_after" in page and page["next_after"] == expected_cursor)
        cursor = page.get("next_after")
        if cursor is not None:
            matching(cursor, SLUG, "cursor")
            require(page["messages"] and cursor == page["messages"][-1]["message"]["message_id"])
        contexts = self.cursors.get(cursor, set())
        retain_cursor = cursor is not None
        if retain_cursor:
            known = offered["walk"] in contexts
            require(known or self.retained_cursor_pairs < max_cursor_pairs, reason="too_large")
        self.pending = ({**offered, "retain_cursor": retain_cursor}, cursor, rendered_bytes)

    def commit(self):
        """Commit after stdout flush; only small responses can suppress later texts."""
        pending, self.pending = self.pending, None
        if pending is not None:
            offered, cursor, rendered_bytes = pending
            # Unfiltered recovery must not replace an earlier frozen cutoff.
            self.cutoffs.setdefault(offered["binding"], offered["cutoff"])
            walk = offered["walk"]
            if offered["retain_cursor"]:
                contexts = self.cursors.setdefault(cursor, set())
                if walk not in contexts:
                    contexts.add(walk)
                    self.retained_cursor_pairs += 1
            elif cursor is None:
                # Every issued context remains valid until its own walk drains,
                # regardless of which other walks issue the same message ID.
                for identifier, contexts in list(self.cursors.items()):
                    if walk in contexts:
                        contexts.remove(walk)
                        self.retained_cursor_pairs -= 1
                    if not contexts:
                        del self.cursors[identifier]
            if offered["slimming"] and rendered_bytes <= self.brief_dedupe_max_bytes:
                self.session = offered["session"]
                if offered["include_briefs"]:
                    self.briefs_session = offered["session"]
            else:
                # Even a recovery page can be truncated. Keep all full metadata owed.
                self.session = None
                self.briefs_session = None
