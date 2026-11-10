"""Planned inbox selection and delivery state, outside the MCP transport.

The adapter supplies fenced snapshots, brief readers, a trusted clock and wire sizes.
Only commit() after a successful flush retains cursors, freezes cutoffs or suppresses
previously delivered checkpoint metadata.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
from typing import Optional

from hierarchy_mailbox import MAX_INBOX_RESPONSE_BYTES, SLUG, matching, require

__all__ = ["InboxPager", "InboxRequest", "bounded_inbox", "parse_inbox_time"]


def parse_inbox_time(value):
    """Parse the pinned UTC grammar without version-dependent fromisoformat fractions."""
    match = re.fullmatch(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
                         r"(?:\.([0-9]{1,6}))?Z", value) if type(value) is str else None
    require(match is not None, "invalid UTC timestamp")
    try:
        parts = [int(part) for part in match.groups()[:6]]
        microsecond = int((match.group(7) or "").ljust(6, "0"))
        return datetime(*parts, microsecond=microsecond, tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError("invalid UTC timestamp") from exc


def bounded_inbox(result, render, *, max_response_bytes=MAX_INBOX_RESPONSE_BYTES):
    """Match the pinned linear pager with logarithmically many transport renders.

    All selected records/briefs are validated before paging. Check metadata and
    the first message separately: neither may be skipped to make another fit.
    For validated mailbox records, each added message/path outweighs any shrink
    in remaining/next_after, including the final cursor becoming null.
    """
    messages = result["messages"]
    total = len(messages) + result["remaining"]

    def page(count):
        remaining = total - count
        return {**result, "messages": messages[:count], "remaining": remaining,
                "next_after": messages[count - 1]["message"]["message_id"] if count and remaining else None}

    empty = page(0)
    require(len(render(empty)) <= max_response_bytes,
            "inbox response metadata exceeds 4194304 bytes")
    if not messages:
        return empty
    require(len(render(page(1))) <= max_response_bytes,
            "inbox first message cannot fit 4194304 byte response budget")
    low, high = 1, len(messages)
    while low < high:
        middle = (low + high + 1) // 2
        if len(render(page(middle))) <= max_response_bytes:
            low = middle
        else:
            high = middle - 1
    return page(low)


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
        self.clock = clock
        self.brief_dedupe_max_bytes = brief_dedupe_max_bytes
        self.since_clock_skew_seconds = since_clock_skew_seconds
        self.capacity_error = capacity_error
        self.session = None
        self.briefs_session = None
        self.offered = None
        self.pending = None
        self.cutoffs = {}
        self.cursors = {}
        self.retained_cursor_pairs = 0

    def begin_response(self):
        """Abandon an unflushed response without changing committed state."""
        self.pending = None
        self.offered = None

    def prepare(self, arguments):
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
        return InboxRequest(include_briefs, force_full, order, since, call_time)

    def page(self, request, *, snapshot, ready, records, limit, after, read_brief, brief_status, slimming):
        """Select from validated snapshots; perform no authorization or transport writes."""
        include_briefs, force_full = request.include_briefs, request.force_full
        order, since, call_time = request.order, request.since, request.call_time
        endpoint = snapshot["endpoint"]
        binding = {**snapshot, "ready": ready}
        identity = _binding_identity(snapshot)
        session = (*identity, snapshot["checkpoint_sha256"], snapshot["created_at"])
        # Keep the pinned whole-history validation, including records outside this page.
        records = sorted((r for r in records if r["message"]["to"] == endpoint),
                         key=lambda r: (r["message"]["created_at"], r["message"]["message_id"]),
                         reverse=order == "newest")
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
        if include_briefs:
            for record in selected:
                brief = record["message"].get("brief")
                if brief is not None:
                    record["brief_text"] = read_brief(brief).decode("utf-8")
        checkpoint_briefs = []
        if include_briefs:
            for brief in (snapshot["checkpoint"] or {}).get("briefs", []):
                if force_full or not slimming or self.briefs_session != session:
                    checkpoint_briefs.append({**brief, "text": read_brief(brief).decode("utf-8")})
                else:
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
        return result

    def stage(self, page, rendered_bytes, *, max_cursor_pairs):
        """Stage the transport-sized page; capacity checks never recount live pairs."""
        offered = self.offered
        cursor = page["next_after"]
        contexts = self.cursors.get(cursor, set())
        retain_cursor = cursor is not None
        if retain_cursor:
            known = offered["walk"] in contexts
            require(known or self.retained_cursor_pairs < max_cursor_pairs,
                    self.capacity_error)
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
