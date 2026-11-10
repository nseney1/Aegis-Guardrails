"""Planned pager delivery accounting through the MCP response lifecycle."""
import pytest

from tests.integration.test_hierarchy_mailbox_mcp import (  # noqa: F401
    MB3_CAPACITY, mb3_call, mb3_connection, mb3_fixed_clock, mb3_pilot, mb3_seed, payload,
)


def test_retained_pairs_commit_retry_collision_and_drain(mb3_pilot, monkeypatch):  # noqa: F811
    import hierarchy_mailbox_mcp as mcp
    from hierarchy_mailbox_pager import InboxPager

    root, _ = mb3_pilot
    mb3_seed(root)
    connection = mb3_connection(root)
    monkeypatch.setattr(mcp, "MAX_INBOX_CURSOR_PAIRS", 2)
    options = {"order": "newest", "limit": 3}
    mb3_call(connection, options, flush=False)
    pager = connection.pager
    assert isinstance(pager, InboxPager)
    assert pager.retained_cursor_pairs == 0
    mb3_call(connection, {"binding_only": True})
    assert pager.retained_cursor_pairs == 0
    first = payload(mb3_call(connection, options))
    assert pager.retained_cursor_pairs == 1
    # Both a repeated commit callback and repeated issuance are idempotent.
    connection.record_inbox_page()
    retry = payload(mb3_call(connection, options))
    assert retry["messages"] == first["messages"]
    assert retry["next_after"] == first["next_after"]
    assert pager.retained_cursor_pairs == 1
    other = payload(mb3_call(connection, {**options, "since": "current_generation"}))
    assert other["next_after"] == first["next_after"]
    assert pager.retained_cursor_pairs == 2
    assert payload(mb3_call(connection, {"limit": 3})) == {"error": MB3_CAPACITY}
    assert pager.retained_cursor_pairs == 2
    # A refused request and an abandoned final page must free nothing.
    finish = {**options, "after_message_id": first["next_after"]}
    mb3_call(connection, finish, flush=False)
    assert pager.retained_cursor_pairs == 2
    assert "error" in payload(mb3_call(connection, {"order": "invalid"}))
    assert pager.retained_cursor_pairs == 2
    assert payload(mb3_call(connection, finish))["next_after"] is None
    assert pager.retained_cursor_pairs == 1
    assert payload(mb3_call(connection, {**finish, "since": "current_generation"}))["next_after"] is None
    assert pager.retained_cursor_pairs == 0
    assert connection.inbox_cursors == {}
    assert payload(mb3_call(connection, options))["next_after"] == first["next_after"]
    assert pager.retained_cursor_pairs == 1


@pytest.mark.parametrize("options", [{}, {"order": "newest"}, {"since": "current_generation"},
                                     {"order": "newest", "since": "current_generation"}])
def test_each_walk_releases_all_its_retained_pairs(mb3_pilot, options):  # noqa: F811
    from hierarchy_mailbox_pager import InboxPager

    root, _ = mb3_pilot
    mb3_seed(root)
    connection = mb3_connection(root)
    cursor = None
    for number in range(5):
        arguments = {**options, "limit": 1}
        if cursor is not None:
            arguments["after_message_id"] = cursor
        page = payload(mb3_call(connection, arguments))
        assert "error" not in page
        assert isinstance(connection.pager, InboxPager)
        cursor = page["next_after"]
        assert connection.pager.retained_cursor_pairs == (number + 1 if cursor else 0)
    assert cursor is None
