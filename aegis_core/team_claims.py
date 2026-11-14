"""Recoverable queue/lease transitions under the workspace writer lock.

Initial refusals restore the exact queue bytes until release may have landed.
Recovery preserves intent and requires the original operation and stopped-writer
acknowledgement. Owner-UID rewriting of owner-managed records is out of scope.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import shlex

from aegis_core import events, gitsafe, storage, team, team_paths

__all__ = ["ClaimRefusal", "validate_pending", "transition", "fingerprint",
           "recovery_refusal", "observe_leases"]

MAX_EVENT_BYTES = 16 * 1024 * 1024
# Covers both event paths at the maximum workspace spelling, escaped labels,
# the 4096-character reason, and fixed event metadata.
EVENT_MARGIN = 1024 * 1024


class ClaimRefusal(ValueError):
    """Fixed public reason and independently sanitized recovery fields."""

    def __init__(self, reason, blockers=None):
        super().__init__(reason)
        self.reason, self.blockers = reason, blockers


def validate_pending(state, key_valid, text_valid):
    """Validate decoded intent before using any recovery field."""
    if "unclaim" not in state:
        return True
    intent = state["unclaim"]
    required = {"id", "revision", "lane", "caller", "reason", "lease_oid", "to_revision"}
    if type(intent) is not dict or not required <= intent.keys() <= required | {"writer_stopped", "released_lease_ids"}:
        return False
    if not key_valid(intent["id"]) or not key_valid(intent["lane"]) or not team.valid_lane(intent["lane"]):
        return False
    for field in ("revision", "to_revision"):
        if type(intent[field]) is not str or re.fullmatch(r"[0-9a-f]{64}", intent[field]) is None:
            return False
    oid = intent["lease_oid"]
    if oid is not None and (type(oid) is not str or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid) is None):
        return False
    if type(intent.get("writer_stopped", False)) is not bool:
        return False
    released = intent.get("released_lease_ids", [])
    if type(released) is not list or released not in ([], [oid]) or (released and oid is None):
        return False
    text_valid(intent["reason"], empty=True)
    text_valid(intent["caller"], 200)
    row = state["items"].get(intent["id"])
    return (row is not None and row["state"] == "claimed" and row["lane"] == intent["lane"]
            and row["revision"] == intent["revision"])


def recovery_refusal(intent, *, cause=None):
    """Give every pending refusal a concrete, safely quoted retry command."""
    command = ("aegis team queue unclaim " + shlex.quote(intent["id"]) +
               " --lane " + shlex.quote(intent["lane"]) + " --expect " + intent["revision"] +
               " --writer-stopped")
    blockers = [{
        "refused": True, "reason": "unclaim_recovery_required",
        "item_id": intent["id"], "lane": intent["lane"], "revision": intent["revision"],
        "caller": intent["caller"], "reason_text": intent["reason"],
        "next_action": "Retry as the recorded caller: " + command}]
    if cause == "queue_size_limit":
        blockers.append({"refused": True, "reason": cause,
            "next_action": "Complete the recorded unclaim recovery, then run aegis team queue compact before work needing more queue space."})
    return ClaimRefusal("unclaim_recovery_required", blockers)


def _lease_refusal(lane, oid):
    command = (f"aegis team release {lane} --expect {oid}" if team.valid_lane(lane)
               else "aegis team list --json; ask the coordinator to repair the unreadable ref")
    return ClaimRefusal("unclaim_lease_refused", [{"lane": lane, "lease_oid": oid,
        "reason": "unclaim_lease_refused", "refused": True,
        "next_action": "Inspect the covering lease before retrying: " + command}])


def _preflight(root, row, lane, caller, now):
    found = team.read_leases(root)
    scope = team_paths.claim_paths(row["item"]["paths"])
    for bad in found.unreadable:
        raise _lease_refusal(bad.lane, bad.oid)
    selected = None
    for lease in found.leases:
        if not team_paths.overlap(lease.path_set, scope):
            continue
        if lease.lane != lane:
            if not lease.expired(now):
                raise _lease_refusal(lease.lane, lease.oid)
            continue
        if lease.owner != caller:
            raise _lease_refusal(lease.lane, lease.oid)
        selected = lease.oid
    return selected


def _event_state(root, correlation, decode):
    """Read once; initial admission reserves a margin, recovery allows slack."""
    limit = MAX_EVENT_BYTES + EVENT_MARGIN if correlation is not None else MAX_EVENT_BYTES
    try:
        target = events.events_path(root)
        with storage.confined_file(target.parent, (target.name,)) as handle:
            raw = handle.read_bytes(limit)
    except storage.ConfinedFileError as error:
        if error.reason == "missing":
            raw = b""
        else:
            raise ClaimRefusal("unclaim_event_unavailable") from None
    except (OSError, ValueError, RuntimeError, gitsafe.GitError):
        raise ClaimRefusal("unclaim_event_unavailable") from None
    if correlation is None and len(raw) > MAX_EVENT_BYTES - EVENT_MARGIN:
        raise ClaimRefusal("unclaim_event_unavailable")
    if raw and not raw.endswith(b"\n"):
        raise ClaimRefusal("unclaim_event_unavailable")
    receipt = None
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            row = decode(line, "invalid_queue_state")
        except ValueError:
            raise ClaimRefusal("unclaim_event_unavailable") from None
        if type(row) is not dict:
            raise ClaimRefusal("unclaim_event_unavailable")
        detail = row.get("detail")
        if (correlation is not None and row.get("event") == "lease_claimed" and
                row.get("result") == "queue_unclaim" and type(detail) is dict and
                detail.get("unclaim_id") == correlation):
            if receipt is not None:
                raise ClaimRefusal("unclaim_event_unavailable")
            receipt = detail
    return receipt


def _record(root, intent, shown):
    detail = {"queue": True, "action": "unclaim", "unclaim_id": intent["to_revision"],
              "item_id": intent["id"], "lane": intent["lane"], "caller": intent["caller"],
              "reason": intent["reason"], "writer_stopped": True,
              "from_revision": intent["revision"], "to_revision": intent["to_revision"],
              "from_state": "claimed", "to_state": "queued",
              "released_lease_ids": intent.get("released_lease_ids", [])}
    if events.try_append(root, "lease_claimed", "queue_unclaim", shown(detail)) is not None:
        raise recovery_refusal(intent)


def _initial_intent(root, state, identifier, expect, lane, reason, caller, now, decode):
    if identifier in state["completed"]:
        raise ClaimRefusal("item_done")
    row = state["items"].get(identifier)
    if row is None:
        raise ClaimRefusal("item_missing")
    if row["revision"] != expect:
        raise ClaimRefusal("stale_revision")
    if row["state"] == "done":
        raise ClaimRefusal("item_done")
    if row["state"] != "claimed":
        raise ClaimRefusal("not_claimed")
    if row["lane"] != lane:
        raise ClaimRefusal("lane_mismatch")
    oid = _preflight(root, row, lane, caller, now)
    _event_state(root, None, decode)
    return {"id": identifier, "revision": expect, "lane": lane, "caller": caller,
            "reason": reason, "lease_oid": oid, "to_revision": secrets.token_hex(32),
            "writer_stopped": True, "released_lease_ids": []}


def _check_leases(root, state, intent, now, *, released=False):
    oid = intent["lease_oid"]
    selected = _preflight(root, state["items"][intent["id"]], intent["lane"], intent["caller"], now)
    if oid is None:
        if selected is not None:
            raise _lease_refusal(intent["lane"], selected)
    else:
        current = gitsafe.read_ref(root, team.lane_ref(intent["lane"]))
        if (released and current is not None) or (not released and current not in (None, oid)):
            raise _lease_refusal(intent["lane"], current or oid)


def _release_lease(root, lane, oid, *, caller, shown):
    """Use the existing strict CAS transport without inferring deletion from absence.

    The legacy release facade deliberately accepts lost acknowledgements. Here
    only 'updated' proves our call removed this OID; 'already' remains uncertain.
    """
    ref = team.lane_ref(lane)
    current = gitsafe.read_ref(root, ref)
    if current != oid:
        raise team.LeaseRefused("lease changed", "stale", lane, current=current)
    try:
        outcome = gitsafe.update_ref(root, ref, None, oid, single_attempt=True)
    except gitsafe.RefConflict as error:
        raise team.LeaseRefused("lease changed", "stale", lane, current=error.current) from None
    except gitsafe.GitError as error:
        if error.code == "ref_update_failed":
            raise team.LeaseRefused("lease release refused", "stale", lane, current=oid) from None
        raise
    if outcome != "updated":
        return False
    events.try_append(root, "lease_claimed", "released", shown({
        "lane": lane, "oid": None, "previous": oid, "caller": caller, "owner": caller}))
    return True


def _release(root, state, intent, now, recovering, receipt, publish, progress):
    """Only a successful call acknowledges our deletion; absence attests nothing."""
    _check_leases(root, state, intent, now)
    oid = intent["lease_oid"]
    if oid is None:
        return
    current = gitsafe.read_ref(root, team.lane_ref(intent["lane"]))
    if recovering and current is None:
        return
    if recovering and receipt is not None:
        raise recovery_refusal(intent)
    progress["release_attempted"] = True
    try:
        confirmed = _release_lease(root, intent["lane"], oid, caller=intent["caller"], shown=progress["shown"])
    except team.LeaseRefused:
        progress["release_attempted"] = False
        raise
    if not confirmed:
        raise recovery_refusal(intent)
    intent["released_lease_ids"] = [oid]
    publish(root, state)


def transition(root, state, *, identifier, expect, lane, reason, caller, writer_stopped,
               now, publish, restore, shown, decode):
    """Separate rollback-capable initial execution from irreversible recovery."""
    recovering = "unclaim" in state
    intent = state.get("unclaim")
    progress = {"release_attempted": False, "receipt": False, "shown": shown}
    try:
        if recovering:
            if ((intent["id"], intent["revision"], intent["lane"], intent["caller"]) != (
                    identifier, expect, lane, caller) or (reason and reason != intent["reason"])):
                raise recovery_refusal(intent)
            receipt = _event_state(root, intent["to_revision"], decode)
            if receipt is not None:
                if (receipt.get("writer_stopped") is not True or
                        receipt.get("released_lease_ids") != intent.get("released_lease_ids", [])):
                    raise recovery_refusal(intent)
                progress["receipt"] = True
            intent["writer_stopped"] = writer_stopped
        else:
            intent = _initial_intent(root, state, identifier, expect, lane, reason, caller, now, decode)
            state["unclaim"] = intent
            receipt = None
            # Failure here is ambiguous: publication may have landed.
            try:
                publish(root, state)
            except (OSError, RuntimeError, gitsafe.GitError):
                raise recovery_refusal(intent) from None
        _release(root, state, intent, now, recovering, receipt, publish, progress)
        _check_leases(root, state, intent, now, released=intent["lease_oid"] is not None)
        if receipt is None:
            _record(root, intent, shown)
            progress["receipt"] = True
        _check_leases(root, state, intent, now, released=intent["lease_oid"] is not None)
        row = dict(state["items"][identifier])
        row.update(state="queued", lane=None, expires_at=None, revision=intent["to_revision"])
        row.pop("branch", None)
        final = {key: value for key, value in state.items() if key != "unclaim"}
        final["items"] = {**state["items"], identifier: row}
        publish(root, final, before_publish=lambda: _check_leases(
            root, state, intent, now, released=intent["lease_oid"] is not None))
        return {"row": row, "released_lease_ids": intent.get("released_lease_ids", []), "state": final}
    except (ClaimRefusal, team.LeaseRefused) as error:
        if intent is None or (not recovering and "unclaim" not in state):
            raise
        if recovering or progress["release_attempted"] or progress["receipt"] or (
                isinstance(error, ClaimRefusal) and error.reason == "unclaim_recovery_required"):
            raise recovery_refusal(intent) from None
        restore()
        if isinstance(error, team.LeaseRefused):
            raise _lease_refusal(lane, error.current or intent["lease_oid"]) from None
        raise
    except (OSError, ValueError, RuntimeError, gitsafe.GitError) as error:
        if intent is not None:
            size_failure = isinstance(error, ValueError) and getattr(error, "reason", None) == "queue_size_limit"
            if not recovering and not progress["release_attempted"] and not progress["receipt"]:
                restore()
                raise ClaimRefusal("queue_size_limit" if size_failure else "queue_io_unavailable") from None
            raise recovery_refusal(intent, cause="queue_size_limit" if size_failure else None) from None
        raise


def _git_marker(root):
    """Distinguish a non-repository from failure in a marked repository."""
    try:
        with storage.confined_file(root, (".git", "queue-probe")) as handle:
            handle.parent_stat()
            return True
    except storage.ConfinedFileError as error:
        if error.reason == "missing":
            return False
    try:
        with storage.confined_file(root, (".git",)) as handle:
            handle.read_bytes(32768)
            return True
    except storage.ConfinedFileError:
        raise ClaimRefusal("queue_io_unavailable") from None


def observe_leases(root):
    """A Git start/timeout failure always propagates; only non-Git is unchecked."""
    probe = gitsafe.run(["rev-parse", "--is-inside-work-tree"], root)
    if probe.returncode == 0:
        return team.read_leases(root), True
    if _git_marker(root):
        raise ClaimRefusal("queue_io_unavailable")
    return team.LeaseSet((), ()), False


def fingerprint(state, found, now, claimable, lanes, policy, leases_checked):
    """Hash the complete scheduling inputs and shared-check claimable set."""
    facts = {"claimable": sorted(claimable), "state": state, "lanes": lanes,
             "profile": policy, "leases_checked": leases_checked,
             "live_claims": sorted(key for key, row in state["items"].items()
                                   if row["state"] == "claimed" and row["expires_at"] > now),
             "live_leases": sorted([lease.lane, lease.oid] for lease in found.leases if not lease.expired(now)),
             "unreadable": sorted([bad.lane, bad.oid] for bad in found.unreadable)}
    return hashlib.sha256(json.dumps(facts, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
