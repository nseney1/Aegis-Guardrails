"""Recoverable queue/lease transitions under the workspace writer lock.

Initial refusals restore the exact queue bytes until release may have landed.
Recovery preserves intent and requires the original operation and stopped-writer
acknowledgement. Owner-UID rewriting of owner-managed records is out of scope.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex

try:
    import pwd
except ImportError:  # Windows has no passwd database.
    pwd = None

from aegis_core import events, gitsafe, storage, team, team_paths, team_writer_binding
from aegis_core.primitives import sanitize_display
from aegis_core.redaction import redact_command_secrets

__all__ = ["ClaimRefusal", "validate_pending", "transition", "fingerprint",
           "recovery_refusal", "observe_leases", "check_writer", "reconcile_completed"]

MAX_RECEIPT_BYTES = 65536
_LEASE_OID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}\Z")
_CAUSE_REASONS = ("queue_size_limit", "unclaim_event_unavailable", "unclaim_lease_refused", "queue_io_unavailable")
_WRITER_REASONS = frozenset(("writer_live", "writer_not_stopped", "identity_unavailable",
    "binding_scope_mismatch", "bindings_unavailable", "writer_absent", "writer_replaced"))


def _passwd_home():
    """Use the owner account, never a model-supplied HOME override."""
    return pwd.getpwuid(os.getuid()).pw_dir


_LEASE_ERRORS = (AttributeError, ImportError, KeyError, OSError, ValueError, RuntimeError)


class _CoveringLeases:
    """The first outcome of each covering object read within one locked unclaim."""

    def __init__(self, root, lane):
        self.root = root
        self.lane = lane
        self._outcomes = {}

    def read(self, root, lane, oid):
        if root != self.root or lane != self.lane:
            return None
        if oid not in self._outcomes:
            try:
                data = gitsafe.read_object(root, oid, team.MAX_LEASE_BYTES)
                outcome = team.parse_lease(data, lane, oid)
            except _LEASE_ERRORS + (gitsafe.GitError,):
                outcome = team.Unreadable(lane, team.lane_ref(lane), oid, "unreadable")
            self._outcomes[oid] = outcome
        return self._outcomes[oid]


def _writer_verdict(root, lane, oid, covering):
    """Judge only the covering claim, even after its ref was released in recovery.

    Absence is the binding observation ``no_binding_config`` published by the
    real ``judge``. A storage failure is never treated as a missing config, a
    replaced ``judge`` keeps the reason it returned, and the object is not read
    again. A non-string reason is refused before that absence fact is read.
    """
    if oid is None:
        return "no_bound_liveness_source"
    try:
        lease = covering.read(root, lane, oid)
        if not isinstance(lease, team.Lease):
            return "bindings_unavailable"
        home = _passwd_home()
        token = team_writer_binding.observation_token()
        verdict = team_writer_binding.judge(home, team.LeaseSet((lease,), ()), {})
        if type(verdict) is not dict:
            return "bindings_unavailable"
        reason = verdict.get("reason")
        if type(reason) is not str:
            return "bindings_unavailable"
        observed = team_writer_binding.observation_since(token)
        if (reason == "bindings_unavailable" and type(observed) is dict
                and observed.get("binding") == "no_binding_config"):
            return "no_bound_liveness_source"
        if reason in _WRITER_REASONS or reason in ("writer_bound", "no_bound_liveness_source"):
            return reason
    except _LEASE_ERRORS + (gitsafe.GitError,):
        pass
    return "bindings_unavailable"


def _check_writer(root, lane, oid, writer_stopped, *, covering=None):
    """A verified live writer defeats acknowledgement; uncertainty requires it."""
    if covering is None:
        covering = _CoveringLeases(root, lane)
    reason = _writer_verdict(root, lane, oid, covering)
    if reason == "writer_bound":
        raise ClaimRefusal("writer_live")
    if not writer_stopped:
        raise ClaimRefusal("writer_not_stopped" if reason == "no_bound_liveness_source" else reason)


def check_writer(root, state, identifier, lane, writer_stopped):
    """Check the current claim before input/state refusals, under the workspace lock.

    A stale requested revision must not hide the item's actual live writer.
    Recovery retains the original immutable lease after its ref is released.
    Return the operation's covering observations. An unreadable ref is remembered
    without becoming the checked oid, preserving the initial no-ack refusal.
    """
    intent = state.get("unclaim")
    oid = None
    if intent is not None and intent["id"] == identifier:
        lane, oid = intent["lane"], intent["lease_oid"]
        row = None
    else:
        row = state["items"].get(identifier)
        if row is not None and row["state"] != "claimed":
            row = None
        if row is not None:
            lane = row["lane"]
    covering = _CoveringLeases(root, lane)
    if row is not None:
        lease = team.read_leases(root, observe=covering.read).get(lane)
        if lease is not None and team_paths.overlap(
                lease.path_set, team_paths.claim_paths(row["item"]["paths"])):
            oid = lease.oid
    _check_writer(root, lane, oid, writer_stopped, covering=covering)
    return covering


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


# Same bound as valid_workspace_spelling, applied before any display scan.
_WORKSPACE_SPELLING_LIMIT = 32768
_WORKSPACE_SEPARATORS = 256
RECOVERY_TEXT_LIMIT = 4096
_RETURN_TO_WORKSPACE = (
    "return to the workspace that issued this command; its path cannot be shown safely")


def _single_line(text):
    """True when text has no control, C1, or Unicode line separator."""
    return not any(ord(char) < 32 or 127 <= ord(char) <= 159 or char in "\u2028\u2029"
                   for char in text)


def _workspace_spelling(root):
    """Absolute spelling that can be shown unchanged, or None. Does not touch the filesystem."""
    text = str(root) if isinstance(root, Path) else root
    if (type(text) is not str or not text or len(text) > _WORKSPACE_SPELLING_LIMIT or
            text.count("/") + text.count("\\") > _WORKSPACE_SEPARATORS or not _single_line(text) or
            not Path(text).is_absolute() or ".." in re.split(r"[\\/:]", text)):
        return None
    try:
        encoded = text.encode("utf-8", "strict")
        if encoded.decode("utf-8", "strict") != text:
            return None
    except UnicodeError:
        return None
    if sanitize_display(text, max_len=None) != text or redact_command_secrets(text) != text:
        return None
    return text


def _display_stable(text, limit):
    """Canonicalize, then redact, then truncate. Identity means nothing was altered."""
    if type(text) is not str or len(text) > limit or not _single_line(text):
        return False
    canonical = sanitize_display(text, max_len=None)
    if canonical != text:
        return False
    redacted = redact_command_secrets(canonical)
    if redacted != text:
        return False
    return sanitize_display(redacted, max_len=limit) == text


def _quote_workspace(text, room):
    """Quote only after the unquoted spelling fits. A longer quote is not emitted."""
    if room < 1 or len(text) > room:
        return None
    quoted = shlex.quote(text)
    if len(quoted) > room:
        return None
    try:
        parts = shlex.split(quoted)
    except ValueError:
        return None
    if parts != [text]:
        return None
    return quoted


def _anchored(root, command, *, prefix="", trailer=""):
    """One faithful ``--workspace``, or an explicit return sentence. Never both."""
    limit = RECOVERY_TEXT_LIMIT
    phrase = _RETURN_TO_WORKSPACE
    hidden = prefix + command + "; " + phrase + trailer
    spelling = _workspace_spelling(root)
    if spelling is not None:
        room = limit - len(prefix) - len(command) - len(" --workspace ") - len(trailer)
        quoted = _quote_workspace(spelling, room)
        if quoted is not None:
            field = prefix + command + " --workspace " + quoted + trailer
            if _display_stable(field, limit):
                return field
    if _display_stable(hidden, limit):
        return hidden
    return phrase


def _cause_blocker(cause, lane, lease_oid, root):
    """One fixed category plus lane, lease OID, and action when those are already safe."""
    if cause not in _CAUSE_REASONS:
        return None
    if cause == "queue_size_limit":
        return {"refused": True, "reason": cause, "next_action": _anchored(
            root, "aegis team queue compact",
            prefix="Complete the recorded unclaim recovery, then run ",
            trailer=" before work needing more queue space.")}
    if cause == "unclaim_event_unavailable":
        return {"refused": True, "reason": cause,
            "next_action": "Ask the coordinator to reconcile the unreadable or inconsistent private unclaim receipt from trusted evidence before retrying unclaim."}
    if cause == "queue_io_unavailable":
        return {"refused": True, "reason": cause,
            "next_action": "Check the trusted workspace and retry the recorded unclaim."}
    entry = {"refused": True, "reason": "unclaim_lease_refused"}
    safe_lane = lane if team.valid_lane(lane) else None
    safe_oid = lease_oid if type(lease_oid) is str and _LEASE_OID.fullmatch(lease_oid) else None
    if safe_lane is not None:
        entry["lane"] = safe_lane
    if safe_oid is not None:
        entry["lease_oid"] = safe_oid
    if safe_lane is not None and safe_oid is not None:
        entry["next_action"] = _anchored(
            root, "aegis team release " + safe_lane + " --expect " + safe_oid,
            prefix="Inspect the covering lease before retrying: ")
    else:
        entry["next_action"] = _anchored(
            root, "aegis team list --json", trailer="; ask the coordinator to repair the unreadable ref")
    return entry


def _recovery_cause(error):
    """Classify a refusal without copying its message, path, or unsanitized fields."""
    if isinstance(error, team.LeaseRefused):
        return "unclaim_lease_refused", getattr(error, "lane", None), getattr(error, "current", None)
    if not isinstance(error, ClaimRefusal):
        return None, None, None
    if error.reason == "unclaim_lease_refused":
        blocker = error.blockers[0] if error.blockers else {}
        return "unclaim_lease_refused", blocker.get("lane"), blocker.get("lease_oid")
    if error.reason in ("unclaim_event_unavailable", "queue_size_limit", "queue_io_unavailable"):
        return error.reason, None, None
    if error.reason == "unclaim_recovery_required":
        for blocker in error.blockers or ():
            reason = blocker.get("reason")
            if reason in _CAUSE_REASONS:
                return reason, blocker.get("lane"), blocker.get("lease_oid")
    return None, None, None


def recovery_refusal(intent, *, root=None, cause=None, lane=None, lease_oid=None):
    """Give every pending refusal a concrete, safely quoted retry command."""
    command = ("aegis team queue unclaim " + shlex.quote(intent["id"]) +
               " --lane " + shlex.quote(intent["lane"]) + " --expect " + intent["revision"] +
               " --writer-stopped")
    blockers = [{
        "refused": True, "reason": "unclaim_recovery_required",
        "item_id": intent["id"], "lane": intent["lane"], "revision": intent["revision"],
        "caller": intent["caller"], "reason_text": intent["reason"],
        "next_action": _anchored(root, command, prefix="Retry as the recorded caller: ")}]
    extra = _cause_blocker(cause, lane, lease_oid, root)
    if extra is not None:
        blockers.append(extra)
    return ClaimRefusal("unclaim_recovery_required", blockers)


def _lease_refusal(root, lane, oid):
    if team.valid_lane(lane):
        command = f"aegis team release {lane} --expect {oid}"
        trailer = ""
    else:
        command = "aegis team list --json"
        trailer = "; ask the coordinator to repair the unreadable ref"
    return ClaimRefusal("unclaim_lease_refused", [{"lane": lane, "lease_oid": oid,
        "reason": "unclaim_lease_refused", "refused": True,
        "next_action": _anchored(root, command, prefix="Inspect the covering lease before retrying: ",
                                 trailer=trailer)}])


def _preflight(root, row, lane, caller, now, covering):
    found = team.read_leases(root, observe=covering.read)
    scope = team_paths.claim_paths(row["item"]["paths"])
    for bad in found.unreadable:
        raise _lease_refusal(root, bad.lane, bad.oid)
    selected = None
    for lease in found.leases:
        if not team_paths.overlap(lease.path_set, scope):
            continue
        if lease.lane != lane:
            if not lease.expired(now):
                raise _lease_refusal(root, lease.lane, lease.oid)
            continue
        if lease.owner != caller:
            raise _lease_refusal(root, lease.lane, lease.oid)
        selected = lease.oid
    return selected


def _receipt_file(root, token, *, create=False):
    """Only a validated transaction ID can select a queue-owned receipt."""
    if type(token) is not str or len(token) != 64 or re.fullmatch(r"[0-9a-f]{64}", token) is None:
        raise ClaimRefusal("unclaim_event_unavailable")
    return storage.confined_file(storage.state_dir(root),
                                ("unclaim-receipts", token + ".json"), create_parents=create)


def _receipt_detail(intent):
    return {"queue": True, "action": "unclaim", "unclaim_id": intent["to_revision"],
            "item_id": intent["id"], "lane": intent["lane"], "caller": intent["caller"],
            "reason": intent["reason"], "writer_stopped": True,
            "from_revision": intent["revision"], "to_revision": intent["to_revision"],
            "from_state": "claimed", "to_state": "queued",
            "released_lease_ids": intent.get("released_lease_ids", [])}


def _receipt_matches(detail, intent):
    return (type(detail) is dict and detail.get("writer_stopped") is True
            and detail.get("queue") is True and detail == _receipt_detail(intent))


def _read_receipt(root, token, decode):
    """Read only this ID, bounding the regular file before allocation/parsing."""
    try:
        with _receipt_file(root, token) as handle:
            raw = handle.read_bytes(MAX_RECEIPT_BYTES)
        detail = decode(raw, "invalid_queue_state")
        if type(detail) is not dict:
            raise ClaimRefusal("unclaim_event_unavailable")
        return detail
    except storage.ConfinedFileError as error:
        if error.reason == "missing":
            return None
        raise ClaimRefusal("unclaim_event_unavailable") from None
    except (OSError, ValueError, RuntimeError, gitsafe.GitError):
        raise ClaimRefusal("unclaim_event_unavailable") from None


def _receipt_state(root, intent, decode):
    detail = _read_receipt(root, intent["to_revision"], decode)
    if detail is not None and not _receipt_matches(detail, intent):
        raise ClaimRefusal("unclaim_event_unavailable")
    return detail


def _write_receipt(root, intent):
    """Exclusive publication under the caller's workspace lock; never overwrite."""
    detail = _receipt_detail(intent)
    # A conservative ASCII-JSON bound, before serialization or encoding. Queue
    # validation already bounds each field; even all-astral reasons fit this cap.
    strings = [value for value in detail.values() if type(value) is str]
    strings.extend(detail["released_lease_ids"])
    if 1024 + sum(12 * len(value) for value in strings) > MAX_RECEIPT_BYTES:
        raise ClaimRefusal("unclaim_event_unavailable")
    data = json.dumps(detail, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    with _receipt_file(root, intent["to_revision"], create=True) as handle:
        handle.publish_bytes(data, replace=False, mode=0o600)


def _remove_receipt(root, token):
    try:
        with _receipt_file(root, token) as handle:
            handle.remove()
    except storage.ConfinedFileError as error:
        if error.reason != "missing":
            raise ClaimRefusal("queue_io_unavailable") from None
    except (OSError, ValueError, RuntimeError, gitsafe.GitError):
        raise ClaimRefusal("queue_io_unavailable") from None


def _record(root, intent, shown):
    """Metrics are best-effort and never transaction evidence."""
    try:
        events.try_append(root, "lease_claimed", "queue_unclaim", shown(_receipt_detail(intent)))
    except (OSError, ValueError, RuntimeError, gitsafe.GitError):
        pass


def _completed_intent(row, detail):
    """Prove completion from the current queued revision and a strict receipt."""
    caller, lane = detail.get("caller"), detail.get("lane")
    revision = detail.get("from_revision")
    reason, released = detail.get("reason"), detail.get("released_lease_ids")
    # JSON escapes can decode to lone surrogates despite display stability.
    if (row["state"] != "queued" or not _display_stable(caller, 200) or not caller or
            type(lane) is not str or len(lane) > 64 or not team.valid_lane(lane) or
            type(revision) is not str or len(revision) != 64 or
            re.fullmatch(r"[0-9a-f]{64}", revision) is None or
            not _display_stable(reason, RECOVERY_TEXT_LIMIT) or
            any(0xD800 <= ord(char) <= 0xDFFF for text in (caller, reason) for char in text) or
            type(released) is not list or len(released) > 1 or
            any(type(oid) is not str or len(oid) > 64 or not _LEASE_OID.fullmatch(oid) for oid in released)):
        raise ClaimRefusal("unclaim_event_unavailable")
    intent = {"id": row["item"]["id"], "revision": revision, "to_revision": row["revision"],
              "lane": lane, "caller": caller, "reason": reason,
              "released_lease_ids": released}
    if not _receipt_matches(detail, intent):
        raise ClaimRefusal("unclaim_event_unavailable")
    return intent


def reconcile_completed(root, row, decode):
    """Before replacing a revision, retire its completed receipt under the lock.

    The caller validates the resulting queue first. Even an absent receipt is
    removed idempotently so a prior unlink/fsync failure cannot resurface an
    unreachable file after the revision changes. No metrics log is consulted.
    """
    if row is None:
        return
    detail = _read_receipt(root, row["revision"], decode)
    if detail is not None:
        _completed_intent(row, detail)
    _remove_receipt(root, row["revision"])


def _finished_unclaim(root, state, identifier, expect, lane, caller, reason, decode):
    """Recover a crash between the final queue publication and receipt removal."""
    row = state["items"].get(identifier)
    if row is None or row["state"] != "queued" or row["revision"] == expect:
        return None
    detail = _read_receipt(root, row["revision"], decode)
    if detail is None:
        return None
    intent = _completed_intent(row, detail)
    if ((expect, lane, caller) != (intent["revision"], intent["lane"], intent["caller"]) or
            (reason and reason != intent["reason"])):
        raise ClaimRefusal("stale_revision")
    _remove_receipt(root, row["revision"])
    return {"row": row, "released_lease_ids": intent["released_lease_ids"], "state": state}


def _initial_intent(root, state, identifier, expect, lane, reason, caller, now, writer_stopped, covering):
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
    oid = _preflight(root, row, lane, caller, now, covering)
    _check_writer(root, lane, oid, writer_stopped, covering=covering)
    return {"id": identifier, "revision": expect, "lane": lane, "caller": caller,
            "reason": reason, "lease_oid": oid, "to_revision": secrets.token_hex(32),
            "writer_stopped": True, "released_lease_ids": []}


def _check_leases(root, state, intent, now, covering, *, released=False):
    oid = intent["lease_oid"]
    _check_writer(root, intent["lane"], oid, intent["writer_stopped"], covering=covering)
    selected = _preflight(root, state["items"][intent["id"]], intent["lane"], intent["caller"], now, covering)
    if oid is None:
        if selected is not None:
            raise _lease_refusal(root, intent["lane"], selected)
    else:
        current = gitsafe.read_ref(root, team.lane_ref(intent["lane"]))
        if (released and current is not None) or (not released and current not in (None, oid)):
            raise _lease_refusal(root, intent["lane"], current or oid)


def _release_lease(root, lane, oid, *, caller, shown, recovering=False):
    """Use the existing strict CAS transport without inferring deletion from absence.

    The legacy release facade deliberately accepts lost acknowledgements. Here
    only 'updated' proves our call removed this OID; 'already' remains uncertain.
    During recovery, an absent ref is not a deletion we performed: return None
    and leave released_lease_ids unchanged. The same observation through
    RefConflict is the same fact.
    """
    ref = team.lane_ref(lane)
    current = gitsafe.read_ref(root, ref)
    if current != oid:
        if recovering and current is None:
            return None
        raise team.LeaseRefused("lease changed", "stale", lane, current=current)
    try:
        outcome = gitsafe.update_ref(root, ref, None, oid, single_attempt=True)
    except gitsafe.RefConflict as error:
        if recovering and error.current is None:
            return None
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


def _release(root, state, intent, now, recovering, receipt, publish, progress, covering):
    """Only a successful call acknowledges our deletion; absence attests nothing."""
    _check_leases(root, state, intent, now, covering)
    oid = intent["lease_oid"]
    if oid is None:
        return
    current = gitsafe.read_ref(root, team.lane_ref(intent["lane"]))
    if recovering and current is None:
        return
    if recovering and receipt is not None:
        raise recovery_refusal(intent, root=root, cause="unclaim_lease_refused", lane=intent["lane"], lease_oid=current)
    progress["release_attempted"] = True
    try:
        confirmed = _release_lease(root, intent["lane"], oid, caller=intent["caller"],
                                   shown=progress["shown"], recovering=recovering)
    except team.LeaseRefused:
        progress["release_attempted"] = False
        raise
    if confirmed is None:
        progress["release_attempted"] = False
        return
    if not confirmed:
        raise recovery_refusal(intent, root=root, cause="unclaim_lease_refused", lane=intent["lane"], lease_oid=oid)
    intent["released_lease_ids"] = [oid]
    publish(root, state)


def transition(root, state, *, identifier, expect, lane, reason, caller, writer_stopped,
               now, publish, restore, shown, decode, covering=None):
    """Separate rollback-capable initial execution from irreversible recovery."""
    recovering = "unclaim" in state
    intent = state.get("unclaim")
    if covering is None:
        covering = _CoveringLeases(root, lane)
    progress = {"release_attempted": False, "receipt": False, "finalized": False, "shown": shown}
    try:
        if not recovering:
            finished = _finished_unclaim(root, state, identifier, expect, lane, caller, reason, decode)
            if finished is not None:
                return finished
        if recovering:
            if ((intent["id"], intent["revision"], intent["lane"], intent["caller"]) != (
                    identifier, expect, lane, caller) or (reason and reason != intent["reason"])):
                raise recovery_refusal(intent, root=root)
            _check_writer(root, lane, intent["lease_oid"], writer_stopped, covering=covering)
            receipt = _receipt_state(root, intent, decode)
            if receipt is not None:
                progress["receipt"] = True
            intent["writer_stopped"] = writer_stopped
        else:
            intent = _initial_intent(root, state, identifier, expect, lane, reason, caller, now,
                                     writer_stopped, covering)
            if _receipt_state(root, intent, decode) is not None:
                raise ClaimRefusal("unclaim_event_unavailable")
            state["unclaim"] = intent
            receipt = None
            # Failure here is ambiguous: publication may have landed.
            try:
                publish(root, state)
            except (OSError, RuntimeError, gitsafe.GitError):
                raise recovery_refusal(intent, root=root, cause="queue_io_unavailable") from None
        _release(root, state, intent, now, recovering, receipt, publish, progress, covering)
        _check_leases(root, state, intent, now, covering, released=intent["lease_oid"] is not None)
        if receipt is None:
            # Publication/fsync can fail after the exclusive link landed.
            progress["receipt"] = True
            _write_receipt(root, intent)
            _record(root, intent, shown)
        _check_leases(root, state, intent, now, covering, released=intent["lease_oid"] is not None)
        row = dict(state["items"][identifier])
        row.update(state="queued", lane=None, expires_at=None, revision=intent["to_revision"])
        row.pop("branch", None)
        final = {key: value for key, value in state.items() if key != "unclaim"}
        final["items"] = {**state["items"], identifier: row}
        publish(root, final, before_publish=lambda: _check_leases(
            root, state, intent, now, covering, released=intent["lease_oid"] is not None))
        progress["finalized"] = True
        # The queue is committed even if cleanup fails. A retry authenticates
        # this completed transaction from its remaining private receipt.
        _remove_receipt(root, intent["to_revision"])
        return {"row": row, "released_lease_ids": intent.get("released_lease_ids", []), "state": final}
    except (ClaimRefusal, team.LeaseRefused) as error:
        if intent is None or (not recovering and "unclaim" not in state):
            raise
        if isinstance(error, ClaimRefusal) and error.reason == "queue_io_unavailable" and progress["finalized"]:
            raise
        if isinstance(error, ClaimRefusal) and error.reason in _WRITER_REASONS:
            if not recovering and not progress["release_attempted"] and not progress["receipt"]:
                restore()
            raise
        if recovering or progress["release_attempted"] or progress["receipt"] or (
                isinstance(error, ClaimRefusal) and error.reason == "unclaim_recovery_required"):
            cause, cause_lane, lease_oid = _recovery_cause(error)
            # An absent ref is not an unreadable ref. Keep the intent OID when
            # the lease reader did not supply one.
            if isinstance(error, team.LeaseRefused) and cause == "unclaim_lease_refused" and lease_oid is None:
                lease_oid = intent.get("lease_oid")
            raise recovery_refusal(intent, root=root, cause=cause, lane=cause_lane, lease_oid=lease_oid) from None
        restore()
        if isinstance(error, team.LeaseRefused):
            raise _lease_refusal(root, lane, error.current or intent["lease_oid"]) from None
        raise
    except (OSError, ValueError, RuntimeError, gitsafe.GitError) as error:
        if intent is not None:
            size_failure = isinstance(error, ValueError) and getattr(error, "reason", None) == "queue_size_limit"
            if not recovering and not progress["release_attempted"] and not progress["receipt"]:
                restore()
                raise ClaimRefusal("queue_size_limit" if size_failure else "queue_io_unavailable") from None
            raise recovery_refusal(intent, root=root, cause="queue_size_limit" if size_failure else "queue_io_unavailable") from None
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
