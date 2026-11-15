"""One CI event snapshot and its pinned comparison and approval policy."""
from __future__ import annotations

from dataclasses import dataclass, replace
import json
import os
import re


@dataclass(frozen=True)
class Event:
    name: str | None
    document: dict
    ref: str = ""
    malformed: bool = False


@dataclass(frozen=True)
class Inputs:
    resolution: object
    head: str
    head_commit: str | None
    pull: object
    target: str | None
    policy: object


_LOGIN = re.compile(r"[A-Za-z0-9-]{1,39}")
_MAX_EVENT_BYTES = 25 * 1024 * 1024


class CiEventError(ValueError):
    """Event input cannot safely identify the comparison or its target."""


CI_EVENT_ACTION = "provide a valid CI event or run locally with --base"
CI_EVENT_ERROR = f"invalid_ci_event: invalid event data; next_action: {CI_EVENT_ACTION}"


def read_event(field="pull_request", *, strict=False) -> dict:
    """The ``pull_request`` object of the event file GitHub Actions names in $GITHUB_EVENT_PATH; {} anywhere else."""
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path:
        return {}
    try:
        with open(path, "rb") as handle:
            # The runner supplies this path; only its contents are repository-controlled.
            if os.fstat(handle.fileno()).st_size > _MAX_EVENT_BYTES:
                raise CiEventError(CI_EVENT_ERROR)
            data = handle.read(_MAX_EVENT_BYTES + 1)
            if len(data) > _MAX_EVENT_BYTES:
                if strict:
                    raise CiEventError(CI_EVENT_ERROR)
                return {}
            document = json.loads(data.decode("utf-8"))
            if strict and not isinstance(document, dict):
                raise CiEventError(CI_EVENT_ERROR)
            pull = (document if field is None else document.get(field)) or {}
    except (OSError, ValueError, TypeError, AttributeError, RecursionError):
        if strict:
            raise CiEventError(CI_EVENT_ERROR) from None
        return {}
    return pull if isinstance(pull, dict) else {}


def _event_shas(document) -> tuple[str | None, str | None]:
    """(base, head) commit ids of the pull request this CI job runs for; (None, None) anywhere else."""
    try:
        pull = document.get("pull_request")
        return pull["base"]["sha"], pull["head"]["sha"]
    except (KeyError, TypeError):
        return None, None


def event_pull_request(event):
    """The pull request of a ``pull_request`` or ``pull_request_target`` run (the base-sourced governance
    job), for tier A's review approval: its number, author, full head commit id and base branch, each
    checked; None for any other event or any value in doubt (no gh call then)."""
    from aegis_core import human_gate

    document = event.document
    if event.name not in ("pull_request", "pull_request_target"):
        return None
    try:
        pull = document.get("pull_request")
        number, login, sha, ref = pull["number"], pull["user"]["login"], pull["head"]["sha"], pull["base"]["ref"]
    except (KeyError, TypeError):
        return None
    if type(number) is not int or number < 1 or number.bit_length() > 63 \
            or not isinstance(login, str) or len(login) > 39 or not _LOGIN.fullmatch(login) \
            or not _event_oid(sha) or not human_gate.is_branch_name(ref):
        return None
    return human_gate.PullRequest(number, login, sha.lower(), ref)


def _event_oid(value):
    from aegis_core import approval_policy

    return isinstance(value, str) and len(value) in (40, 64) and approval_policy.FULL_OID.fullmatch(value) is not None


def validate_event(event):
    """Refuse malformed comparison data before policy discovery or any Git lookup.

    Absent push predecessors retain the documented base-unavailable/fallback
    semantics. Supplied commit identities must be bounded full OIDs even when
    an explicit comparison would otherwise bypass that field.
    """
    if event.malformed or not isinstance(event.document, dict):
        raise CiEventError(CI_EVENT_ERROR)
    if event.name in ("pull_request", "pull_request_target"):
        pull = event.document.get("pull_request")
        if not isinstance(pull, dict):
            raise CiEventError(CI_EVENT_ERROR)
        for field in ("base", "head"):
            entry = pull.get(field)
            if not isinstance(entry, dict) or not _event_oid(entry.get("sha")):
                raise CiEventError(CI_EVENT_ERROR)
        anchor = pull["base"]
        if "ref" in anchor and (not isinstance(anchor["ref"], str) or len(anchor["ref"]) > 255 or "\0" in anchor["ref"]):
            raise CiEventError(CI_EVENT_ERROR)
    elif event.name == "push":
        if not isinstance(event.ref, str) or len(event.ref) > 8 * 1024 or "\0" in event.ref:
            raise CiEventError(CI_EVENT_ERROR)
        for field in ("before", "after"):
            value = event.document.get(field)
            if value is not None and not _event_oid(value):
                raise CiEventError(CI_EVENT_ERROR)
    return event_pull_request(event)


def _ci_policy_context(event, explicit_base, *, resolved_target=None):
    """The event may constrain a verified target, but cannot upgrade an unknown one."""
    from aegis_core import human_gate

    if event.name in ("pull_request", "pull_request_target"):
        anchor = event.document["pull_request"]["base"]
        ref = anchor.get("ref")
        if explicit_base:
            return resolved_target if resolved_target == ref else None
        return ref if human_gate.is_branch_name(ref) else None
    if event.name == "push":
        full_ref = event.ref
        ref = (full_ref[len("refs/heads/"):] if len(full_ref) <= len("refs/heads/") + 255
               and full_ref.startswith("refs/heads/") else None)
        if explicit_base:
            return resolved_target if resolved_target == ref else None
        return ref if human_gate.is_branch_name(ref) else None
    return resolved_target


def resolve_inputs(root, args, event):
    """Resolve once from an already parsed event, including its captured name."""
    from aegis_core import approval_policy, gitsafe

    pull = validate_event(event)
    event_base, event_head = _event_shas(event.document) if event.name in ("pull_request", "pull_request_target") else (None, None)
    head = getattr(args, "head", None) or event_head or "HEAD"
    with gitsafe.scrubbed():
        explicit = getattr(args, "base", None)
        if explicit == "":
            explicit = None
        selector = explicit if explicit is not None else event_base or gitsafe.resolve_base_ref(root)
        resolved = approval_policy.resolve_comparison(root, selector, discovered=explicit is None)
        base = resolved.commit
        strict = approval_policy.policy_present_at(root, base)
        head_commit = gitsafe.resolve_commit(root, head)
        if event.name == "push":
            base = approval_policy.push_base(root, event.document.get("before"), base, head,
                                             explicit=explicit is not None, label=selector,
                                             resolved=resolved, pinned_head=head_commit)
        if selector is not None and not base:
            raise approval_policy.BaseUnavailable("base_unavailable: comparison branch is unavailable",
                explicit_base=selector if explicit is not None else None, comparison_base=selector)
        if base != resolved.commit:
            strict = approval_policy.policy_present_at(root, base)
        target = _ci_policy_context(event, explicit, resolved_target=resolved.target)
        policy = approval_policy.resolve_policy(root, base, head_commit, target) if base and head_commit else None
        resolved = replace(resolved, commit=base, target=target,
                           ref=resolved.ref if base == resolved.commit else None)
        if strict:
            head = head_commit or head
    return Inputs(resolved, head, head_commit, pull, target, policy)
