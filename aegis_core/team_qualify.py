"""Tree-bound qualification records for the model-free custodian (Git ADR D12).

Only the trusted executor-result adapter may construct QualificationResult. This
library does not authenticate model payloads or execute tests. The custodian owns
the active GitStore and GitOpsJournal; model processes must have neither. Records
are deterministic commits with the tested tree and the previous record as parent
(the source/base commit on first creation). Only team_git.cas_fast_forward can
publish them. Failed or interrupted journal requests are observed, never retried.

Required legs are an explicit trusted-reader argument: Publisher's qualified hook
supplies operation-specific requirements, including hosted legs for release PRs.
Publisher wiring, signature verification and record retention are separate gates.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re

from aegis_core import approval_shape, gitsafe, team_git, team_gitops
from aegis_core.primitives import sanitize_display, strict_loads
from aegis_core.redaction import redact_command_secrets

__all__ = ["QualificationError", "QualificationResult", "REFUSALS", "approval_equivalent",
           "descriptor_supported", "qualification_ref", "qualified", "record_pass"]

MAX_RECORD_BYTES = 2048
MAX_RECORD_COMMIT_BYTES = 4096
MAX_COMMIT_BYTES = 128 * 1024
MAX_LEGS = 32
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_APPROVE = re.compile(r"^Aegis-Approve: ([0-9a-f]{64})$", re.M)
_KEYS = {"v", "tree", "leg", "source_commit", "run_id", "passed"}
REFUSALS = {
    "invalid_result": "qualification requires a bounded exact-tree passing result",
    "invalid_record": "qualification record is missing or invalid",
    "unsupported_platform": "qualification writes require descriptor-relative custody and journal support",
    "git_failed": "qualification Git operation failed",
    "journal_failed": "qualification journal unavailable; reconcile before any new attempt",
    "request_closed": "qualification request already attempted; reconcile without retrying",
    "cas_mismatch": "qualification ref moved; observe the winning record",
    "not_fast_forward": "qualification records must fast-forward",
    "ref_update_failed": "qualification ref update was not applied",
    "ref_update_unknown": "qualification ref update needs read-only reconciliation",
}


class QualificationError(ValueError):
    """Fixed input-free refusal; code and next_action are safe to display."""

    def __init__(self, code):
        super().__init__(REFUSALS[code])
        self.code = code
        self.next_action = {"actor": "custodian", "command": REFUSALS[code]}


@dataclass(frozen=True)
class QualificationResult:
    tree: str
    leg: str
    source_commit: str
    run_id: str
    passed: bool


def descriptor_supported():
    return team_git.descriptor_support() and team_gitops.descriptor_supported()


def _oid(value):
    return type(value) is str and len(value) in (40, 64) and _OID.fullmatch(value) is not None


def _identifier(value):
    if type(value) is not str or not 1 <= len(value) <= 128 or not _IDENTIFIER.fullmatch(value):
        return False
    # Bound first, canonicalize, redact, then compare. No arbitrary display text
    # is persisted, and no truncated prefix can hide a credential suffix.
    canonical = sanitize_display(value, max_len=None)
    return canonical == value and redact_command_secrets(canonical) == canonical


def qualification_ref(tree, leg):
    """Exact namespace; invalid names refuse before Git or filesystem access."""
    if not _oid(tree) or not _identifier(leg) or ".." in leg or leg.endswith((".", ".lock")):
        raise QualificationError("invalid_result")
    return "refs/aegis/qual/" + tree + "/" + leg


def _valid_result(item):
    if (type(item) is not QualificationResult or item.passed is not True
            or not _oid(item.source_commit) or not _identifier(item.run_id)):
        raise QualificationError("invalid_result")
    qualification_ref(item.tree, item.leg)
    if len(item.source_commit) != len(item.tree):
        raise QualificationError("invalid_result")


def _commit(store, oid, limit=MAX_COMMIT_BYTES):
    if not isinstance(store, team_git.GitStore) or not _oid(oid):
        raise QualificationError("invalid_record")
    raw = store.object(oid, "commit", max_bytes=limit)
    # object() checks size and type before capturing the payload. Bound again
    # before decoding or splitting in case an adapter violates its contract.
    if type(raw) is not bytes or len(raw) > limit:
        raise QualificationError("invalid_record")
    headers, separator, message = raw.partition(b"\n\n")
    if not separator:
        raise QualificationError("invalid_record")
    trees, parents = [], []
    for line in headers.split(b"\n"):
        if line.startswith(b"tree "):
            trees.append(line[5:].decode("ascii"))
        elif line.startswith(b"parent "):
            parents.append(line[7:].decode("ascii"))
    if len(trees) != 1 or not _oid(trees[0]) or len(parents) > 8 or any(not _oid(p) for p in parents):
        raise QualificationError("invalid_record")
    return trees[0], parents, message


def _ref(store, ref):
    # gitsafe owns all Git/path access. Never open a ref pathname here.
    if not isinstance(store, team_git.GitStore):
        raise QualificationError("invalid_record")
    with gitsafe.custody(scratch=store.scratch, stdout_limit=4096, stderr_limit=4096,
                         strict_lane=True, worktree_root=store.repo):
        oid = gitsafe.read_ref(store.repo, ref)
    if oid is not None and not _oid(oid):
        raise QualificationError("invalid_record")
    return oid


def _record(store, oid, tree, leg):
    record_tree, parents, body = _commit(store, oid, MAX_RECORD_COMMIT_BYTES)
    if len(body) > MAX_RECORD_BYTES or len(parents) != 1:
        raise QualificationError("invalid_record")
    row = strict_loads(body)
    if type(row) is not dict or set(row) != _KEYS or type(row["v"]) is not int or row["v"] != 1:
        raise QualificationError("invalid_record")
    item = QualificationResult(**{key: row[key] for key in _KEYS - {"v"}})
    _valid_result(item)
    _commit(store, item.source_commit)
    if record_tree != tree or item.tree != tree or item.leg != leg:
        raise QualificationError("invalid_record")
    return item


def qualified(store, tree, legs):
    """True only when every explicit required leg has a valid exact-tree PASS.

    Empty, duplicate, invalid or oversized selections and all read failures return
    False. This function never writes records or repairs malformed evidence.
    """
    if (not isinstance(store, team_git.GitStore) or not _oid(tree)
            or type(legs) not in (tuple, list) or not 1 <= len(legs) <= MAX_LEGS):
        return False
    try:
        store.object(tree, "tree")
        refs = [qualification_ref(tree, leg) for leg in legs]
        if len(set(refs)) != len(refs):
            return False
        for leg, ref in zip(legs, refs):
            oid = _ref(store, ref)
            if oid is None:
                return False
            _record(store, oid, tree, leg)
        return True
    except (QualificationError, gitsafe.GitError, OSError, ValueError, UnicodeError, RecursionError):
        return False


def _observed_result(store, journal, request_id, ref, expected, new, receipt=None):
    observed = _ref(store, ref)
    status = "done" if observed == new else "not_applied" if observed == expected else "unknown"
    journal.record_result(request_id, status, observed, receipt=receipt)
    return observed


def record_pass(store, result, *, expected, identity, journal, lane, request_id, actor):
    """Custodian-only PASS publication; returns updated or already.

    expected=None creates the first record. New runs parent the explicit previous
    record; stale expectations cannot overwrite a concurrent writer. All shared
    effects have a journal intent first and an observed result afterwards. Reusing
    a request observes its first attempt and never calls CAS again. A failed result
    append leaves an open intent for GitOpsJournal.reconcile, not another effect.
    Git refusals retain the fixed codes listed in REFUSALS; others map to git_failed.
    """
    _valid_result(result)
    if expected is not None and not _oid(expected):
        raise QualificationError("invalid_result")
    if not descriptor_supported():
        raise QualificationError("unsupported_platform")
    if type(journal) is not team_gitops.GitOpsJournal:
        raise QualificationError("journal_failed")
    ref = qualification_ref(result.tree, result.leg)
    try:
        _commit(store, result.source_commit)
        try:
            store.object(result.tree, "tree")
        except gitsafe.GitError as exc:
            if exc.code == "invalid_object":
                raise QualificationError("invalid_result") from None
            raise
        if expected is not None:
            _record(store, expected, result.tree, result.leg)
        body = json.dumps(dict(v=1, **asdict(result)), sort_keys=True, separators=(",", ":")) + "\n"
        if len(body) > MAX_RECORD_BYTES or len(body.encode("utf-8")) > MAX_RECORD_BYTES:
            raise QualificationError("invalid_result")
        new = team_git.commit_tested(store, result.tree, expected or result.source_commit, body, identity)
        with journal.record_intent(op="ref_update", lane=lane, request_id=request_id,
                                   expected_old=expected, expected_new=new, actor=actor) as receipt:
            if not receipt.created:
                # Reconcile owns its own effect lock and skips active writers.
                # Calling record_result directly here could close another
                # thread's in-flight request before that thread performs CAS.
                journal.reconcile(lane, lambda intent: team_gitops.Observation(_ref(store, ref))
                                  if intent["request_id"] == request_id else None)
                # A terminal done row remains valid even after a newer record.
                rows = journal.read().rows
                if any(row["kind"] == "result" and row["request_id"] == request_id
                       and row["status"] == "done" for row in rows):
                    return "already"
                raise QualificationError("request_closed")
            try:
                status = team_git.cas_fast_forward(store, ref, expected, new)
            except gitsafe.GitError as exc:
                observed = _observed_result(store, journal, request_id, ref, expected, new, receipt)
                if observed == new:
                    return "already"
                code = exc.code if exc.code in REFUSALS else "git_failed"
                raise QualificationError(code) from None
            if _observed_result(store, journal, request_id, ref, expected, new, receipt) != new:
                raise QualificationError("cas_mismatch")
            return status
    except QualificationError:
        raise
    except team_gitops.GitOpsError:
        raise QualificationError("journal_failed") from None
    except (gitsafe.GitError, OSError, ValueError, UnicodeError, RecursionError):
        raise QualificationError("git_failed") from None


def approval_equivalent(store, base, head, legs):
    """Structural carry-over only, not signature authority or an approval verdict.

    Only one direct empty approval commit with the standard approval subject and
    one uncontinued Aegis-Approve digest is equivalent. The policy gate separately
    verifies its signature and base-bound digest. Extra prose, metadata, parents
    or tree changes fail closed; no signed value is ever joined across lines.
    """
    try:
        tree, _, _ = _commit(store, base)
        head_tree, parents, raw = _commit(store, head)
        if head_tree != tree or parents != [base] or len(raw) > approval_shape.MAX_MESSAGE_BYTES:
            return False
        message = raw.decode("utf-8")
        if (approval_shape.bounds_refusal(message) is not None
                or not approval_shape.has_authority_line(message)
                or approval_shape.refusal(message, _APPROVE, "Aegis-Approve") is not None):
            return False
        match = _APPROVE.search(message)
        if message != "chore: approve governance state\n\n" + match.group(0) + "\n":
            return False
        return qualified(store, tree, legs)
    except (QualificationError, gitsafe.GitError, OSError, ValueError, UnicodeError, RecursionError):
        return False
