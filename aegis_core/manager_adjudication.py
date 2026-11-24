"""Read-only owner adjudication of exact served manager decisions."""
from __future__ import annotations

import hashlib
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path

from aegis_core import approval_shape, gitsafe
from aegis_core.manager import ManagerService
from aegis_core.manager_config import verify_owner
from aegis_core.manager_policy import ManagerError, digest
from aegis_core.primitives import strict_loads

__all__ = ["prepare", "verify"]

_TOKEN = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_HASH = re.compile(r"[0-9a-f]{64}")
_OID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_MANIFEST_PATH = "adjudication/label.json"
_ENTRY = re.compile(rb"100644 blob ([0-9a-f]{40}(?:[0-9a-f]{24})?)\tadjudication/label\.json\0")
_TRAILER = "Aegis-Manager-Approve"
_OWNER_LINE = re.compile(r"^" + _TRAILER + r": ([0-9a-f]{64})$", re.MULTILINE)
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_COMMIT_BYTES = 128 * 1024
_MAX_ANCHORS = 128
_MAX_DECISIONS = 64
_LABEL_FIELDS = frozenset({"schema", "workspace_id", "episode_id", "decision_refs", "rule_id", "rule_revision",
                           "assessment", "evidence_digest", "previous_anchor", "predecessor", "audit_head"})
_VERDICTS = {"helpful": "tp", "misleading": "fp", "missing_evidence": "unresolved",
             "ignored_appropriate": "unresolved"}


def _matches(value, pattern):
    return type(value) is str and len(value) <= 64 and pattern.fullmatch(value) is not None


def _label(raw):
    try:
        value = strict_loads(raw)
    except (ValueError, RecursionError):
        raise ManagerError("invalid_label_manifest") from None
    if type(value) is dict and (value.get("schema") == "aegis.manager-label/v1"
                               or value.get("schema") == "aegis.manager-label/v2" and "audit_head" not in value):
        raise ManagerError("uncheckpointed_history")
    if type(value) is not dict or len(value) != len(_LABEL_FIELDS) or value.keys() != _LABEL_FIELDS:
        raise ManagerError("invalid_label_manifest")
    if value["schema"] != "aegis.manager-label/v2" or any(
            not _matches(value[key], _TOKEN) for key in ("workspace_id", "episode_id", "rule_id")):
        raise ManagerError("invalid_label_manifest")
    if not _matches(value["audit_head"], _HASH):
        raise ManagerError("invalid_audit_checkpoint")
    refs = value["decision_refs"]
    if type(refs) is not list or not 1 <= len(refs) <= _MAX_DECISIONS or any(
            not _matches(ref, _HASH) for ref in refs) or len(set(refs)) != len(refs):
        raise ManagerError("invalid_label_manifest")
    assessment, evidence = value["assessment"], value["evidence_digest"]
    if type(assessment) is not str or len(assessment) > 32 or assessment not in _VERDICTS or (
            not _matches(evidence, _HASH) and (assessment != "missing_evidence" or evidence is not None)):
        raise ManagerError("invalid_label_manifest")
    if not _matches(value["rule_revision"], _HASH) or any(
            value[key] is not None and not _matches(value[key], pattern)
            for key, pattern in (("predecessor", _HASH), ("previous_anchor", _OID))):
        raise ManagerError("invalid_label_manifest")
    return value


def _commit_size(root, oid, missing):
    if not _matches(oid, _OID) or gitsafe.resolve_commit(root, oid) != oid:
        raise ManagerError(missing)
    size = gitsafe.blob_sizes(root, [oid], kind="commit", timeout=5)[oid]
    if size > _MAX_COMMIT_BYTES:
        raise ManagerError("anchor_limit")
    return size


def _manifest(root, revision):
    # Read one fixed Git tree entry. The checkout and any worktree symlink are irrelevant.
    result = gitsafe.run(["ls-tree", "-z", "--full-tree", revision, "--", _MANIFEST_PATH], root, timeout=5)
    if result.returncode:
        raise ManagerError("git_unavailable")
    if not result.stdout:
        raise ManagerError("missing_label_manifest")
    match = _ENTRY.fullmatch(result.stdout) if len(result.stdout) <= 128 else None
    if match is None:
        raise ManagerError("unsafe_label_manifest")
    oid = match[1].decode("ascii")
    size = gitsafe.blob_sizes(root, [oid], timeout=5)[oid]
    if size > _MAX_MANIFEST_BYTES:
        raise ManagerError("manifest_limit")
    raw = gitsafe.read_blobs(root, [oid], timeout=5)[oid]
    if len(raw) != size:
        raise ManagerError("unsafe_label_manifest")
    return _label(raw), hashlib.sha256(raw).hexdigest()


def _signed_digest(root, oid, size):
    raw = gitsafe.read_blobs(root, [oid], kind="commit", timeout=5)[oid]
    if len(raw) != size:
        raise ManagerError("invalid_owner_signature")
    header, _, message = raw.partition(b"\n\n")
    signature = b"gpgsig-sha256" if len(oid) == 64 else b"gpgsig"
    armor = signature + b" -----BEGIN SSH SIGNATURE-----"
    if not any(line.removesuffix(b"\r") == armor for line in header.split(b"\n")[1:]):
        raise ManagerError("invalid_owner_signature")
    if len(message) > approval_shape.MAX_MESSAGE_BYTES:
        raise ManagerError("invalid_owner_signature")
    try:
        text = message.decode("utf-8")
    except UnicodeDecodeError:
        raise ManagerError("invalid_owner_signature") from None
    if approval_shape.refusal(text, _OWNER_LINE, _TRAILER):
        raise ManagerError("invalid_owner_signature")
    return _OWNER_LINE.search(text)[1]


def _anchors(root, anchor, limit):
    chain = []
    seen = set()
    while anchor is not None:
        if len(chain) >= limit or anchor in seen:
            raise ManagerError("anchor_limit")
        size = _commit_size(root, anchor, "missing_anchor")
        signed_digest = _signed_digest(root, anchor, size)
        label, manifest_digest = _manifest(root, anchor)
        chain.append((anchor, signed_digest, label, manifest_digest))
        seen.add(anchor)
        anchor = label["previous_anchor"]
    return reversed(chain)


def _registration(path, pin):
    if not _matches(pin, _HASH):
        raise ManagerError("invalid_config_digest")
    if not isinstance(path, (str, Path)) or len(str(path)) > 32768:
        raise ManagerError("unsafe_config")
    return ManagerService.for_adjudication(path, pin)


@contextmanager
def _bounded_git():
    # Also cap transport if a repository changes between object sizing and reading.
    # An activation can read both of its bounded policy blobs in one command.
    with tempfile.TemporaryDirectory(prefix="aegis-manager-review-") as scratch, gitsafe.custody(
            scratch=Path(scratch), stdout_limit=1024 * 1024), gitsafe.memo():
        yield


class _Projection:
    """Fold a verified prefix while keeping decision assignments and votes distinct."""

    def __init__(self, service, history):
        self.service = service
        self.head, self.checkpoints, self.activations, self.decisions = history
        self.signed_head = None
        self.assignments = {}
        self.bound = set()
        self.current = {}
        self.bindings = set()

    def statement(self, label, manifest_digest):
        if label["workspace_id"] != self.service.config["workspace_id"]:
            raise ManagerError("workspace_mismatch")
        head = label["audit_head"]
        checkpoint = self.checkpoints.get(head)
        if checkpoint is None:
            raise ManagerError("audit_checkpoint_unavailable")
        if self.signed_head is not None and checkpoint < self.checkpoints[self.signed_head]:
            raise ManagerError("audit_checkpoint_regressed")
        key = self.key(label)
        predecessor, _ = self.current.get(key, (None, None))
        if label["predecessor"] != predecessor:
            raise ManagerError("divergent_predecessor")
        snapshots = []
        for ref in label["decision_refs"]:
            decision = self.decisions.get(ref)
            if decision is None:
                raise ManagerError("unknown_decision")
            if decision["seq"] > checkpoint:
                raise ManagerError("decision_after_checkpoint")
            if not any(rule["id"] == label["rule_id"] and rule["revision"] == label["rule_revision"]
                       for rule in decision["result"]["rules"]):
                raise ManagerError("unserved_revision")
            if self.assignments.get(ref, label["episode_id"]) != label["episode_id"]:
                raise ManagerError("episode_conflict")
            self.require_binding(decision)
            snapshots.append(decision["hash"])
        return {"schema": "aegis.manager-adjudication/v2", "config_digest": self.service.config_digest,
                "audit_head": head,
                "manifest_digest": manifest_digest, "decision_snapshot_digests": snapshots,
                "evidence_digest": label["evidence_digest"], "previous_anchor": label["previous_anchor"],
                "predecessor": predecessor}

    def require_binding(self, decision):
        activation = decision["activation_ref"]
        context = decision["context"]
        binding = (activation, context["member_id"], context["worktree_id"])
        if binding not in self.bindings:
            self.service.verify_adjudication_binding(self.activations[activation], decision)
            self.bindings.add(binding)

    @staticmethod
    def key(label):
        return label["episode_id"], label["rule_id"], label["rule_revision"]

    def replay(self, anchor, limit):
        config = self.service.config
        for oid, signed_digest, label, manifest_digest in _anchors(config["control_root"], anchor, limit):
            statement = self.statement(label, manifest_digest)
            if signed_digest != digest(statement):
                raise ManagerError("invalid_owner_signature")
            verify_owner(config, statement, {"statement": statement, "commit": oid})
            self.signed_head = label["audit_head"]
            self.current[self.key(label)] = (signed_digest, _VERDICTS[label["assessment"]])
            for ref in label["decision_refs"]:
                self.assignments[ref] = label["episode_id"]
                self.bound.add((ref, label["rule_id"], label["rule_revision"]))

    def rows(self, decisions):
        for decision in decisions:
            ref = decision["decision_ref"]
            episode = self.assignments.get(ref)
            for rule in decision["result"]["rules"]:
                rule_id, revision = rule["id"], rule["revision"]
                key = (episode, rule_id, revision)
                approval, verdict = (self.current[key] if (ref, rule_id, revision) in self.bound
                                     else (None, "unresolved"))
                yield {**_decision_key(decision), "episode_id": episode,
                       "rule_id": rule_id, "rule_revision": revision, "verdict": verdict,
                       "adjudication_ref": approval}

    def result(self, anchor):
        checkpoint = self.checkpoints[self.signed_head]
        signed, tail = [], []
        for decision in self.decisions.values():
            (signed if decision["seq"] <= checkpoint else tail).append(decision)
        return {"schema": "aegis.manager-fitness/v2", "workspace_id": self.service.config["workspace_id"],
                "anchor": anchor, "audit_head": self.head, "signed_audit_head": self.signed_head,
                "decisions": list(self.rows(signed)), **self.totals(signed),
                "unsigned_tail": {"decisions": [_decision_key(decision) for decision in tail],
                                  "opportunities": list(self.rows(tail)), **self.totals(tail)}}

    def totals(self, decisions):
        revisions = {}
        actions = {decision["action"]: {} for decision in decisions}
        for row in self.rows(decisions):
            rule = row["rule_id"], row["rule_revision"]
            # The disjoint namespaces keep a provisional decision ID from merging with an owner episode.
            identity = (True, row["episode_id"]) if row["episode_id"] is not None else (False, row["decision_ref"])
            _count(revisions.setdefault(rule, {}), identity, row["verdict"])
            _count(actions[row["action"]], (*identity, *rule), row["verdict"])
        return {"by_revision": [{"rule_id": rid, "rule_revision": rev, **_totals(votes)}
                                for (rid, rev), votes in sorted(revisions.items())],
                "by_action": [{"action": action, **_totals(votes), "covered": sum(
                    verdict != "unresolved" for verdict in votes.values())}
                              for action, votes in sorted(actions.items())]}


def _decision_key(decision):
    context = decision["context"]
    return {"workspace_id": decision["workspace_id"], "activation_ref": decision["activation_ref"],
            "decision_ref": decision["decision_ref"], "action": decision["action"],
            "member_id": context["member_id"], "worktree_id": context["worktree_id"]}


def _count(votes, identity, verdict):
    if verdict != "unresolved":
        votes[identity] = verdict
    else:
        votes.setdefault(identity, verdict)


def _totals(votes):
    result = {"tp": 0, "fp": 0, "unresolved": 0, "eligible": len(votes)}
    for verdict in votes.values():
        result[verdict] += 1
    return result


def prepare(config_path, config_digest, manifest_commit):
    """Prepare a typed statement from the reviewed manifest and its served snapshots."""
    try:
        with _bounded_git():
            service, history = _registration(config_path, config_digest)
            root = service.config["control_root"]
            _commit_size(root, manifest_commit, "missing_manifest_commit")
            label, manifest_digest = _manifest(root, manifest_commit)
            projection = _Projection(service, history)
            projection.replay(label["previous_anchor"], _MAX_ANCHORS - 1)
            statement = projection.statement(label, manifest_digest)
            statement_digest = digest(statement)
            return {"statement": statement, "statement_digest": statement_digest,
                    "required_trailer": _TRAILER + ": " + statement_digest}
    except gitsafe.GitError:
        raise ManagerError("git_unavailable") from None
    except OSError:
        raise ManagerError("adjudication_unavailable") from None


def verify(config_path, config_digest, anchor):
    """Rebuild current owner votes from the pinned anchor and one audit snapshot."""
    if not _matches(anchor, _OID):
        raise ManagerError("missing_anchor")
    try:
        with _bounded_git():
            projection = _Projection(*_registration(config_path, config_digest))
            projection.replay(anchor, _MAX_ANCHORS)
            return projection.result(anchor)
    except gitsafe.GitError:
        raise ManagerError("git_unavailable") from None
    except OSError:
        raise ManagerError("adjudication_unavailable") from None
