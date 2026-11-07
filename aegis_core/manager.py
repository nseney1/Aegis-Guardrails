"""Manager-only audit services, deliberately separate from repository fitness.

Management claims are data. Acknowledgement grants no execution, approval,
delegation authority, native identity or verified completion.
"""
from __future__ import annotations

import copy
import os
import re
import uuid
from pathlib import Path

from aegis_core import gitsafe
from aegis_core.manager_config import initialize, load_config, verify_owner
from aegis_core.manager_policy import ACTIONS, ManagerError, digest, parse_membership, parse_policy, read_candidate
from aegis_core.manager_store import ManagerStore

__all__ = ["ManagerService", "initialize"]
_OUTCOMES = frozenset(("success", "partial", "failure", "pass", "fail", "tp", "fp"))
_CONTEXT = {"member_id", "worktree_id", "role", "phase", "risk", "summary"}
_EVIDENCE = {"member_id", "worktree_id", "source_tree", "check", "rule_id", "rule_revision", "reference"}
_HEX = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def _bounded(value, limit):
    return type(value) is str and 0 < len(value) <= limit and "\x00" not in value


def _pending(rows):
    scanned = {row["decision_ref"] for row in rows if row["kind"] == "decision"}
    reported = {row["request"]["decision_ref"] for row in rows if row["kind"] == "outcome"}
    return sorted(scanned - reported)


def _activation(rows):
    return next((row for row in reversed(rows) if row["kind"] == "activation"), None)


def _statement(config, fingerprint, candidate, rows):
    previous = _activation(rows)
    return {"schema": "aegis.manager-activation/v1", "workspace_id": config["workspace_id"],
            "config_digest": fingerprint, "control_commit": candidate["control_commit"],
            "policy_digest": candidate["policy_digest"], "membership_digest": candidate["membership_digest"],
            "membership_bindings_digest": digest(candidate["bindings"]),
            "expected_activation": previous["activation_ref"] if previous else None,
            "expected_audit_head": rows[-1]["hash"], "pending_decisions_digest": digest(_pending(rows))}


def _context(value):
    if type(value) is not dict or set(value) - _CONTEXT or not {"member_id", "worktree_id"} <= set(value):
        raise ManagerError("invalid_context")
    if any(not _bounded(item, 4096 if key == "summary" else 128) for key, item in value.items()):
        raise ManagerError("invalid_context")
    return copy.deepcopy(value)


def _member(candidate, member_id, worktree_id):
    for member in candidate["membership"]["repositories"]:
        if member["id"] == member_id:
            for worktree in member["worktrees"]:
                if worktree["id"] == worktree_id:
                    return member, worktree
    raise ManagerError("unauthorized_membership")


def _safe_runtime_path(path):
    return path.is_dir() and path.resolve() == path and not any(
        p.is_symlink() or (getattr(p, "is_junction", lambda: False)()) for p in (path, *path.parents))


@gitsafe.scrubbed()
def _runtime_paths(member, worktree):
    path = Path(worktree["path"])
    common = gitsafe.common_dir(path)
    result = gitsafe.run(["rev-parse", "--absolute-git-dir"], path, timeout=5)
    if result.returncode or common is None:
        raise ManagerError("membership_unavailable")
    gitdir = Path(os.fsdecode(result.stdout).strip())
    if gitsafe.toplevel(path) != path or common != Path(member["common_dir"]):
        raise ManagerError("membership_unavailable")
    return {"root": path, "common_dir": common, "git_dir": gitdir}


def _path_identity(path):
    if not _safe_runtime_path(path):
        raise ManagerError("membership_unavailable")
    info = path.stat()
    if not info.st_ino:
        raise ManagerError("identity_unavailable")
    return {"path": str(path), "device": info.st_dev, "inode": info.st_ino}


@gitsafe.scrubbed()
def _bindings(candidate):
    result = {}
    for member in candidate["membership"]["repositories"]:
        for worktree in member["worktrees"]:
            result[member["id"] + "/" + worktree["id"]] = {
                key: _path_identity(path) for key, path in _runtime_paths(member, worktree).items()}
    return result


@gitsafe.scrubbed()
def _identity(member, worktree, bindings=None):
    path = Path(worktree["path"])
    if not path.is_dir():
        return "missing"
    try:
        current = {key: _path_identity(value) for key, value in _runtime_paths(member, worktree).items()}
        if bindings is not None and current != bindings.get(member["id"] + "/" + worktree["id"]):
            return "mismatched"
    except ManagerError:
        return "mismatched"
    except (gitsafe.GitError, OSError):
        return "unavailable"
    return "available"


def _evidence_input(value):
    if type(value) is not list or len(value) > 20:
        raise ManagerError("invalid_evidence")
    for entry in value:
        if type(entry) is not dict or set(entry) != _EVIDENCE:
            raise ManagerError("invalid_evidence")
        if any(not _bounded(item, 1024 if key == "reference" else 256) for key, item in entry.items()):
            raise ManagerError("invalid_evidence")
        if not _HEX.fullmatch(entry["source_tree"]) or not re.fullmatch(r"[0-9a-f]{64}", entry["rule_revision"]):
            raise ManagerError("invalid_evidence")
    return copy.deepcopy(value)


@gitsafe.scrubbed()
def _worktree_state(path):
    overrides = gitsafe.filter_overrides(path, scope="all")
    if overrides is None:
        return "unavailable"
    flags = gitsafe.run(["ls-files", "-v", "-z"], path, timeout=5)
    if flags.returncode or any(entry[:1] != b"H" for entry in flags.stdout.split(b"\0") if entry):
        # Hidden/skip-worktree or unmerged entries cannot establish a clean source observation.
        return "unavailable"
    changed = gitsafe.run([*overrides, "diff-index", "--quiet", "--no-ext-diff", "--no-textconv", "HEAD", "--"],
                         path, timeout=5)
    untracked = gitsafe.list_files(path, tracked=False, untracked=True)
    if changed.returncode not in (0, 1) or untracked is None:
        return "unavailable"
    return "dirty" if changed.returncode == 1 or untracked else "clean"


@gitsafe.scrubbed()
def _evidence_state(candidate, evidence):
    result = []
    rules = {rule["id"]: rule["revision"] for rule in candidate["policy"]["rules"]}
    for entry in evidence:
        state = {**entry, "check_execution": "unverified", "reference_status": "not_retrieved"}
        state["rule_status"] = "match" if rules.get(entry["rule_id"]) == entry["rule_revision"] else "unavailable"
        try:
            member, worktree = _member(candidate, entry["member_id"], entry["worktree_id"])
            status = _identity(member, worktree, candidate["bindings"])
            if status == "available":
                tree_result = gitsafe.run(["rev-parse", "HEAD^{tree}"], worktree["path"], timeout=5)
                tree = tree_result.stdout.decode("ascii", "replace").strip() if not tree_result.returncode else None
                dirty = _worktree_state(worktree["path"])
                if tree_result.returncode or not tree or not _HEX.fullmatch(tree) or dirty == "unavailable":
                    status = "unavailable"
                elif dirty == "dirty":
                    status = "dirty"
                else:
                    status = "source_match" if tree == entry["source_tree"] else "stale"
            state["source_status"] = status
        except ManagerError:
            state["source_status"] = "unauthorized_membership"
        except gitsafe.GitError:
            state["source_status"] = "unavailable"
        result.append(state)
    return result


def _matching(candidate, action, context):
    return [rule for rule in candidate["policy"]["rules"] if action in rule["actions"]
            and all(context.get(key) == value for key, value in rule["match"].items())]


def _candidate_shape(candidate):
    fields = {"workspace_id", "control_root", "control_commit", "policy_digest", "membership_digest", "policy", "membership", "bindings"}
    if type(candidate) is not dict or set(candidate) != fields or type(candidate["policy"]) is not dict \
            or type(candidate["bindings"]) is not dict or type(candidate["membership"]) is not dict:
        raise ManagerError("audit_corrupt")
    policy = candidate["policy"]
    if set(policy) != {"schema", "workspace_id", "rules"} or type(policy["rules"]) is not list:
        raise ManagerError("audit_corrupt")
    rules = []
    for rule in policy["rules"]:
        if type(rule) is not dict or set(rule) != {"id", "actions", "match", "text", "revision"}:
            raise ManagerError("audit_corrupt")
        rules.append({key: value for key, value in rule.items() if key != "revision"})
    if parse_policy({**policy, "rules": rules}) != policy \
            or parse_membership(candidate["membership"], verify_identity=False) != candidate["membership"]:
        raise ManagerError("audit_corrupt")


def _decision_valid(row, activation):
    result, candidate = row["result"], activation["candidate"]
    expected = {"schema": "aegis.manager-scan/v1", "scope": "manager", "workspace_id": row["workspace_id"],
                "decision_ref": row["decision_ref"], "activation_ref": activation["activation_ref"],
                "control_commit": candidate["control_commit"], "policy_digest": candidate["policy_digest"],
                "membership_digest": candidate["membership_digest"],
                "rules": _matching(candidate, row["action"], row["context"]),
                "provenance": row["provenance"], "fitness_credit": 0, "delegation_authority": False}
    if row["action"] not in ACTIONS or row["context_digest"] != digest(_context(row["context"])) or result != expected:
        raise ManagerError("audit_corrupt")


def _outcome_valid(row, decision, activation):
    request, result = row["request"], row["result"]
    if set(request) != {"decision_ref", "rules_used", "outcome", "evidence", "idempotency_key", "tests_passed"}:
        raise ManagerError("audit_corrupt")
    rules = decision["result"]["rules"]
    if type(request["rules_used"]) is not list or any(type(rule) is not str for rule in request["rules_used"]) \
            or type(request["outcome"]) is not str or type(request["idempotency_key"]) is not str \
            or not set(request["rules_used"]) <= {rule["id"] for rule in rules} or request["outcome"] not in _OUTCOMES:
        raise ManagerError("audit_corrupt")
    expected = {"schema": "aegis.manager-outcome/v1", "scope": "manager", "workspace_id": row["workspace_id"],
                "decision_ref": decision["decision_ref"], "activation_ref": activation["activation_ref"],
                "rule_revisions": {rule["id"]: rule["revision"] for rule in rules},
                "acknowledgement": "recorded", "fitness_credit": 0, "claimed_outcome": request["outcome"],
                "claimed_tests_passed": request["tests_passed"], "execution": "unverified", "human_approval": "not_established",
                "native_observation": "unavailable", "verified_completion": False,
                "provenance": row["provenance"], "native_enforcement_ready": False,
                "acknowledgement_ref": digest({"request": request, "activation_ref": activation["activation_ref"]})}
    if set(result) != set(expected) | {"evidence"} or any(result[key] != value for key, value in expected.items()):
        raise ManagerError("audit_corrupt")
    _evidence_input(request["evidence"])
    if type(result["evidence"]) is not list or len(result["evidence"]) != len(request["evidence"]):
        raise ManagerError("audit_corrupt")
    for original, observed in zip(request["evidence"], result["evidence"]):
        if type(observed) is not dict or set(observed) != _EVIDENCE | {"source_status", "rule_status", "check_execution", "reference_status"}:
            raise ManagerError("audit_corrupt")
        if any(observed[key] != value for key, value in original.items()) \
                or observed["check_execution"] != "unverified" or observed["reference_status"] != "not_retrieved" \
                or type(observed["source_status"]) is not str or type(observed["rule_status"]) is not str \
                or observed["source_status"] not in {"source_match", "dirty", "stale", "missing", "mismatched", "unavailable", "unauthorized_membership"} \
                or observed["rule_status"] not in {"match", "unavailable"}:
            raise ManagerError("audit_corrupt")


class ManagerService:
    """One immutable startup binding over a shared external audit history."""

    def __init__(self, config_path, provenance=None, expected_config_digest=None):
        self.config_path = Path(config_path)
        self.config, self.config_digest = load_config(self.config_path, expected_config_digest)
        self.provenance = copy.deepcopy(provenance or {"transport": "cli", "native_identity": None})
        self.store = ManagerStore(self.config["store_root"], forbidden_roots=(self.config["control_root"],))
        self._rows()

    def _validate(self, rows):
        if not rows or rows[0].get("kind") != "init" or rows[0].get("config_digest") != self.config_digest:
            raise ManagerError("config_mismatch")
        if any(row.get("workspace_id") != self.config["workspace_id"] for row in rows):
            raise ManagerError("config_mismatch")
        envelope = {"seq", "prev", "hash", "kind", "workspace_id"}
        fields = {"init": {"config_digest"},
                  "activation": {"activation_ref", "candidate", "approval", "statement", "provenance"},
                  "decision": {"decision_ref", "activation_ref", "action", "context", "context_digest", "result", "provenance"},
                  "outcome": {"request", "result", "provenance"}}
        activations, decisions, keys = {}, {}, set()
        try:
            for index, row in enumerate(rows):
                kind = row["kind"]
                if type(kind) is not str or kind not in fields or set(row) != envelope | fields[kind] or (kind == "init" and index != 0):
                    raise ManagerError("audit_corrupt")
                if kind == "activation":
                    if not _bounded(row["activation_ref"], 64) or row["activation_ref"] in activations:
                        raise ManagerError("audit_corrupt")
                    _candidate_shape(row["candidate"])
                    if type(row["approval"]) is not dict or type(row["statement"]) is not dict:
                        raise ManagerError("audit_corrupt")
                    activations[row["activation_ref"]] = row
                elif kind == "decision":
                    if not _bounded(row["decision_ref"], 64) or not _bounded(row["activation_ref"], 64) \
                            or row["decision_ref"] in decisions or type(row["action"]) is not str:
                        raise ManagerError("audit_corrupt")
                    _decision_valid(row, activations[row["activation_ref"]])
                    decisions[row["decision_ref"]] = row
                elif kind == "outcome":
                    request = row["request"]
                    if type(request) is not dict or type(request.get("idempotency_key")) is not str \
                            or type(request.get("decision_ref")) is not str or type(row["result"]) is not dict:
                        raise ManagerError("audit_corrupt")
                    if request["idempotency_key"] in keys:
                        raise ManagerError("audit_corrupt")
                    decision = decisions[request["decision_ref"]]
                    _outcome_valid(row, decision, activations[decision["activation_ref"]])
                    keys.add(request["idempotency_key"])
        except (KeyError, ValueError, AttributeError) as exc:
            raise ManagerError("audit_corrupt") from exc
        return rows

    def _rows(self):
        load_config(self.config_path, self.config_digest)
        return self._validate(self.store.read())

    def _verified_activation(self, rows):
        current = _activation(rows)
        if current is None:
            return None
        index = rows.index(current)
        if _pending(rows[:index]):
            raise ManagerError("activation_integrity")
        candidate = read_candidate(self.config["control_root"], current["candidate"]["control_commit"],
                                   verify_membership=False)
        candidate["bindings"] = current["candidate"].get("bindings", {})
        statement = _statement(self.config, self.config_digest, candidate, rows[:index])
        if current["candidate"] != candidate or current["statement"] != statement \
                or current["activation_ref"] != digest(statement):
            raise ManagerError("activation_integrity")
        approval = {"statement": statement, "commit": current["approval"].get("approval_commit")}
        if verify_owner(self.config, statement, approval) != current["approval"]:
            raise ManagerError("activation_integrity")
        return current

    def _active(self, rows):
        current = self._verified_activation(rows)
        if current is None:
            raise ManagerError("policy_not_active")
        return current

    def candidate(self, revision):
        rows = self._rows()
        candidate = read_candidate(self.config["control_root"], revision)
        if candidate["workspace_id"] != self.config["workspace_id"]:
            raise ManagerError("workspace_mismatch")
        candidate["bindings"] = _bindings(candidate)
        self._verified_activation(rows)
        statement = _statement(self.config, self.config_digest, candidate, rows)
        return {"status": "awaiting_owner_approval", **candidate, "approval_statement": statement,
                "approval_digest": digest(statement), "required_trailer": "Aegis-Manager-Approve: " + digest(statement),
                "pending_decisions": _pending(rows), "fitness_credit": 0}

    def activate(self, revision, expected, approval):
        candidate = read_candidate(self.config["control_root"], revision)
        if candidate["workspace_id"] != self.config["workspace_id"]:
            raise ManagerError("workspace_mismatch")
        candidate["bindings"] = _bindings(candidate)
        def activate(rows):
            self._validate(rows)
            current = self._verified_activation(rows)
            if expected != (current["activation_ref"] if current else None):
                raise ManagerError("stale_activation")
            if _pending(rows):
                raise ManagerError("pending_decisions")
            statement = _statement(self.config, self.config_digest, candidate, rows)
            owner = verify_owner(self.config, statement, approval)
            ref = digest(statement)
            event = {"kind": "activation", "workspace_id": self.config["workspace_id"],
                     "activation_ref": ref, "candidate": candidate, "approval": owner,
                     "statement": statement, "provenance": self.provenance}
            result = {"status": "activated", "policy_approval": "approved", "active_revision": ref,
                      "control_commit": revision, "fitness_credit": 0, "native_enforcement_ready": False}
            return event, result
        self._rows()
        return self.store.transaction(activate)

    def status(self):
        rows = self._rows()
        current = self._verified_activation(rows)
        outcomes = [row for row in rows if row["kind"] == "outcome"]
        references = [(row, entry) for row in outcomes for entry in row["request"]["evidence"]]
        states, memberships = [], []
        if current:
            for row, entry in references[-20:]:
                decision = next(item for item in rows if item.get("decision_ref") == row["request"]["decision_ref"]
                                and item["kind"] == "decision")
                origin = next(item for item in rows if item.get("activation_ref") == decision["activation_ref"]
                              and item["kind"] == "activation")
                states.extend(_evidence_state(origin["candidate"], [entry]))
            for member in current["candidate"]["membership"]["repositories"]:
                for worktree in member["worktrees"]:
                    memberships.append({"member_id": member["id"], "worktree_id": worktree["id"],
                                        "state": _identity(member, worktree, current["candidate"]["bindings"])})
        return {"schema": "aegis.manager-status/v1", "workspace_id": self.config["workspace_id"],
                "manager_audit_available": True, "policy_approval": "approved" if current else "draft",
                "active_revision": current["activation_ref"] if current else None,
                "control_commit": current["candidate"]["control_commit"] if current else None,
                "policy_digest": current["candidate"]["policy_digest"] if current else None,
                "membership_digest": current["candidate"]["membership_digest"] if current else None,
                "pending_decisions": _pending(rows), "outcomes": len(outcomes), "evidence": states,
                "evidence_total": len(references), "evidence_omitted": max(0, len(references) - 20),
                "omitted_evidence_state": "unverified", "membership": memberships,
                "fitness_credit": 0, "native_enforcement_ready": False, "teams_mutations_enabled": False,
                "delegation_authority": False, "native_identity": None, "audit_head": rows[-1]["hash"]}

    def list_rules(self):
        current = self._active(self._rows())
        return {"scope": "manager", "workspace_id": self.config["workspace_id"],
                "activation_ref": current["activation_ref"], "control_commit": current["candidate"]["control_commit"],
                "rules": copy.deepcopy(current["candidate"]["policy"]["rules"]), "fitness_credit": 0}

    def scan(self, action, context):
        context = _context(context)
        if type(action) is not str or action not in ACTIONS:
            raise ManagerError("invalid_action")
        def scan(rows):
            self._validate(rows)
            current = self._active(rows)
            candidate = current["candidate"]
            member, worktree = _member(candidate, context["member_id"], context["worktree_id"])
            if _identity(member, worktree, candidate["bindings"]) != "available":
                raise ManagerError("membership_unavailable")
            rules = _matching(candidate, action, context)
            ref = digest({"workspace_id": self.config["workspace_id"], "activation_ref": current["activation_ref"],
                          "action": action, "context_digest": digest(context), "nonce": uuid.uuid4().hex})
            result = {"schema": "aegis.manager-scan/v1", "scope": "manager", "workspace_id": self.config["workspace_id"],
                      "decision_ref": ref, "activation_ref": current["activation_ref"],
                      "control_commit": candidate["control_commit"], "policy_digest": candidate["policy_digest"],
                      "membership_digest": candidate["membership_digest"], "rules": copy.deepcopy(rules),
                      "provenance": self.provenance, "fitness_credit": 0, "delegation_authority": False}
            event = {"kind": "decision", "workspace_id": self.config["workspace_id"], "decision_ref": ref,
                     "activation_ref": current["activation_ref"], "action": action, "context": context,
                     "context_digest": digest(context), "result": result, "provenance": self.provenance}
            return event, result
        self._rows()
        return self.store.transaction(scan)

    def report(self, decision_ref, rules_used, outcome, evidence, idempotency_key, tests_passed=None):
        if not _bounded(decision_ref, 64) or not re.fullmatch(r"[0-9a-f]{64}", decision_ref):
            raise ManagerError("unknown_decision")
        if type(rules_used) is not list or len(rules_used) > 128 \
                or any(not _bounded(rule, 64) for rule in rules_used) or len(set(rules_used)) != len(rules_used):
            raise ManagerError("unserved_rules")
        if type(outcome) is not str or outcome not in _OUTCOMES or not _bounded(idempotency_key, 128):
            raise ManagerError("invalid_outcome")
        if tests_passed is not None and type(tests_passed) is not bool:
            raise ManagerError("invalid_outcome")
        request = {"decision_ref": decision_ref, "rules_used": sorted(rules_used), "outcome": outcome,
                   "evidence": _evidence_input(evidence), "idempotency_key": idempotency_key, "tests_passed": tests_passed}
        def report(rows):
            self._validate(rows)
            current = self._active(rows)
            for row in rows:
                if row["kind"] == "outcome" and row["request"]["idempotency_key"] == idempotency_key:
                    if row["request"] != request:
                        raise ManagerError("idempotency_conflict")
                    return None, row["result"]
            decision = next((row for row in rows if row["kind"] == "decision" and row["decision_ref"] == decision_ref), None)
            if decision is None:
                raise ManagerError("unknown_decision")
            if decision["activation_ref"] != current["activation_ref"]:
                raise ManagerError("stale_decision")
            served = {rule["id"] for rule in decision["result"]["rules"]}
            if not set(rules_used) <= served:
                raise ManagerError("unserved_rules")
            result = {"schema": "aegis.manager-outcome/v1", "scope": "manager", "workspace_id": self.config["workspace_id"],
                      "decision_ref": decision_ref, "activation_ref": current["activation_ref"],
                      "rule_revisions": {rule["id"]: rule["revision"] for rule in decision["result"]["rules"]},
                      "acknowledgement": "recorded", "fitness_credit": 0, "claimed_outcome": outcome,
                      "claimed_tests_passed": tests_passed, "execution": "unverified", "human_approval": "not_established",
                      "native_observation": "unavailable", "verified_completion": False,
                      "evidence": _evidence_state(current["candidate"], request["evidence"]),
                      "provenance": self.provenance, "native_enforcement_ready": False}
            result["acknowledgement_ref"] = digest({"request": request, "activation_ref": current["activation_ref"]})
            event = {"kind": "outcome", "workspace_id": self.config["workspace_id"], "request": request,
                     "result": result, "provenance": self.provenance}
            return event, result
        self._rows()
        return self.store.transaction(report)
