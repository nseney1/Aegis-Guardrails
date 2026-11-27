"""Mailbox operation policy over injected roles, hosts and confined storage.

The service owns authorization, envelopes and witness validation. Store owns
all descriptors, staging capabilities, exclusion, publication and rollback.
No file is opened here and no tools module or process execution is used.
"""
from contextlib import nullcontext
from functools import wraps
import hashlib
import uuid

from aegis_core.team_mailbox_primitives import (
    MAX_RELEASE_WARNINGS, MAX_STATUS_EVIDENCE_BYTES, MailboxRefusal,
    bounded_tree, render_mailbox_refusal, require, safe_path, validate_warnings,
    witness_record,
)

__all__ = ["operation", "witnesses"]


def operation(write=False, *, evidence=False, authorization=None, envelope=False, input_record=None):
    """Normalize failures; authorize (position, keyword, member, action) before locking."""
    def decorate(function):
        @wraps(function)
        def call(self, *args, **kwargs):
            depth = getattr(self.calls, "depth", 0)
            observed = [] if not depth and envelope else None
            try:
                if write:
                    self.roles.authorize(self.caller_role, function.__name__)
                if authorization is not None:
                    position, keyword, member, action = authorization
                    value = args[position] if len(args) > position else kwargs.get(keyword)
                    requested = (type(value) is dict and member in value) if member is not None else value is not None
                    if requested:
                        self.roles.authorize(self.caller_role, action)
                if input_record is not None:
                    position, keyword, normalize = input_record
                    if len(args) > position:
                        args = (*args[:position], normalize(args[position]), *args[position + 1:])
                    else:
                        require(keyword in kwargs)
                        kwargs = {**kwargs, keyword: normalize(kwargs[keyword])}
                if write or evidence or input_record is not None:
                    for argument in (*args, *kwargs.values()):
                        if type(argument) in (dict, list, tuple):
                            bounded_tree(argument)
                kind = "evidence-destination" if evidence else "mailbox"
                with self.store._warning_listener(observed):
                    with self.store.creation(kind) if write or evidence else nullcontext():
                        with self.store.evidence_transaction() if write or evidence else nullcontext():
                            with self.store.lock(self.root) if write else nullcontext():
                                self.calls.depth = depth + 1
                                if not depth:
                                    self.calls.history_bytes = {}
                                    self.refresh()
                                result = function(self, *args, **kwargs)
                if not depth and envelope:
                    warnings = self.store.drain_warnings()
                    seen = {id(warning) for warning in warnings}
                    warnings.extend(warning for warning in observed if id(warning) not in seen)
                    if warnings:
                        result = {**result, "warnings": warnings}
                return result
            except MailboxRefusal as error:
                render_mailbox_refusal(error, reraise=True)
            except OSError:
                raise MailboxRefusal("io") from None
            except (ValueError, KeyError, UnicodeError, RecursionError, OverflowError):
                raise MailboxRefusal("invalid_record") from None
            finally:
                self.calls.depth = depth
        return call
    return decorate


def witnesses(store, worktrees, directory, observe, *, expected=None, warnings=None):
    """Stage an entire observation batch under one exclusion, then commit or undo."""
    require(type(worktrees) is list and len(worktrees) <= 256)
    validate_warnings(warnings, limit=MAX_RELEASE_WARNINGS)
    if expected is not None:
        require(type(expected) is list)
        require(len(expected) <= 256, reason="too_large")
        require(len(expected) == len(worktrees))
        expected = [witness_record(source, worktree) for source, worktree in zip(expected, worktrees)]
        bounded_tree(expected)
    directory = safe_path(directory)
    stage = store.root / (".pending-witness-" + uuid.uuid4().hex)
    results, artifacts, undo, total = [], {}, [], 0
    with store.creation("evidence-destination"), store.evidence_transaction(warnings) as transaction, store.publication_lock(store.root, transaction), store.witness_lock(directory, transaction) as anchor:
        with store.directory(directory, create=True, undo=undo, parent=anchor) as parent:
            with store.directory(stage, create=True, temporary=True) as stage_fd:
                for index, worktree in enumerate(worktrees):
                    with store.witness_stage(stage, stage_fd) as capability:
                        result = witness_record(observe("source_witness", safe_path(worktree), capability), worktree)
                    if expected is not None:
                        require(all(result[key] == expected[index][key] for key in
                                    ("worktree", "source_revision", "source_tree", "dirty_state_sha256", "dirty_entries")))
                    if "dirty_evidence" in result:
                        sha = result["dirty_state_sha256"]
                        artifact = stage / (sha + ".status")
                        require(safe_path(result["dirty_evidence"]) == artifact)
                        if sha not in artifacts:
                            raw = store.read(artifact, limit=MAX_STATUS_EVIDENCE_BYTES - total, parent=stage_fd)
                            require(hashlib.sha256(raw).hexdigest() == sha)
                            artifacts[sha], total = raw, total + len(raw)
                        result["dirty_evidence"] = str(directory / artifact.name)
                    else:
                        require(result["dirty_entries"] == 0)
                    results.append(result)
                bounded_tree(results)
                require({path.name for path in store.entries(stage, parent=stage_fd)} == {sha + ".status" for sha in artifacts})
                pending = []
                for sha, raw in artifacts.items():
                    path = directory / (sha + ".status")
                    if store.exists(path, parent=parent):
                        require(hashlib.sha256(store.read(path, limit=MAX_STATUS_EVIDENCE_BYTES, parent=parent)).hexdigest() == sha)
                    else:
                        pending.append((path, raw))
                for path, raw in pending:
                    store.publish(path, raw, limit=MAX_STATUS_EVIDENCE_BYTES, parent=parent, undo=undo)
            # All evidence is published and staging cleanup has completed.
            transaction["committed"] = True
    return results
