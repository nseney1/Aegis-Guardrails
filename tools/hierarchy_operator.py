#!/usr/bin/env python3
"""Canonical operator integration; current native execution is unavailable.

The CLI refuses before effects. Disposable providers may exercise the imported
Operator only with evidence_only=True. That seam tests journal/effect correlation
without promoting configured identities or local decisions into native authority.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import digest, encoded, fields, parse_time, require, safe_path, timestamp, writer_lock  # noqa: E402


NATIVE_HOLD = "authenticated native operator execution is unavailable"
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024


def answer(state, effect, reason, intent_id=None):
    return {"state": state, "effect": effect, "reason": reason,
            "intent_id": intent_id, "native_qualified": False}


def verify_refs(references):
    from hierarchy_lifecycle import evidence
    evidence(references)
    for reference in references:
        path = safe_path(reference["path"])
        require(stat.S_ISREG(path.stat().st_mode), "gate evidence must be a regular file")
        require(path.stat().st_size <= MAX_EVIDENCE_BYTES, "gate evidence exceeds byte limit")
        with path.open("rb") as stream:
            total, observed = 0, hashlib.sha256()
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                require(total <= MAX_EVIDENCE_BYTES, "gate evidence exceeds byte limit")
                observed.update(chunk)
        require(observed.hexdigest() == reference["sha256"], "gate evidence sha256 mismatch")


def inspect_provider(provider, request, actor, generation):
    from hierarchy_lifecycle import GATES
    inspected = provider.inspect(request, actor, generation)
    fields(inspected, {"qualified", "mode", "source", "gates", "reason"})
    require(inspected["mode"] == "fixture", "only an explicitly disposable provider is supported")
    require(inspected["qualified"] is True, str(inspected["reason"]))
    require(inspected["source"] == request["source"], "provider source mismatch")
    fields(inspected["gates"], GATES)
    for references in inspected["gates"].values():
        verify_refs(references)
    return inspected


class NativeProvider:
    """Supported production behavior is explicit refusal, never a fake grant."""
    def inspect(self, request, actor, generation):
        return {"qualified": False, "mode": "native", "source": request["source"],
                "gates": {}, "reason": NATIVE_HOLD}

    def execute(self, request, intent_id):
        raise ValueError(NATIVE_HOLD)


class Operator:
    def __init__(self, lifecycle_root, provider, *, evidence_only=False):
        self.root = Path(lifecycle_root)
        self.provider = provider
        self.evidence_only = evidence_only

    def execute(self, request_id, actor, generation):
        if not self.evidence_only:
            return answer("refused", "none", NATIVE_HOLD)
        # Separate open descriptions conflict even inside one process. Keep the
        # directory inode locked from eligibility through terminal publication;
        # never unlink a lock file or recycle a stale execution claim. A crashed
        # holder releases the OS lock, while its canonical intent still prevents
        # redispatch. This is a disposable POSIX seam, not native authorization.
        if os.name != "posix":
            return answer("refused", "none", "disposable operator requires POSIX execution exclusion")
        import fcntl
        descriptor = None
        try:
            descriptor = os.open(safe_path(self.root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                # This caller never entered eligibility or dispatched an effect.
                # Fresh canonical eligibility can safely retry a refused call.
                return answer("refused", "none", "canonical operator execution is already in progress")
            return self._execute(request_id, actor, generation)
        except (OSError, ValueError) as exc:
            return answer("refused", "none", str(exc))
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _execute(self, request_id, actor, generation):
        # Import lazily: the production refusal does not even open a local ledger.
        from hierarchy_lifecycle import Lifecycle, active_seconds, actor_for
        lifecycle = Lifecycle(self.root)
        intent_id = None
        try:
            policy, state = lifecycle.load()
            require(request_id in state["requests"], "unknown request id")
            row = state["requests"][request_id]
            request = row["request"]
            request_hash = row["raw"]["sha256"]
            root = state["current"]["root"]
            custody = {"cid": root, "generation": policy["actors"][root]["generation"]}
            correlation = digest({"request": request_hash, "actor": actor, "generation": generation})[:32]

            def envelope(kind, **body):
                return {"id": "operator-" + correlation + "-" + kind, "actor": actor,
                        "generation": generation, "custody": custody,
                        "event": {"type": kind, "request_id": request_id, "request_sha256": request_hash, **body}}

            # Fence role/generation even on receipt retrieval; retrieval never executes.
            actor_for(policy, state, envelope("admit"))
            if row["intent"] is not None:
                intent_id = row["intent"]["id"]
                if row["terminal"] is not None and row["terminal"]["value"]["outcome"] != "unknown":
                    return answer("completed", "confirmed", "canonical terminal evidence already recorded", intent_id)
                return answer("unknown", "possible", "canonical intent has an unresolved effect; never redispatch", intent_id)
            inspected = inspect_provider(self.provider, request, actor, generation)
            lifecycle.record(envelope("admit", source=request["source"], gates=inspected["gates"]))
            chosen_intent = "intent-" + correlation
            # Publication can succeed even when its acknowledgement is lost.
            # From this attempt onward, an error must never claim no effect.
            intent_id = chosen_intent
            lifecycle.record(envelope("intent", intent_id=chosen_intent))
            lifecycle.record(envelope("start", intent_id=intent_id))
            # Keep the canonical journal's writer exclusion across the final fresh
            # fence and the provider call. A cooperating successor/denial cannot
            # race the effect. Source/process enforcement is the provider boundary.
            with writer_lock(lifecycle.root):
                policy, current = lifecycle.load()
                _, actor_policy, _ = actor_for(policy, current, envelope("admit"))
                now = timestamp()
                require(active_seconds(current, actor, now) < actor_policy["cap_seconds"],
                        "actor cumulative active cap reached")
                current_row = current["requests"][request_id]
                require(current_row["raw"]["sha256"] == request_hash
                        and current_row["intent"]["id"] == intent_id
                        and current_row["terminal"] is None, "canonical execution correlation changed")
                authority = request["authority"]
                decisions = [decision for decision in current["decisions"] if decision["request_id"] == authority]
                require(decisions and decisions[-1]["decision"] == "approve", "authority revoked before effect")
                expires = current["requests"][authority]["request"]["continuation"]["expires_at"]
                require(parse_time(now) < parse_time(expires), "bounded authority expired")
                inspect_provider(self.provider, request, actor, generation)
                result = self.provider.execute(request, intent_id)
            fields(result, {"outcome", "exit_code", "evidence"})
            require(result["outcome"] in {"passed", "failed", "unknown"}, "provider did not return terminal effect evidence")
            verify_refs(result["evidence"])
            terminal = {"request_sha256": request_hash, "intent_id": intent_id, "source": request["source"], **result}
            raw = encoded(terminal).decode()
            lifecycle.record(envelope("terminal", result={"raw": raw, "sha256": hashlib.sha256(raw.encode()).hexdigest()}))
            if result["outcome"] == "unknown":
                return answer("unknown", "possible", "provider reported unknown effect", intent_id)
            return answer("completed", "confirmed", "terminal evidence recorded; independent acceptance remains open", intent_id)
        except (ValueError, OSError, TypeError, KeyError, RecursionError) as exc:
            # Before intent this is a refusal. After intent no exception, missing
            # reply or malformed result authorizes a second attempt. The durable
            # canonical intent preserves the unknown effect even if result write fails.
            return answer("unknown" if intent_id else "refused", "possible" if intent_id else "none", str(exc), intent_id)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lifecycle", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--generation", type=int, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    execute = commands.add_parser("execute")
    execute.add_argument("--request-id", required=True)
    args = parser.parse_args(argv)
    result = Operator(args.lifecycle, NativeProvider()).execute(args.request_id, args.actor, args.generation)
    print(encoded(result).decode())
    return 2


if __name__ == "__main__":
    sys.exit(main())
