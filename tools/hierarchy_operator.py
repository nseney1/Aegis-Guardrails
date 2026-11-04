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
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import (SHA256, SLUG, digest, encoded, fields, matching, parse_time, require,  # noqa: E402
                               safe_path, text, timestamp, writer_lock)


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

    @staticmethod
    def _async_reply(request_id, request_sha256, row=None, *, state=None, reason="canonical asynchronous state retained"):
        from hierarchy_lifecycle import provider_handle
        intent = row["intent"] if row else None
        association = row.get("association") if row else None
        terminal = row["terminal"] if row else None
        observations = row.get("observations", []) if row else []
        observed = observations[-1]["value"] if observations else None
        known = terminal is not None and terminal["value"]["outcome"] != "unknown"
        if state is None:
            state = "completed" if known else "running" if observed and observed["provider_state"] == "running" else "unknown" if intent else "refused"
        # An older unknown receipt stays in history; a fresh running observation
        # must not inherit that receipt's terminal outcome/exit-code fields.
        value = terminal["value"] if terminal and (known or state == "unknown") else None
        return {"schema": "aegis.operator-async-result/v1", "state": state,
                "effect": {"completed": "confirmed", "running": "possible", "unknown": "possible", "refused": "none"}[state],
                "reason": reason, "request_id": request_id, "request_sha256": request_sha256,
                "intent_id": intent["id"] if intent else None,
                "original_actor": association["value"]["original_actor"] if association else intent["actor"] if intent else None,
                "original_generation": association["value"]["original_generation"] if association else intent["generation"] if intent else None,
                "association": association["value"] if association else None,
                "association_sha256": association["sha256"] if association else None,
                "provider_handle": provider_handle(row) if association else None,
                "provider_state": observed["provider_state"] if observed else value["outcome"] if value else "unknown" if intent else "not_started",
                "outcome": value["outcome"] if value else None, "exit_code": value["exit_code"] if value else None,
                "evidence": value["evidence"] if value else observed["evidence"] if observed else [],
                "terminal_sha256": terminal["sha256"] if terminal else None, "native_qualified": False}

    @staticmethod
    def _context(policy, state, request_id, request_sha256, actor, generation):
        from hierarchy_lifecycle import actor_for
        matching(request_id, SLUG, "request id")
        matching(request_sha256, SHA256, "request sha256")
        require(request_id in state["requests"], "unknown request id")
        row = state["requests"][request_id]
        require(row["raw"]["sha256"] == request_sha256, "request sha256 mismatch")
        root = state["current"]["root"]

        def envelope(kind, **body):
            event = {"type": kind, "request_id": request_id, "request_sha256": request_sha256, **body}
            if kind == "associate":
                identifier = "async-associate-" + digest(body["association"])[:48]
            elif kind == "observe":
                identifier = "async-observe-" + digest({"association_sha256": body["association_sha256"],
                                                       "observation": body["observation"]})[:48]
            elif kind == "cancel_attempt":
                identifier = "async-cancel-" + body["association_sha256"][:48]
            else:
                identifier = "async-" + digest({"actor": actor, "generation": generation, "event": event})[:48]
            return {"id": identifier,
                    "actor": actor, "generation": generation,
                    "custody": {"cid": root, "generation": policy["actors"][root]["generation"]}, "event": event}

        actor_for(policy, state, envelope("admit"))
        return row, envelope

    @staticmethod
    def _deadline(policy, state, actor, *, row=None, target=None):
        from hierarchy_lifecycle import active_seconds
        now = timestamp()
        remaining = policy["actors"][actor]["cap_seconds"] - active_seconds(state, actor, now)
        require(remaining > 0, "actor cumulative active cap reached")
        remaining = min(5.0, remaining)
        if target is not None:
            authority = state["requests"][row["request"]["authority"]]["request"]
            target_time = parse_time(target["deadline"])
            require(parse_time(now) < target_time <= parse_time(authority["continuation"]["expires_at"]),
                    "execution deadline expired or exceeds authority")
            require((target_time - parse_time(now)).total_seconds()
                    <= policy["actors"][actor]["cap_seconds"] - active_seconds(state, actor, now),
                    "execution deadline exceeds original actor cap")
            remaining = min(remaining,
                            (parse_time(authority["continuation"]["expires_at"]) - parse_time(now)).total_seconds(),
                            (parse_time(target["deadline"]) - parse_time(now)).total_seconds())
            require(remaining > 0, "execution deadline expired")
        return time.monotonic() + remaining

    @staticmethod
    def _process(spec, method, row, actor, generation, deadline, reason=None):
        # These fixed, source-reviewed helpers accept plain data, never an
        # arbitrary Python provider callback. Native mode never reaches here.
        from hierarchy_watch_bridge import process_provider_call
        from hierarchy_lifecycle import provider_handle
        association = row.get("association")
        call = process_provider_call(spec, method, row["request"], row["raw"]["sha256"], actor=actor,
                                     generation=generation, association=association["value"] if association else None,
                                     provider_handle=provider_handle(row) if association else None,
                                     reason=reason, deadline=deadline, evidence_only=True)
        fields(call, {"schema", "transport", "reason", "result", "process", "evidence_dir", "native_qualified"})
        require(call["schema"] == "aegis.fixture-process-call-result/v1" and call["native_qualified"] is False,
                "invalid process provider qualification")
        require(call["transport"] in {"received", "not_sent", "uncertain"}, "invalid process provider transport")
        return call

    def _publish_observation(self, lifecycle, call, request_id, request_sha256, actor, generation, association_sha256):
        from hierarchy_lifecycle import validate_observation
        with writer_lock(lifecycle.root):
            policy, state = lifecycle.load()
            row, envelope = self._context(policy, state, request_id, request_sha256, actor, generation)
            require(row.get("association") and row["association"]["sha256"] == association_sha256,
                    "canonical association correlation changed")
            if row["terminal"] is not None and row["terminal"]["value"]["outcome"] != "unknown":
                return self._async_reply(request_id, request_sha256, row)
            if call["transport"] == "received":
                observed = call["result"]
            else:
                from hierarchy_lifecycle import provider_handle
                observed = {"association_sha256": association_sha256, "provider_state": "unknown",
                            "provider_handle": provider_handle(row), "exit_code": None,
                            "evidence": row["admission"]["gates"]["job"], "quiescent": False}
            validate_observation(row, observed)
            verify_refs(observed["evidence"])
            if call["evidence_dir"] is not None:
                # The immutable call receipt retains the provider's original
                # evidence list as well as timeout/correlation/cleanup failures.
                # Referencing it avoids losing the actual uncertain transport
                # behind a generic pre-existing admission witness.
                receipt = safe_path(Path(call["evidence_dir"]) / "result.json")
                require(stat.S_ISREG(receipt.stat().st_mode), "transport receipt must be a regular file")
                with receipt.open("rb") as stream:
                    raw_receipt = stream.read(MAX_EVIDENCE_BYTES + 1)
                require(len(raw_receipt) <= MAX_EVIDENCE_BYTES, "transport receipt exceeds byte limit")
                observed = {**observed, "evidence": [{"path": str(receipt),
                                                     "sha256": hashlib.sha256(raw_receipt).hexdigest()}]}
                verify_refs(observed["evidence"])
            require(row["request"]["source"] == row["association"]["value"]["source"], "provider source mismatch")
            lifecycle._record_under_lock(envelope("observe", intent_id=row["intent"]["id"],
                                                  association_sha256=association_sha256, observation=observed), policy, state)
            phase = observed["provider_state"]
            if phase in {"passed", "failed", "cancelled"}:
                result = {"request_sha256": request_sha256, "intent_id": row["intent"]["id"],
                          "source": row["request"]["source"], "outcome": "passed" if phase == "passed" else "failed",
                          "exit_code": observed["exit_code"], "evidence": observed["evidence"]}
                raw = encoded(result).decode()
                lifecycle._record_under_lock(envelope("terminal", result={"raw": raw, "sha256": hashlib.sha256(raw.encode()).hexdigest()}),
                                             policy, state)
            return self._async_reply(request_id, request_sha256, row, reason=call["reason"])

    def submit(self, request_id, request_sha256, actor, generation, target):
        if not self.evidence_only:
            return self._async_reply(request_id, request_sha256, reason=NATIVE_HOLD)
        from hierarchy_lifecycle import Lifecycle, active_seconds, approved_authority
        from hierarchy_watch_bridge import validate_process_provider
        lifecycle, row, descriptor = Lifecycle(self.root), None, None
        attempted = False
        try:
            require(os.name == "posix", "disposable operator requires POSIX execution exclusion")
            spec = validate_process_provider(self.provider)
            import fcntl
            descriptor = os.open(safe_path(self.root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return self._async_reply(request_id, request_sha256, reason="canonical operator execution is already in progress")
            with writer_lock(lifecycle.root):
                policy, state = lifecycle.load()
                row = state["requests"].get(request_id)
                row, envelope = self._context(policy, state, request_id, request_sha256, actor, generation)
                if row["intent"] is not None:
                    return self._async_reply(request_id, request_sha256, row)
                fields(target, {"provider", "endpoint_id", "thread_id", "deadline"})
                require(target["provider"] == spec["provider"] and target["endpoint_id"] == spec["endpoint_id"],
                        "provider target mismatch")
                text(target["thread_id"], "provider thread_id", 256)
                now = timestamp()
                approved_authority(state, row, now)
                deadline = self._deadline(policy, state, actor, row=row, target=target)
                inspected = self._process(spec, "inspect", row, actor, generation, deadline)
                require(inspected["transport"] == "received", inspected["reason"])
                observation = inspected["result"]
                from hierarchy_lifecycle import GATES
                fields(observation, {"qualified", "mode", "source", "gates", "reason"})
                require(observation["mode"] == "fixture" and observation["qualified"] is True, observation["reason"])
                require(observation["source"] == row["request"]["source"], "provider source mismatch")
                fields(observation["gates"], GATES)
                for refs in observation["gates"].values():
                    verify_refs(refs)
                lifecycle._record_under_lock(envelope("admit", source=row["request"]["source"], gates=observation["gates"]), policy, state)
                intent_id = "intent-" + digest({"request": request_sha256, "actor": actor, "generation": generation})[:32]
                attempted = True  # Publication may succeed even when its reply is lost.
                lifecycle._record_under_lock(envelope("intent", intent_id=intent_id), policy, state)
                lifecycle._record_under_lock(envelope("start", intent_id=intent_id), policy, state)
                authority = state["requests"][row["request"]["authority"]]
                decisions = [d for d in state["decisions"] if d["request_id"] == row["request"]["authority"]]
                binding = {"schema": "aegis.provider-association/v1", "request_id": request_id,
                           "request_sha256": request_sha256, "intent_id": intent_id, "source": row["request"]["source"],
                           "authority": row["request"]["authority"], "authority_sha256": authority["raw"]["sha256"],
                           "decision_sha256": digest(decisions[-1]), "admission_sha256": digest(row["admission"]),
                           "original_actor": actor, "original_generation": generation,
                           "original_cap_seconds": policy["actors"][actor]["cap_seconds"],
                           "authority_expires_at": authority["request"]["continuation"]["expires_at"],
                           "provider": target["provider"], "endpoint_id": target["endpoint_id"],
                           "thread_id": target["thread_id"], "client_id": "client-" + intent_id, "deadline": target["deadline"]}
                lifecycle._record_under_lock(envelope("associate", association=binding), policy, state)
                fresh = timestamp()
                require(parse_time(fresh) < parse_time(binding["authority_expires_at"])
                        and parse_time(fresh) < parse_time(binding["deadline"]), "bounded authority expired")
                require(active_seconds(state, actor, fresh) < policy["actors"][actor]["cap_seconds"], "actor cumulative active cap reached")
                require(time.monotonic() < deadline, "process provider deadline reached")
                call = self._process(spec, "submit", row, actor, generation, deadline)
                association_sha256 = row["association"]["sha256"]
            return self._publish_observation(lifecycle, call, request_id, request_sha256, actor, generation, association_sha256)
        except (ValueError, OSError, TypeError, KeyError, RecursionError) as exc:
            return self._async_reply(request_id, request_sha256, row, state="unknown" if attempted else "refused", reason=str(exc))
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def observe(self, request_id, request_sha256, actor, generation):
        return self._follow("observe", request_id, request_sha256, actor, generation)

    def cancel(self, request_id, request_sha256, actor, generation, reason):
        return self._follow("cancel", request_id, request_sha256, actor, generation, reason)

    def _follow(self, method, request_id, request_sha256, actor, generation, reason=None):
        if not self.evidence_only:
            return self._async_reply(request_id, request_sha256, reason=NATIVE_HOLD)
        from hierarchy_lifecycle import Lifecycle, provider_handle
        from hierarchy_watch_bridge import validate_process_provider
        lifecycle, row, attempted = Lifecycle(self.root), None, False
        try:
            spec = validate_process_provider(self.provider)
            with writer_lock(lifecycle.root):
                policy, state = lifecycle.load()
                row = state["requests"].get(request_id)
                row, envelope = self._context(policy, state, request_id, request_sha256, actor, generation)
                if row["intent"] is None or row.get("association") is None or (row["terminal"] is not None
                        and row["terminal"]["value"]["outcome"] != "unknown"):
                    return self._async_reply(request_id, request_sha256, row)
                binding = row["association"]["value"]
                require(binding["provider"] == spec["provider"] and binding["endpoint_id"] == spec["endpoint_id"],
                        "provider target mismatch")
                deadline = self._deadline(policy, state, actor)
                association_sha256 = row["association"]["sha256"]
                if method == "cancel":
                    if row.get("cancellation") is not None:
                        return self._async_reply(request_id, request_sha256, row)
                    text(reason, "cancellation reason", 1024)
                    require(provider_handle(row) is not None, "owned provider handle is unavailable")
                    attempted = True
                    lifecycle._record_under_lock(envelope("cancel_attempt", intent_id=row["intent"]["id"],
                                                          association_sha256=association_sha256, reason=reason), policy, state)
                    call = self._process(spec, "cancel", row, actor, generation, deadline, reason)
            if method == "observe":
                attempted = True
                call = self._process(spec, "observe", row, actor, generation, deadline)
            return self._publish_observation(lifecycle, call, request_id, request_sha256, actor, generation, association_sha256)
        except (ValueError, OSError, TypeError, KeyError, RecursionError) as exc:
            return self._async_reply(request_id, request_sha256, row, state="unknown" if attempted else "refused", reason=str(exc))

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
