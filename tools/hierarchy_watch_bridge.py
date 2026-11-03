#!/usr/bin/env python3
"""Supported continuation port; native execution remains explicitly unqualified.

This adapter does not turn metadata, CLI success, or local JSON into authority.
OperatorBridge joins the canonical operator to the watch port for evidence-only
qualification. It never substitutes raw RPC or starts another native session.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import SHA256, SLUG, encoded, matching, require, text  # noqa: E402


def correlation(request_id, request_sha256, operation_id=None):
    matching(request_id, SLUG, "request id")
    matching(request_sha256, SHA256, "request sha256")
    if operation_id is not None:
        matching(operation_id, SLUG, "watch operation id")


class NativeBridge:
    """No installed provider has yet passed the required native acceptance gate."""

    def __init__(self, host="codex"):
        self.host = text(host, "host", 128)

    def capabilities(self):
        return {"schema": "aegis.watch-bridge-capabilities/v1", "host": self.host,
                "native_qualified": False, "execution_enabled": False,
                "persistent_executor": "unqualified",
                "reason": "native identity, decision service, continuation and persistent executor are unqualified",
                "publication_is_execution": False, "execution_is_read": False}

    def observe(self, request_id, request_sha256):
        correlation(request_id, request_sha256)
        return {"state": "hold", "reason": self.capabilities()["reason"], "native_qualified": False}

    def continue_request(self, request_id, request_sha256, operation_id):
        correlation(request_id, request_sha256, operation_id)
        return {"state": "refused", "effect": "none", "reason": self.capabilities()["reason"],
                "intent_id": None, "native_qualified": False}


class OperatorBridge:
    """External-provider boundary around Session 1's canonical Operator API.

The caller must explicitly select evidence-only operation. Provider observations
remain fixture evidence; the operator independently repeats admission checks.
"""

    def __init__(self, lifecycle_root, provider, actor, generation, *, evidence_only=False):
        from hierarchy_lifecycle import Lifecycle
        from hierarchy_operator import Operator
        self.lifecycle = Lifecycle(lifecycle_root)
        self.provider = provider
        self.actor = actor
        self.generation = generation
        self.evidence_only = evidence_only
        self.operator = Operator(lifecycle_root, provider, evidence_only=evidence_only)

    def request(self, request_id, request_sha256):
        correlation(request_id, request_sha256)
        status = self.lifecycle.status()
        require(request_id in status["requests"], "unknown request id")
        row = status["requests"][request_id]
        require(row["raw"]["sha256"] == request_sha256, "request sha256 mismatch")
        return status, row

    def observe(self, request_id, request_sha256):
        status, row = self.request(request_id, request_sha256)
        if not self.evidence_only:
            return NativeBridge().observe(request_id, request_sha256)
        if request_id not in status["continuation_candidates"]:
            return {"state": "hold", "reason": status["continuation_holds"].get(request_id, "not a continuation candidate"),
                    "native_qualified": False}
        result = self.provider.inspect(row["request"], self.actor, self.generation)
        require(isinstance(result, dict) and type(result.get("qualified")) is bool, "invalid provider observation")
        require(result.get("mode") == "fixture", "evidence-only bridge requires a fixture provider")
        return {"state": "eligible" if result["qualified"] else "hold", "reason": result.get("reason", ""),
                "native_qualified": False}

    def continue_request(self, request_id, request_sha256, operation_id):
        correlation(request_id, request_sha256, operation_id)
        self.request(request_id, request_sha256)
        if not self.evidence_only:
            return NativeBridge().continue_request(request_id, request_sha256, operation_id)
        # The watch ID correlates delivery only. Operator owns the one canonical
        # execution intent and revalidates authority/source/generation under lock.
        result = self.operator.execute(request_id, self.actor, self.generation)
        return {**result, "native_qualified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capabilities = commands.add_parser("capabilities")
    capabilities.add_argument("--host", required=True)
    args = parser.parse_args(argv)
    try:
        result = NativeBridge(args.host).capabilities()
    except ValueError as exc:
        print(encoded({"state": "hold", "error": str(exc), "native_qualified": False}).decode())
        return 2
    print(encoded(result).decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
