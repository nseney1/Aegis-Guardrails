"""Explicit manager audit commands, independent of repository workspace discovery."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from aegis_cli.base import AegisCommand, CommandCategory
from aegis_core.config import env_workspace
from aegis_core.primitives import strict_loads

__all__ = ["WorkspaceCommand"]

_MAX_JSON = 65536


def _json_input(text: str):
    if len(text.encode("utf-8")) > _MAX_JSON:
        raise ValueError("manager JSON object exceeds 65536 bytes")
    try:
        return strict_loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON object: {exc.msg}") from None


def _json_object(text: str) -> dict:
    value = _json_input(text)
    if not isinstance(value, dict):
        raise ValueError("manager input must be a JSON object")
    return value


def _configure_common(parser):
    parser.add_argument("--config", default=argparse.SUPPRESS,
                        help="Explicit manager configuration path")
    parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                        help="Emit machine-readable JSON output")
    parser.add_argument("--plain", action="store_true", default=argparse.SUPPRESS,
                        help="Strip ANSI styling and emoji")


class WorkspaceCommand(AegisCommand):
    name = "workspace"
    category = CommandCategory.WORKFLOW
    help = "Audit management decisions using a separately approved manager policy"
    description = ("Manager audit prototype: explicit configuration, zero fitness credit, "
                   "and no native Teams enforcement or delegation authority.")

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--config", default=argparse.SUPPRESS,
                            help="Explicit manager configuration path")
        common = argparse.ArgumentParser(add_help=False)
        _configure_common(common)
        sub = parser.add_subparsers(dest="workspace_action", required=True)
        init = sub.add_parser("init", parents=[common], help="Prepare draft configuration and registration")
        init.add_argument("--workspace-id", required=True, help="Stable manager workspace identity")
        init.add_argument("--control-repo", required=True, help="Private control repository root")
        init.add_argument("--store", required=True, help="External manager audit directory")
        init.add_argument("--trusted-signers", required=True, help="Owner-selected public allowed-signers file")
        activate = sub.add_parser("activate", parents=[common], help="Review or apply an owner-signed revision")
        activate.add_argument("--revision", required=True, help="Full control-repository policy commit")
        activate.add_argument("--expect", required=True, help="Expected active revision, or none for bootstrap")
        activate.add_argument("--approval", help="JSON containing the exact statement and owner-signed approval commit")
        sub.add_parser("status", parents=[common], help="Inspect audit, approval and native enforcement states")
        scan = sub.add_parser("scan", parents=[common], help="Record a management decision and matching rules")
        scan.add_argument("--action", required=True, help="Management action to match against manager policy")
        scan.add_argument("--context", required=True, help="Bounded management context as a JSON object")
        report = sub.add_parser("report", parents=[common], help="Append an audit outcome without fitness credit")
        report.add_argument("--decision", required=True, help="Immutable decision reference returned by scan")
        report.add_argument("--rules", nargs="*", default=[], help="Served manager rule IDs used in this decision")
        report.add_argument("--outcome", required=True, help="Claimed outcome; acknowledgement grants no verified completion")
        report.add_argument("--evidence", default="[]", help="Qualified evidence references as a JSON array")
        report.add_argument("--idempotency-key", required=True, help="Stable key reused for identical outcome retries")

    def execute(self, args: argparse.Namespace) -> int:
        if getattr(args, "workspace", None) is not None or env_workspace():
            raise ValueError("manager mode cannot use --workspace or AEGIS_WORKSPACE")
        config = getattr(args, "config", None)
        if not config:
            raise ValueError("manager mode requires --config")
        # Parse request data before loading configuration; data never selects a scope.
        context = _json_object(args.context) if args.workspace_action == "scan" else None
        evidence = _json_input(args.evidence) if args.workspace_action == "report" else None
        if args.workspace_action == "report" and not isinstance(evidence, list):
            raise ValueError("manager evidence must be a JSON array")
        from aegis_core.manager import ManagerService, initialize

        if args.workspace_action == "init":
            result = initialize(config, workspace_id=args.workspace_id, control_root=args.control_repo,
                                store_root=args.store, trusted_signers=args.trusted_signers)
        else:
            service = ManagerService(config, provenance={"transport": "cli", "native_identity": None})
            result = self._dispatch(service, args, context, evidence)
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0

    @staticmethod
    def _dispatch(service: Any, args: argparse.Namespace, context, evidence):
        if args.workspace_action == "status":
            return service.status()
        if args.workspace_action == "scan":
            return service.scan(args.action, context)
        if args.workspace_action == "report":
            return service.report(args.decision, args.rules, args.outcome, evidence, args.idempotency_key)
        expected = None if args.expect == "none" else args.expect
        if not args.approval:
            candidate = service.candidate(args.revision)
            if candidate["approval_statement"]["expected_activation"] != expected:
                raise ValueError("stale expected activation")
            return candidate
        approval_path = Path(args.approval)
        with approval_path.open("r", encoding="utf-8") as stream:
            approval = _json_object(stream.read(_MAX_JSON + 1))
        return service.activate(args.revision, expected, approval)
