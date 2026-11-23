"""CLI adapter for report-only host receipts with an unavailable version reader."""
import json
import sys
import unicodedata

from aegis_cli.hooks.redaction import redact_text
from aegis_core import team_host_qualify as qualify
from aegis_core.primitives import sanitize_display


__all__ = [
    "configure_parser", "refuse_usage", "run_qualify", "state_root_for", "workspace_refusal",
]

_LIMITS = {"status": 32, "reason": 64, "host": 128, "actor": 32, "command": 200}


def _unavailable_version():
    return None


def state_root_for(_args):
    return qualify.default_state_root()


def workspace_refusal(_args, _error=None):
    """A workspace that cannot be bound. The refusal is fixed and does not echo the path."""
    action = qualify.NEXT_ACTIONS["state_unavailable"]
    body = {"status": "refused", "reason": "state_unavailable", "host": None,
            "next_action": {"actor": action["actor"], "command": action["command"]}}
    print(json.dumps(body, sort_keys=True), file=sys.stderr)
    return 1


def _present(value, limit):
    if type(value) is not str or "\n" in value or "\r" in value:
        return "refused"
    shown = sanitize_display(unicodedata.normalize("NFKC", value), max_len=None)
    shown = redact_text(shown)
    if type(shown) is not str or shown.splitlines() != [shown]:
        return "refused"
    return sanitize_display(shown, max_len=limit)


def _usage():
    action = qualify.NEXT_ACTIONS["invalid_usage"]
    return {"status": "refused", "reason": "invalid_usage", "host": None,
            "next_action": {"actor": action["actor"], "command": action["command"]}}


def refuse_usage():
    """The fixed qualify refusal. The parser message is ignored so untrusted text is not echoed."""
    print(json.dumps(_usage(), sort_keys=True), file=sys.stderr)


def _payload(result):
    action = result.get("next_action") or {}
    body = {
        "status": _present(result.get("status"), _LIMITS["status"]),
        "reason": _present(result.get("reason"), _LIMITS["reason"]),
        "next_action": {
            "actor": _present(action.get("actor"), _LIMITS["actor"]),
            "command": _present(action.get("command"), _LIMITS["command"]),
        },
    }
    host = result.get("host")
    body["host"] = None if host is None else _present(host, _LIMITS["host"])
    return body


def _emit(args, result, code):
    body = _payload(result)
    if getattr(args, "json", False):
        print(json.dumps(body, sort_keys=True, separators=(",", ":")))
    else:
        print("status " + body["status"])
        print("reason " + body["reason"])
        if type(body.get("host")) is str:
            print("host " + body["host"])
        print("next_action " + body["next_action"]["actor"] + " " + body["next_action"]["command"])
    return code


def _workspace(args):
    bound = getattr(args, "ws", None)
    if bound is not None:
        return str(bound.root)
    workspace = getattr(args, "workspace", None)
    if type(workspace) is str and workspace:
        return workspace
    return None


def run_qualify(args):
    kind = getattr(args, "kind", None)
    report = getattr(args, "report", None)
    recording = bool(getattr(args, "record", False))
    if getattr(args, "qualify_action", None) != "host" or type(kind) is not str or not kind:
        refuse_usage()
        return 2
    if (report is None) != (not recording):
        refuse_usage()
        return 2
    root = state_root_for(args)
    workspace = _workspace(args)

    if recording:
        result = qualify.record_file(root, kind, report, version_reader=_unavailable_version, workspace=workspace)
    else:
        result = qualify.status(root, kind, version_reader=_unavailable_version, workspace=workspace)
    return _emit(args, result, 1)


def configure_parser(sub, common):
    parser = sub.add_parser("qualify", parents=[common], allow_abbrev=False,
                            help="Inspect host report receipt status")
    verbs = parser.add_subparsers(dest="qualify_action", required=True)
    host = verbs.add_parser("host", parents=[common], allow_abbrev=False,
                            description="Live version reading is deferred. Receipt operations requiring it return version_unavailable.",
                            help="Inspect receipt status or validate a submitted report")
    host.add_argument("kind", nargs="?", metavar="KIND", help="Host id or surface alias")
    host.add_argument("--report", help="Absolute path of the probe report to submit")
    host.add_argument("--record", action="store_true", help="Request recording of a passing report once a live version reader is available")
