"""Queue CLI adapter and invocation-local privacy policy."""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr
from functools import partial
import json

from aegis_core import team

EXIT_OK = 0
EXIT_USAGE = 2


def _emit(payload):
    print(json.dumps(payload, indent=2))


class QueueArgumentError(ValueError):
    """Parser signal that never retains untrusted diagnostic text."""


class _DiscardOutput:
    def write(self, text):
        return len(text)

    def flush(self):
        pass


class QueueErrorPolicy:
    """Compose queue parsing explicitly, without rewriting parser policies."""

    def __init__(self, fallback, *, active=False, output=None, parser_error=QueueArgumentError):
        self.fallback = fallback
        self.active = active
        self.output = output
        self.parser_error = parser_error

    def __call__(self):
        self.fallback()

    def run(self, operation):
        return self.fallback.run(operation)

    def select_parser(self, model_errors):
        select = getattr(self.fallback, "select_parser", None)
        if select is not None:
            select(model_errors)

    def removed_pointer(self, argv, lookup):
        return None if self.active else self.fallback.removed_pointer(argv, lookup)

    def parse(self, parser, argv):
        if not self.active:
            return self.fallback.parse(parser, argv)
        from aegis_core import team_queue
        from aegis_cli.msg import MsgArgumentError

        try:
            with redirect_stderr(_DiscardOutput()):
                args = parser.parse_args(argv)
                raw = args.workspace
                if raw is not None and not team_queue.valid_workspace_spelling(raw):
                    raise QueueArgumentError()
                return args
        except SystemExit as error:
            if error.code == 0:
                return EXIT_OK
        except (QueueArgumentError, self.parser_error, MsgArgumentError):
            pass
        result = team_queue.refusal("invalid_arguments")
        if self.output is not None:
            return self.output(result)
        _emit(result)
        return result["exit_code"]

    def workspace_error(self, args, error):
        if args.command == "team" and getattr(args, "team_action", None) == "queue":
            from aegis_core import team_queue

            result = team_queue.refusal("queue_io_unavailable", verb=getattr(args, "queue_action", "usage"))
            return _output(args, result)
        return self.fallback.workspace_error(args, error)


def run_queue(args):
    """Thin adapter: core owns item parsing, scheduling, storage and refusals."""
    from aegis_core import team_queue

    verb = getattr(args, "queue_action", None)
    root = args.ws.root if getattr(args, "ws", None) is not None else getattr(args, "workspace", None)
    if verb == "add":
        parsed = team_queue.parse_item(args.item)
        result = (team_queue.refusal(parsed["reason"], verb=verb) if parsed["refused"]
                  else team_queue.add(root, parsed["item"]))
    elif verb == "list":
        result = team_queue.list(root, capabilities=args.capabilities, include_done=args.include_done)
    elif verb in ("audit", "compact"):
        result = getattr(team_queue, verb)(root)
    elif verb == "claim":
        result = team_queue.claim(root, args.item_id, expect=args.expect, lane=args.lane,
                                  capabilities=args.capabilities or [], ttl_s=args.ttl, branch=args.branch)
    elif verb in ("release", "done"):
        result = getattr(team_queue, verb)(root, args.item_id, expect=args.expect, lane=args.lane)
    elif verb == "unclaim":
        result = team_queue.unclaim(root, args.item_id, expect=args.expect, lane=args.lane,
                                    reason=args.reason, writer_stopped=args.writer_stopped)
    else:
        result = team_queue.refusal("invalid_arguments")
    return _output(args, result)


def configure_parser(sub, common, parent):
    """Scope non-echoing parser/workspace errors to this new command only."""
    from aegis_core import team_queue

    class QueueParser(type(parent)):
        def error(self, message):
            if getattr(self, "_error_policy", None) is not None:
                raise QueueArgumentError()
            _emit(team_queue.refusal("invalid_arguments"))
            self.exit(EXIT_USAGE)

        def parse_known_args(self, args=None, namespace=None):
            values, extras = super().parse_known_args(args, namespace)
            if extras:
                self.error("")
            raw = getattr(values, "workspace", None)
            if raw is not None and not team_queue.valid_workspace_spelling(raw):
                self.error("")
            return values, extras

    class Capabilities(argparse.Action):
        def __call__(self, parser, namespace, value, option_string=None):
            previous = getattr(namespace, self.dest, None) or []
            if len(previous) >= 128 or len(value) > 64:
                parser.error("")
            setattr(namespace, self.dest, previous + [value])

    factory = sub._parser_class
    keywords = {"error_policy": parent._error_policy} if hasattr(parent, "_error_policy") else {}
    sub._parser_class = partial(QueueParser, **keywords)
    try:
        parser = sub.add_parser("queue", parents=[common], help="Manage queued team work with CAS leases",
                                description="Queue add, list, claim, release, unclaim, done, audit and compact; all results are JSON.",
                                allow_abbrev=False)
    finally:
        sub._parser_class = factory
    verbs = parser.add_subparsers(dest="queue_action", metavar="VERB")
    add = verbs.add_parser("add", parents=[common], help="Enqueue a bounded inline JSON item", allow_abbrev=False)
    add.add_argument("--item", required=True, metavar="JSON", help="Queue item object; no file paths are opened")
    view = verbs.add_parser("list", parents=[common], help="List items, blockers and lane labels", allow_abbrev=False)
    view.add_argument("--capability", dest="capabilities", action=Capabilities, default=None,
                      help="Filter by a team capability label; repeat for each label")
    view.add_argument("--include-done", action="store_true", help="Include completed items hidden by default")
    claim = verbs.add_parser("claim", parents=[common], help="Claim a current item revision with a lease", allow_abbrev=False)
    claim.add_argument("item_id", metavar="ITEM", help="Stable queue item id")
    claim.add_argument("--expect", required=True, metavar="REVISION", help="Current revision returned by add or list")
    claim.add_argument("--lane", required=True, help="Lane declared in .aegis/team.json")
    claim.add_argument("--branch", default=None, help="Lane's local branch; omitted means unknown branch evidence")
    claim.add_argument("--capability", dest="capabilities", action=Capabilities, default=None,
                       help="Team capability label; repeat for each label")
    claim.add_argument("--ttl", type=int, default=team.DEFAULT_TTL_S, metavar="SECONDS", help="Claim lifetime, at most one day")
    for verb in ("release", "done", "unclaim"):
        action = verbs.add_parser(verb, parents=[common], help={"release": "Release a claim", "done": "Complete a live claim",
                                  "unclaim": "Return a claim together with its intersecting lane leases"}[verb],
                                  allow_abbrev=False)
        action.add_argument("item_id", metavar="ITEM", help="Stable queue item id")
        action.add_argument("--expect", required=True, metavar="REVISION", help="Current revision returned by claim or list")
        action.add_argument("--lane", default=None, required=verb == "unclaim", help="Current claim lane; required for a live claim")
        if verb == "unclaim":
            action.add_argument("--writer-stopped", action="store_true", help="Acknowledge that the lane's writer and queued jobs are stopped")
            action.add_argument("--reason", default="", help="Single-line noncredential reason for returning the claim and its leases")
    verbs.add_parser("audit", parents=[common], help="Report held work needing a decision", allow_abbrev=False)
    verbs.add_parser("compact", parents=[common], help="Remove completed items not needed by unfinished dependencies", allow_abbrev=False)


def _output(args, result):
    policy = getattr(args, "_queue_output_policy", None)
    if policy is not None:
        return policy.queue_output(result)
    _emit(result)
    return result["exit_code"]


