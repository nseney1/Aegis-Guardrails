"""Queue CLI adapter and invocation-local privacy policy."""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr
from functools import partial
import json

from aegis_core import team

EXIT_OK = 0
EXIT_USAGE = 2
_ARGUMENT_NAMES = frozenset(("ITEM", "--item", "--expect", "--lane", "--branch",
                             "--capability", "--ttl", "--reason", "--workspace", "--view"))
_VERBS = ("add", "list", "claim", "release", "unclaim", "done", "audit", "compact")


def _emit(payload):
    print(json.dumps(payload, indent=2))


class QueueArgumentError(ValueError):
    """Parser signal that never retains untrusted diagnostic text."""

    def __init__(self, category=None, names=(), verb=None):
        super().__init__()
        self.details = None
        if (category in ("missing_required", "missing_value", "invalid_value", "limit_exceeded")
                and verb in _VERBS and names and len(names) <= len(_ARGUMENT_NAMES)
                and all(name in _ARGUMENT_NAMES for name in names)):
            self.details = {"category": category, "arguments": list(names),
                            "help_command": "aegis team queue " + verb + " --help"}


def _parser_refusal(error=None):
    from aegis_core import team_queue

    result = team_queue.refusal("invalid_arguments")
    if error is not None and error.details is not None:
        result["argument_error"] = error.details
    return result


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

        diagnostic = None
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
        except QueueArgumentError as error:
            diagnostic = error
        except (self.parser_error, MsgArgumentError):
            pass
        result = _parser_refusal(diagnostic)
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
        result = team_queue.list(root, capabilities=args.capabilities, include_done=args.include_done, view=args.view)
    elif verb == "audit":
        result = team_queue.audit(root, view=args.view)
    elif verb == "compact":
        result = team_queue.compact(root)
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
        def __init__(self, *args, **kwargs):
            kwargs["exit_on_error"] = False
            super().__init__(*args, **kwargs)
            self.queue_verb = None

        def refuse(self, category=None, names=()):
            error = QueueArgumentError(category, names, self.queue_verb)
            if getattr(self, "_error_policy", None) is not None:
                raise error
            _emit(_parser_refusal(error))
            self.exit(EXIT_USAGE)

        def error(self, message):
            # Only recognize a bounded, exact required-argument diagnostic.
            # Names are projected from parser declarations, never copied from argv.
            prefix = "the following arguments are required: "
            if len(message) <= 512 and message.startswith(prefix):
                declared = {action.option_strings[0] if action.option_strings else action.metavar: action
                            for action in self._actions if action.required}
                names = message[len(prefix):].split(", ")
                if all(name in declared and name in _ARGUMENT_NAMES for name in names):
                    self.refuse("missing_required", [name for name in declared if name in names])
            self.refuse()

        def _get_value(self, action, arg_string):
            if action.dest == "view" and len(arg_string) > 11:
                self.refuse("limit_exceeded", ["--view"])
            return super()._get_value(action, arg_string)

        def parse_known_args(self, args=None, namespace=None):
            try:
                values, extras = super().parse_known_args(args, namespace)
            except argparse.ArgumentError as error:
                names = [name for name in _ARGUMENT_NAMES if name == error.argument_name]
                category = "missing_value" if error.message == "expected one argument" else "invalid_value"
                self.refuse(category, names)
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
                parser.refuse("limit_exceeded", ["--capability"])
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
                      help="Capabilities available to this team; list items whose requirements are all satisfied. Repeat for each label")
    view.add_argument("--include-done", action="store_true", help="Include completed items hidden by default")
    view.add_argument("--view", choices=("full", "fingerprint"), default="full",
                      help="Full item detail (default), or fingerprint only; run the full list after a change")
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
    audit = verbs.add_parser("audit", parents=[common], help="Report held work needing a decision", allow_abbrev=False)
    audit.add_argument("--view", choices=("full", "findings"), default="full",
                       help="Full item detail (default), or findings with affected revisions and counts; inspect full constraints before decisions")
    verbs.add_parser("compact", parents=[common], help="Remove completed items not needed by unfinished dependencies", allow_abbrev=False)
    for name, action_parser in verbs.choices.items():
        action_parser.queue_verb = name


def _output(args, result):
    policy = getattr(args, "_queue_output_policy", None)
    if policy is not None:
        return policy.queue_output(result)
    _emit(result)
    return result["exit_code"]


