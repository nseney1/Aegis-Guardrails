"""Owner mailbox CLI adapter; the core owns policy, validation and storage."""
import argparse
from datetime import datetime, timezone
from functools import partial
import json
import os
import sys
import unicodedata

from aegis_core import team_mailbox as core
from aegis_core import team_mailbox_doctor as doctor
from aegis_core import team_mailbox_store as storage
from aegis_core import team_profile
from aegis_core.primitives import sanitize_display
from aegis_core.team_board import SECRET_REPLACEMENTS
from aegis_core.team_mailbox_pager import bounded_inbox
from aegis_core.team_mailbox_primitives import (
    MAX_BYTES, MAX_INBOX_RESPONSE_BYTES, MailboxRefusal, RoleTables, render_mailbox_refusal,
    require, safe_path, strict_json, validate_warnings,
)

__all__ = ["MailBoardErrorPolicy", "configure_parser", "run_mail", "workspace_refusal", "options",
           "request", "emit", "parser_factory", "cli_line"]


def now_utc():
    return datetime.now(timezone.utc)


def process_status(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return "dead"
    except PermissionError:
        return "unknown"
    return "alive"


def display_text(value, *, whole=False):
    normalized = unicodedata.normalize("NFKC", value)
    canonical = sanitize_display(normalized, max_len=None)
    # Preserve admitted multiline text when the shared sanitizer changed only
    # its ordinary layout. Removed controls or masks keep the sanitizer's view.
    if whole and canonical == normalized.replace("\n", " ").replace("\t", " "):
        canonical = normalized
    for pattern, replacement in SECRET_REPLACEMENTS:
        canonical = pattern.sub(replacement, canonical)
    if whole:
        require(len(canonical) <= MAX_INBOX_RESPONSE_BYTES, reason="too_large")
        return canonical
    return canonical[:65536]


def display(value, *, field=None):
    if isinstance(value, str):
        return display_text(value, whole=field in ("brief_text", "text"))
    if isinstance(value, dict):
        return {display(key): display(item, field=key) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [display(item, field=field) for item in value]
    return value


def cli_line(value):
    return (json.dumps(display(value), sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def fragment_size(value):
    return len(json.dumps(display(value), sort_keys=True, ensure_ascii=True, allow_nan=False))


cli_line.board_page_framing = (fragment_size, 2)


def emit(value, *, rendered=False, stream=None):
    if rendered:
        # Board digests already prepare every field before interpolation; preserve
        # their trusted line framing rather than treating it as one data field.
        print(json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False), file=stream)
    else:
        print(cli_line(value).decode("ascii"), end="", file=stream)


def usage():
    return {"status": "refused", "reason": "invalid_arguments",
            "next_action": "Use aegis team mail or board --help and supply the required options.", "exit_code": 2}


class _MailBoardParseRefusal(BaseException):
    """Carry a fixed refusal past policies that handle Exception and SystemExit."""


class MailBoardErrorPolicy:
    """Own parse failures in the raw mail and board scopes."""

    guards_usage = True

    def __init__(self, fallback, parser_errors):
        self.fallback = fallback
        self.parser_errors = parser_errors

    def __getattr__(self, name):
        return getattr(self.fallback, name)

    def __call__(self):
        raise _MailBoardParseRefusal()

    def removed_pointer(self, argv, lookup):
        # Let the parser establish the command before selecting a diagnostic.
        return None

    def run(self, operation):
        try:
            return self.fallback.run(operation)
        except _MailBoardParseRefusal:
            emit(usage())
            raise SystemExit(2) from None

    def parse_cli_args(self, parse, args, namespace):
        try:
            return parse(args=args, namespace=namespace)
        except self.parser_errors:
            raise _MailBoardParseRefusal() from None


def workspace_refusal(args, error):
    emit({"status": "refused", "reason": "workspace_unavailable",
          "next_action": "Select an available trusted workspace and retry.", "exit_code": 1})
    return 1


def parser_factory(parent):
    """Keep argument errors local to the new verbs, with no argv-derived output."""
    class MailParser(type(parent)):
        def error(self, message):
            policy = getattr(self, "_error_policy", None)
            if isinstance(policy, MailBoardErrorPolicy):
                policy()
            emit(usage())
            self.exit(2)

        def parse_known_args(self, args=None, namespace=None):
            values, extras = super().parse_known_args(args, namespace)
            path_name = getattr(self, "team_path", None)
            if extras or path_name is not None and not hasattr(values, path_name):
                self.error("")
            return values, extras

        def _get_value(self, action, arg_string):
            if len(arg_string) > MAX_BYTES or action.type is int and len(arg_string) > 8:
                self.error("")
            return super()._get_value(action, arg_string)

    keywords = {"error_policy": parent._error_policy} if hasattr(parent, "_error_policy") else {}
    return partial(MailParser, **keywords)


def configure_parser(sub, common, parent):
    factory = sub._parser_class
    sub._parser_class = parser_factory(parent)
    try:
        parser = sub.add_parser("mail", parents=[common], help="Send, read and diagnose the team mailbox", allow_abbrev=False)
    finally:
        sub._parser_class = factory
    parser.team_path = "root"
    parser.add_argument("--root", default=argparse.SUPPRESS, help="Absolute mailbox root; required once before or after the verb")
    verbs = parser.add_subparsers(dest="mail_action", required=True)
    for verb in ("send", "read", "doctor"):
        child = verbs.add_parser(verb, parents=[common], help={"send": "Publish a strict mailbox request",
            "read": "Read a bounded mailbox page", "doctor": "Inspect mailbox health without writes"}[verb], allow_abbrev=False)
        child.add_argument("--root", default=argparse.SUPPRESS, help="Absolute mailbox root; required once before or after the verb")
        if verb == "send":
            child.add_argument("--request", "--request-file", required=True,
                               help="Absolute strict JSON request with no symlink components, or - for bounded stdin")
        if verb == "read":
            child.add_argument("--endpoint", required=True, help="Configured recipient endpoint")
            child.add_argument("--include-briefs", action="store_true", help="Include hash-checked brief text")
            child.add_argument("--binding-only", action="store_true", help="Read only the binding and message count")
            child.add_argument("--limit", type=int, default=None, help="Page size: default 20, maximum 100")
            child.add_argument("--after", default=None, help="Continue after this received message identifier")
            child.add_argument("--mark-read", action="store_true", help="Root only: record this page after stdout flush")
            child.add_argument("--delivery-dir", default=None, help="Existing owner-selected delivery directory for read receipts")
            child.add_argument("--host", default=None, help="The reading root's configured host")
            child.add_argument("--session", default=None, help="The reading root's own session")
            child.add_argument("--generation", type=int, default=None, help="The reading root's binding generation")


def options(args):
    require(storage.descriptor_supported(), reason="unsupported_platform")
    root = args.ws.root if getattr(args, "ws", None) is not None else args.workspace
    try:
        resolved = team_profile.load(root)
    except (team_profile.ProfileError, OSError, ValueError, RuntimeError):
        raise MailboxRefusal("host_unavailable") from None
    hosts = {name: object() for name in resolved["profile"]["model_settings"]["hosts"]}
    require(bool(hosts), reason="unknown_host")
    roles = RoleTables(writes={"owner": {"publish", "initialize", "configure", "tombstone",
                                       "record_read", "write_delivery_receipt"}})
    return dict(clock=now_utc, roles=roles, hosts=hosts, caller_role="owner")


def request(store, value):
    if value == "-":
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        require(len(raw) <= MAX_BYTES, reason="too_large")
    else:
        path = safe_path(value)
        if path.is_relative_to(store.root.parent):
            raw = store.read(path)
        else:
            # Store walks absolute ancestors from the trusted filesystem anchor,
            # then retains the no-follow parent descriptor through the leaf read.
            with storage.Store.from_parent(path.parent) as source:
                raw = source.read(path)
    return strict_json(raw)


def read(box, args):
    if args.binding_only:
        require(not (args.include_briefs or args.limit is not None or args.after is not None or args.mark_read))
        return box.binding_view(args.endpoint)
    require(args.mark_read or (args.host, args.session, args.generation) == (None, None, None))
    if args.mark_read:
        require(box.roles.endpoint_parts(args.endpoint)[1] == "root")
        require(all(value is not None for value in (args.delivery_dir, args.host, args.session, args.generation)))
    result = box.inbox(args.endpoint, include_briefs=args.include_briefs,
                       limit=20 if args.limit is None else args.limit, after=args.after)
    return bounded_inbox(result, cli_line)


def report_receipt_warnings(store):
    warnings = store.drain_warnings()
    validate_warnings(warnings, allow_none=False)
    if warnings:
        emit({"status": "warning", "reason": "lock_release", "code": 0,
              "next_action": "Inspect the reported retained locks before another write.",
              "warnings": warnings}, stream=sys.stderr)


def run_mail(args):
    emitted = False
    try:
        if args.mail_action == "doctor" and not doctor.descriptor_reads_supported():
            raise doctor.Refusal("MD_PLATFORM")
        config = options(args)
        if args.mail_action == "doctor":
            config.pop("caller_role")
            result = doctor.inspect_mailbox(args.root, process_status=process_status, **config)
            code = 0 if result["healthy"] else 1
            if code:
                result = {**result, "status": "refused", "reason": "mailbox_unhealthy",
                          "next_action": "Reconcile the reported records from trusted evidence, then run mail doctor again."}
        else:
            if getattr(args, "mark_read", False):
                config["delivery_roots"] = (safe_path(args.delivery_dir),) if args.delivery_dir is not None else ()
            with core.Mailbox(args.root, **config) as box:
                if args.mail_action == "send":
                    payload = request(box.store, args.request)
                    box.host = payload.get("host") if type(payload) is dict else None
                    result = box.publish(payload)
                else:
                    result = read(box, args)
                    if args.mark_read:
                        emit(result)
                        emitted = True
                        sys.stdout.flush()
                        try:
                            box.record_read(args.delivery_dir, {"from": args.endpoint, "host": args.host,
                                "session": args.session, "binding_generation": args.generation},
                                [row["message"]["message_id"] for row in result["messages"]])
                        finally:
                            report_receipt_warnings(box.store)
            code = 0
    except MailboxRefusal as error:
        result, code = render_mailbox_refusal(error), 1
    except doctor.Refusal as error:
        result, code = {"schema": doctor.SCHEMA, "status": "refused", "reason": error.code,
                        "next_action": error.next_action,
                        "error": {"code": error.code, "message": doctor.REFUSALS[error.code]}}, 1
    except (OSError, UnicodeError, ValueError, KeyError, RecursionError, OverflowError):
        result, code = render_mailbox_refusal(MailboxRefusal("io")), 1
    try:
        if not emitted or code:
            emit(result, stream=sys.stderr if emitted else None)
    except (OSError, UnicodeError):
        return 1
    return code
