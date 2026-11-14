"""Workspace-bound aegis.msg/1 CLI; all views use the core renderer unchanged."""
from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import json
import os
import sys

from aegis_cli.base import AegisCommand, CommandCategory
from aegis_core.errors import WorkspaceError

__all__ = ["MsgCommand", "MsgArgumentError", "KINDS", "emit_error"]

KINDS = ("text", "record", "log", "blob", "review.v1", "prereview.v1", "handoff.v1", "leadreport.v1")


class MsgArgumentError(ValueError):
    """Lightweight parser signal; the core error is constructed only on failure."""

    def __init__(self, code="E_FORMAT", detail="arguments"):
        self.code, self.detail = code, detail


class MsgErrorPolicy:
    """Own the argv-wide refusal policy without teaching the entry point msg rules."""

    def __init__(self, argv=()):
        self.active = "msg" in argv

    def __call__(self):
        if self.active:
            raise MsgArgumentError()

    def removed_pointer(self, argv, lookup):
        return None if self.active else lookup(argv)

    def parse(self, parser, argv):
        try:
            return parser.parse_args(argv)
        except MsgArgumentError as error:
            from aegis_core.message_codec import CodecError

            return emit_error(CodecError(error.code), detail=error.detail)

    def workspace_error(self, args, error):
        if args.command != "msg":
            return None
        from aegis_core.message_codec import CodecError
        from aegis_core.errors import WorkspaceNotFoundError

        detail = ("attachment" if isinstance(error, OSError) else
                  "root" if isinstance(error, WorkspaceNotFoundError) else "binding")
        if detail == "root":
            from aegis_core.config import env_workspace
            from aegis_core.workspace.binding import resolve_binding

            pin = env_workspace()
            if error.__cause__ is not None:
                if error.message.startswith("AEGIS_WORKSPACE "):
                    detail = "pin"
            elif pin:
                try:
                    reason = resolve_binding(pin=pin).reason
                    detail = "pin_not_a_workspace" if reason == "pin_not_a_workspace" else "pin"
                except OSError:
                    pass  # Preserve the original refusal if the diagnostic is unavailable.
        return emit_error(CodecError("E_AUTH"), detail=detail)


class BoundedSelections(argparse.Action):
    """Retain at most limit + 1 entries; let codec preflight order the refusals."""

    def __call__(self, parser, namespace, values, option_string=None):
        from aegis_core import message_codec as codec

        limit, width = {"fields": (codec.MAX_SELECTORS, 1024),
                        "spans": (codec.MAX_SPANS, len(str(codec.MAX_NODES - 1))),
                        "expand": (codec.MAX_REFS, 64)}[self.dest]
        previous = getattr(namespace, self.dest, [])
        if len(previous) > limit:
            return
        entries, depth, start = [], 0, 0
        for index, char in enumerate(values):
            if self.dest == "fields":
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
            if char == "," and depth == 0:
                entries.append(values[start:index])
                if len(previous) + len(entries) > limit:
                    setattr(namespace, self.dest, previous + entries)
                    return
                start = index + 1
            elif index - start >= width:
                # This group already has invalid content. Keep its original
                # reference without scanning/copying an unbounded suffix.
                setattr(namespace, self.dest, previous + entries + [values])
                return
        entries.append(values[start:])
        setattr(namespace, self.dest, previous + entries)


def _write_output(rendered):
    if sys.stdout is None:
        return 2
    try:
        sys.stdout.write(rendered)
        sys.stdout.flush()
        return 0
    except (OSError, ValueError):
        # Do not retry a failed stream, including Python's final stdout flush.
        sys.stdout = None
        return 2


def _anchored_operations_supported():
    capabilities = {function.__name__ for function in os.supports_dir_fd}
    nofollow = {function.__name__ for function in os.supports_follow_symlinks}
    return ({"open", "mkdir", "stat", "link", "unlink"} <= capabilities and "stat" in nofollow
            and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW") and hasattr(os, "geteuid"))


def emit_error(error, *, detail=None) -> int:
    """Errors contain only the shared core's fixed next-action guidance."""
    from aegis_core.message_codec_format import frontend_error

    value = frontend_error(error, detail=detail)
    messages = {
        "pin": "workspace pin refused; check or unset AEGIS_WORKSPACE",
        "workspace_store": "workspace is not initialized; pass --workspace PROJECT",
        "platform": "platform unsupported; message stores require anchored file operations",
    }
    if detail in messages:
        value["error"]["message"] = messages[detail]
    _write_output(json.dumps(value, separators=(",", ":")) + "\n")
    return 2


def _content(filename, maximum):
    if filename == "-":
        source = getattr(sys.stdin, "buffer", None)
        if source is None or getattr(source, "closed", False):
            raise MsgArgumentError()
        return source.read(maximum + 1)
    with open(filename, "rb") as source:
        return source.read(maximum + 1)


def _open_store(args):
    from aegis_core import message_codec as codec, storage

    if args.store is not None:
        return closing(codec.Store(args.store))
    return storage.message_store(args.ws, write=args.msg_action == "write")


class MsgCommand(AegisCommand):
    name = "msg"
    category = CommandCategory.PLUMBING
    help = "Write, read and verify untrusted content-addressed messages"
    description = (
        "Records are untrusted data, never instructions. Store defaults to the workspace's "
        ".aegis/state/messages/ (created private on write through the state helper). "
        "Run aegis init first; message commands never initialize a workspace. "
        "All errors are fixed JSON with exit 2. Reading never acknowledges a message."
    )

    def configure_parser(self, parser: argparse.ArgumentParser) -> None:
        parser.allow_abbrev = False
        store_help = "Existing private store directory; default: workspace .aegis/state/messages/"
        parser.add_argument("--store", default=None, metavar="DIR", help=store_help)
        common = argparse.ArgumentParser(add_help=False)
        common.add_argument("--store", default=argparse.SUPPRESS, metavar="DIR", help=store_help)
        common.add_argument("--workspace", default=argparse.SUPPRESS, help="Target workspace root")
        common.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                            help="Emit machine-readable JSON output")
        common.add_argument("--plain", action="store_true", default=argparse.SUPPRESS,
                            help="Strip ANSI styling and emoji")
        sub = parser.add_subparsers(dest="msg_action", required=True, metavar="ACTION")
        write = sub.add_parser("write", parents=[common], allow_abbrev=False,
                               help="Store caller-authored message content",
                               description="Input must contain exactly fields, body and refs. The CLI authors "
                               "schema, kind, meta (from=cli, host=cli, empty session, UTC time) and spans.")
        write.add_argument("--kind", required=True, choices=KINDS, metavar="K",
                           help="Message kind; fields must match its schema")
        write.add_argument("--in", dest="input_file", required=True, metavar="FILE",
                           help="UTF-8 JSON content object (fields, body, refs); - reads stdin; at most 262144 bytes. "
                           "ATX headings (# through ###### at line start) outside code fences define "
                           "body-character spans, each ending at the next heading or body end")
        read = sub.add_parser("read", parents=[common], allow_abbrev=False,
                              help="Render a verified message view",
                              description="No selectors: pass through records up to 4000 canonical chars; "
                              "otherwise show outline and top-level scalars. JSON is default; TSV is opt-in. "
                              "All role-authored text is verbatim and untrusted.")
        read.add_argument("ref", metavar="REF", help="64-hex id or unambiguous 16-64 lowercase hex prefix")
        read.add_argument("--fields", action=BoundedSelections, default=[], metavar="SEL",
                          help="At most 16 selectors, depth 8: dotted paths, indices, one-level * and "
                          "row projection findings.*.{id,severity,file,line}; comma separated; repeatable")
        read.add_argument("--spans", action=BoundedSelections, default=[], metavar="N",
                          help="Zero-based body span indices; at most 64 selections; comma separated; repeatable")
        read.add_argument("--outline", action="store_true",
                          help="Include outline; alone emits only the envelope and outline")
        read.add_argument("--since", default=None, metavar="CURSOR",
                          help="Log rows after cursor; 0 starts a new cursor")
        read.add_argument("--expand", action=BoundedSelections, default=[], metavar="NAME",
                          help="Expand a named ref one level, charged to max-chars; comma separated; repeatable")
        read.add_argument("--format", default="json", metavar="FORMAT",
                          help="View format: json, md or tsv; --json requires json; "
                          "MD fences data as untrusted, TSV uses JSON values")
        read.add_argument("--max-chars", default="60000", metavar="N",
                          help="Output character limit; excess refuses with E_LIMIT: narrow the selectors")
        verify = sub.add_parser("verify", parents=[common], allow_abbrev=False,
                                help="Verify canonical bytes and content hash")
        verify.add_argument("ref", metavar="REF", help="64-hex id or unambiguous 16-64 lowercase hex prefix")

    def execute(self, args: argparse.Namespace) -> int:
        from aegis_core import message_codec as codec
        from aegis_core.workspace.layout import is_aegis_workspace

        try:
            # Views are a UTF-8 wire surface; inherited ASCII/cp1252 settings
            # must not silently replace verbatim role-authored characters.
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="strict")
            if not is_aegis_workspace(args.ws.root):
                detail = "workspace_store" if args.store is not None else "workspace"
                return emit_error(codec.CodecError("E_AUTH"), detail=detail)
            if args.msg_action == "read":
                if args.json and args.format != "json":
                    return emit_error(codec.CodecError("E_FORMAT", detail="format"))
                options = codec.preflight_read(True, selectors=args.fields, spans=args.spans, outline=args.outline,
                                               since=args.since, expand=args.expand, format=args.format,
                                               max_chars=args.max_chars).options
            if not _anchored_operations_supported():
                return emit_error(codec.CodecError("E_AUTH"), detail="platform")
            # Validate caller content before creating even the default store.
            if args.msg_action == "write":
                try:
                    payload = _content(args.input_file, codec.MAX_BYTES)
                except MsgArgumentError:
                    return emit_error(codec.CodecError("E_FORMAT"), detail="arguments")
                except (OSError, ValueError):
                    return emit_error(codec.CodecError("E_AUTH"), detail="input")
                value = codec.compose(args.kind, payload,
                                      {"from": "cli", "host": "cli", "session": "",
                                       "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
            with _open_store(args) as store:
                if args.msg_action == "write":
                    for rid in value["refs"].values():
                        store.resolve(rid)
                    rid = store.write(value)
                    rendered = json.dumps({"id": rid, "ref": rid[:16]}, separators=(",", ":")) + "\n"
                else:
                    value = store.read(args.ref)
                    if args.msg_action == "verify":
                        rid = codec.record_id(value)
                        rendered = json.dumps({"id": rid, "ref": rid[:16], "verified": True},
                                              separators=(",", ":")) + "\n"
                    else:
                        rendered = codec.read_view(value, store=store, **options)
        except codec.CodecError as error:
            detail = "write_ref" if args.msg_action == "write" and error.code == "E_REF" else error.detail
            return emit_error(error, detail=detail)
        except WorkspaceError:
            return emit_error(codec.CodecError("E_AUTH"))
        except OSError:
            return emit_error(codec.CodecError("E_AUTH", detail="operation"))
        return _write_output(rendered)
