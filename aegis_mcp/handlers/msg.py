"""Workspace-bound message tools; composition and rendering belong to the codec."""
from datetime import datetime, timezone

from aegis_core import message_codec as codec, storage
from aegis_core.errors import WorkspaceError
from aegis_core.message_codec_format import MAX_OUTPUT_CHARS, frontend_error, require
from aegis_core.workspace.base import Workspace


class MessageText(str):
    """Already rendered by the codec; the transport must preserve these characters."""


def _store(workspace, *, write):
    """Both front ends use the storage layer's default-store preparation."""
    require(type(workspace) is Workspace, "E_AUTH")
    return storage.message_store(workspace, write=write)


def _content_bytes(content):
    """Bound the encoding allocation, then check UTF-8 bytes before JSON parsing."""
    require(type(content) is str)
    require(len(content) <= codec.MAX_BYTES, "E_LIMIT", detail="record")
    try:
        encoded = content.encode("utf-8")
    except UnicodeEncodeError:
        raise codec.CodecError("E_FORMAT") from None
    require(len(encoded) <= codec.MAX_BYTES, "E_LIMIT", detail="record")
    return encoded


def handle_msg_read(args):
    try:
        options = codec.preflight_read(selectors=args.get("fields", ()), spans=args.get("spans", ()),
                                       outline=args.get("outline", False), since=args.get("since"),
                                       expand=args.get("expand", ()), format=args.get("format", "json"),
                                       max_chars=args.get("max_chars", 60000)).options
        with _store(args.get("workspace"), write=False) as store:
            value = store.read(args.get("ref"))
            return MessageText(codec.read_view(value, store=store, **options))
    except codec.CodecError as error:
        return frontend_error(error, detail=error.detail)
    except WorkspaceError:
        return codec.CodecError("E_AUTH").as_dict()
    except OSError:
        return codec.CodecError("E_AUTH", detail="operation").as_dict()


def handle_msg_write(args):
    try:
        content = _content_bytes(args.get("content"))
        value = codec.compose(args.get("kind"), content,
                              {"from": "mcp", "host": args.get("_host", "generic"),
                               "session": args.get("_session", ""),
                               "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})
        with _store(args.get("workspace"), write=True) as store:
            for rid in value["refs"].values():
                store.resolve(rid)
            rid = store.write(value)
            return {"id": rid, "ref": rid[:16]}
    except codec.CodecError as error:
        return frontend_error(error, detail="write_ref" if error.code == "E_REF" else error.detail)
    except WorkspaceError:
        return codec.CodecError("E_AUTH").as_dict()
    except OSError:
        return codec.CodecError("E_AUTH", detail="operation").as_dict()


def message_result(result):
    """Bound the only pre-rendered response seam; other results stay JSON objects."""
    if type(result) is MessageText:
        if len(result) <= MAX_OUTPUT_CHARS:
            return str(result), False
        result = codec.CodecError("E_LIMIT").as_dict()
    return result, True
