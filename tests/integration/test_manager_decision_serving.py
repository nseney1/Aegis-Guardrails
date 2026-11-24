"""Exercise the manager decision workflow over direct stdio wire sessions."""
from __future__ import annotations

import codecs
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import copy
from dataclasses import dataclass, field
import errno
import hashlib
import io
import json
import ntpath
import os
from pathlib import Path
from queue import Empty, Queue
import re
import shutil
import stat
import subprocess
import sys
from tempfile import TemporaryFile
from threading import Barrier, Thread
import time
from time import monotonic
from types import SimpleNamespace
import uuid
from venv import EnvBuilder

import pytest

from aegis_core import pathlookup
from aegis_core.config import ENV_MANAGER_CONFIG, ENV_MANAGER_CONFIG_SHA256
from aegis_core.manager_policy import ACTIONS, digest
from aegis_core.primitives import real_key, real_path, strict_loads
from tests import helpers_manager

REPO = Path(__file__).resolve().parents[2]
CONTRACT_SNAPSHOT = REPO / "tests" / "contract" / "manager_mcp_tools.json"
CLIENT = "orchard-review-client"
SUBJECT = {"member_id": "aegis", "worktree_id": "orchard-review", "phase": "cutover"}
WORKSPACE = "orchard-management"
SERVER = "aegis-manager"
TOOLS = frozenset({"aegis_list_rules", "aegis_scan", "aegis_report_outcome"})
CODEX_SELECTION = "AEGIS_TEST_MANAGER_CODEX"
ADAPTER_SELECTION = "AEGIS_TEST_MANAGER_ADAPTER"
MAX_FRAME = 1024 * 1024
manager_root = helpers_manager.manager_root


class RegistrationRefused(ValueError):
    """The direct manager launch, filesystem identity, schema, or teardown failed qualification."""


def guard_direct_only(
    *,
    adapter: str = "direct-wire",
    requested: object = None,
    environ: Mapping[str, str] | None = None,
) -> None:
    """Registered-host qualification belongs to MANAGER-RULES-SERVING-d; HOLD before launching anything."""
    env_map = os.environ if environ is None else environ
    selected_adapter = env_map.get(ADAPTER_SELECTION)
    extra_manager_selection = any(
        isinstance(key, str)
        and key.upper().startswith("AEGIS_TEST_MANAGER_")
        and (key.upper() != ADAPTER_SELECTION or val != "direct-wire")
        for key, val in env_map.items()
    )
    if (
        requested is not None
        or adapter != "direct-wire"
        or CODEX_SELECTION in env_map
        or (selected_adapter is not None and selected_adapter != "direct-wire")
        or extra_manager_selection
    ):
        pytest.fail(
            "HOLD: registered-host qualification is deferred to MANAGER-RULES-SERVING-d; "
            "MANAGER-RULES-SERVING-c delivers direct-wire only",
            pytrace=False,
        )


def classify_observation(record: dict | None, *, status: str = "passed") -> str:
    """Classify local evidence; never credit direct wire, CLI history, or skips as registered."""
    if status == "skipped" or record is None:
        return "skipped"
    if type(record) is not dict:
        raise RegistrationRefused("invalid manager observation record")
    transport = record.get("observed_transport")
    if transport == "cli":
        if "adapter" in record or "registration_fingerprint" in record:
            raise RegistrationRefused("historical CLI audit cannot carry adapter credit")
        return "historical-cli"
    if transport != "stdio":
        raise RegistrationRefused("unexpected manager observation transport")
    if record.get("adapter") != "direct-wire" or "registration_fingerprint" not in record:
        raise RegistrationRefused("registered qualification is deferred to MANAGER-RULES-SERVING-d")
    if record["registration_fingerprint"] is not None:
        raise RegistrationRefused("direct-wire observation cannot carry a registration fingerprint")
    return "direct-wire"


def is_registered_observation(record: dict | None, *, status: str = "passed") -> bool:
    kind = classify_observation(record, status=status)
    assert kind in {"direct-wire", "historical-cli", "skipped"}
    return False


def _contains_surrogates(text: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


@dataclass(frozen=True)
class NativePath:
    """One parent-owned filesystem identity carried across process and text boundaries."""

    raw: bytes | None
    text: str

    @classmethod
    def from_parent(
        cls,
        value: Path | str | bytes | NativePath,
        *,
        mode: str | None = None,
    ) -> NativePath:
        if isinstance(value, NativePath):
            return value
        platform_mode = os.name if mode is None else mode
        if platform_mode == "nt":
            if isinstance(value, bytes):
                raise TypeError("Windows paths use native Unicode")
            spelled = os.fspath(value)
            if not isinstance(spelled, str) or not spelled or "\x00" in spelled:
                raise ValueError("invalid Windows path")
            if _contains_surrogates(spelled):
                raise ValueError("Windows native path contains lone surrogates")
            return cls(None, spelled)
        raw = value if isinstance(value, bytes) else os.fsencode(value)
        if not raw or b"\x00" in raw:
            raise ValueError("invalid POSIX path bytes")
        return cls(raw, os.fsdecode(raw))

    @property
    def is_windows(self) -> bool:
        return self.raw is None

    @property
    def path(self) -> Path:
        return Path(self.text if self.is_windows else os.fsdecode(self.raw))

    def fs_target(self) -> bytes | str:
        """Native bytes for POSIX filesystem syscalls and native Unicode on Windows."""
        return self.text if self.is_windows else self.raw

    def mkdir(self, mode: int = 0o700, *, exist_ok: bool = False) -> None:
        if self.is_windows or os.name == "nt":
            Path(self.text).mkdir(mode=mode, exist_ok=exist_ok)
            return
        try:
            os.mkdir(self.raw, mode)
        except FileExistsError:
            if not exist_ok or not stat.S_ISDIR(os.lstat(self.raw).st_mode):
                raise

    def child(self, name: str | bytes) -> NativePath:
        if self.is_windows:
            if not isinstance(name, str):
                raise TypeError("Windows child names must be str")
            if not name or "\x00" in name or _contains_surrogates(name) or "\\" in name or "/" in name:
                raise ValueError("invalid Windows child segment")
            sep = "" if self.text.endswith(("\\", "/")) else "\\"
            joined = str(Path(self.text) / name) if os.name == "nt" else self.text + sep + name
            return NativePath.from_parent(joined, mode="nt")
        part = name if isinstance(name, bytes) else os.fsencode(name)
        if not part or b"/" in part or b"\x00" in part:
            raise ValueError("invalid POSIX child segment")
        sep = b"" if self.raw.endswith(b"/") else b"/"
        return NativePath.from_parent(self.raw + sep + part, mode="posix")

    def process_text(self) -> str:
        """Exact OS argv/environ string preserving native bytes on POSIX and Unicode on Windows."""
        if self.is_windows:
            return self.text
        spelled = os.fsdecode(self.raw)
        assert os.fsencode(spelled) == self.raw
        return spelled

    def utf8(self) -> str:
        """Verified UTF-8 spelling for JSON boundaries; Windows keeps native Unicode."""
        if self.is_windows:
            return self.text
        try:
            decoded = self.raw.decode("utf-8")
        except UnicodeDecodeError:
            pytest.fail("disposable path must be representable as UTF-8", pytrace=False)
        if _contains_surrogates(decoded):
            pytest.fail("disposable path contains surrogate code points", pytrace=False)
        return decoded

    def cli_serialized(self, child_encoding: str | None = None) -> str:
        """Exact JSON string produced by Python CLI serialization under child_encoding."""
        if self.is_windows:
            return self.text
        encoding = codecs.lookup(child_encoding or sys.getfilesystemencoding()).name
        if encoding == "ascii":
            return self.raw.decode("ascii", "surrogateescape")
        return self.utf8()

    def resolve_existing(
        self,
        *,
        kind: str = "any",
        key_fn=real_key,
        path_fn=real_path,
        stat_fn=os.stat,
        samefile_fn=os.path.samefile,
        os_name: str | None = None,
    ) -> NativePath | None:
        """Resolve an existing filesystem object; return None when absent or unresolvable."""
        active_os = os.name if os_name is None else os_name
        if self.is_windows != (active_os == "nt"):
            return None
        if self.is_windows:
            try:
                key = key_fn(self.text)
                if key is None:
                    return None
                resolved = path_fn(self.text)
                if not isinstance(resolved, str) or not resolved or "\x00" in resolved or _contains_surrogates(resolved):
                    return None
                _ = stat_fn(self.text)
                st_real = stat_fn(resolved)
                if not samefile_fn(self.text, resolved):
                    return None
            except (OSError, RuntimeError, TypeError, ValueError):
                return None
            if not _matches_kind(st_real.st_mode, kind):
                return None
            return NativePath.from_parent(resolved, mode="nt")

        try:
            st = os.stat(self.raw)
            resolved_raw = os.path.realpath(self.raw)
            if not resolved_raw or b"\x00" in resolved_raw or os.path.islink(resolved_raw):
                return None
            st_real = os.stat(resolved_raw)
            if not os.path.samestat(st, st_real):
                return None
        except (OSError, RuntimeError, TypeError, ValueError):
            return None
        if not _matches_kind(st_real.st_mode, kind):
            return None
        return NativePath.from_parent(resolved_raw, mode="posix")

    def require_existing(self, label: str, *, kind: str = "any") -> NativePath:
        resolved = self.resolve_existing(kind=kind)
        if resolved is None:
            raise RegistrationRefused(f"direct manager {label} identity unavailable")
        return resolved

    def same_entry(self, other: Path | str | bytes | NativePath) -> bool:
        if self.is_windows != (os.name == "nt"):
            return False
        self_resolved = self.resolve_existing()
        if self_resolved is None:
            return False
        try:
            other_id = NativePath.from_parent(other, mode="nt" if self.is_windows else "posix")
        except (TypeError, ValueError):
            return False
        other_resolved = other_id.resolve_existing()
        if other_resolved is None:
            return False
        try:
            if self.is_windows:
                return (
                    os.path.samefile(self.text, other_id.text)
                    and real_key(self_resolved.text) == real_key(other_resolved.text)
                )
            return (
                os.path.samestat(os.stat(self.raw), os.stat(other_id.raw))
                and os.path.samestat(os.stat(self_resolved.raw), os.stat(other_resolved.raw))
            )
        except OSError:
            return False


def _matches_kind(mode: int, kind: str) -> bool:
    if kind == "dir":
        return stat.S_ISDIR(mode)
    if kind == "file":
        return stat.S_ISREG(mode)
    if kind == "any":
        return stat.S_ISREG(mode) or stat.S_ISDIR(mode)
    raise ValueError("unknown filesystem entry kind")


def verify_json_identity(expected: NativePath, claimed: object) -> bool:
    """Verify UTF-8/Unicode spelling at JSON boundary AND existing native same-file identity."""
    if type(claimed) is not str or not claimed or "\x00" in claimed or _contains_surrogates(claimed):
        return False
    if expected.is_windows:
        if ntpath.normcase(claimed) != ntpath.normcase(expected.utf8()):
            return False
        return expected.same_entry(claimed)
    if claimed != expected.utf8():
        return False
    try:
        claimed_raw = claimed.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return expected.same_entry(claimed_raw)


def read_json(raw: bytes | str):
    assert len(raw) <= MAX_FRAME, "response exceeds the test budget"
    try:
        return strict_loads(raw)
    except (ValueError, RecursionError):
        pytest.fail("invalid JSON response", pytrace=False)


def _is_link_or_reparse(info: object) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    mode = getattr(info, "st_mode", 0)
    attrs = getattr(info, "st_file_attributes", 0) or 0
    return stat.S_ISLNK(mode) or bool(attrs & reparse_flag)


def read_regular_bytes(path: Path | NativePath, *, lstat_fn=os.lstat, fdopen_fn=os.fdopen) -> bytes:
    """Read a regular non-symlink file within MAX_FRAME, closing descriptors on every path."""
    if isinstance(path, NativePath):
        if path.is_windows != (os.name == "nt"):
            raise RegistrationRefused("direct manager file identity unavailable")
        target = path.fs_target()
    else:
        target = path
    try:
        info = lstat_fn(target)
    except OSError:
        raise RegistrationRefused("direct manager file missing") from None
    if _is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise RegistrationRefused("direct manager file mismatch")
    if info.st_size > MAX_FRAME:
        raise RegistrationRefused("direct manager file exceeds the test budget")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        fd = os.open(target, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise RegistrationRefused("direct manager file mismatch") from None
        raise RegistrationRefused("direct manager file missing") from None
    try:
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                raise RegistrationRefused("direct manager file mismatch")
            if opened.st_size > MAX_FRAME:
                raise RegistrationRefused("direct manager file exceeds the test budget")
            if os.name != "nt" and not os.path.samestat(info, opened):
                raise RegistrationRefused("direct manager file mismatch")
            with fdopen_fn(fd, "rb", closefd=False) as handle:
                raw = handle.read(MAX_FRAME + 1)
        except OSError:
            raise RegistrationRefused("direct manager file unreadable") from None
    finally:
        os.close(fd)
    if len(raw) > MAX_FRAME:
        raise RegistrationRefused("direct manager file exceeds the test budget")
    return raw


def capture_command(command, *, timeout, cwd=None, env=None, stdin=None):
    run_cwd = cwd.process_text() if isinstance(cwd, NativePath) else cwd
    run_args = [part.process_text() if isinstance(part, NativePath) else part for part in command]
    with TemporaryFile() as stdout, TemporaryFile() as stderr:
        try:
            result = subprocess.run(
                run_args,
                cwd=run_cwd,
                env=env,
                input=stdin,
                stdout=stdout,
                stderr=stderr,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            pytest.fail("disposable tool timed out", pytrace=False)
        except OSError:
            pytest.fail("disposable tool failed to start or complete", pytrace=False)
        stdout.seek(0)
        stderr.seek(0)
        result.stdout = stdout.read(MAX_FRAME + 1)
        result.stderr = stderr.read(MAX_FRAME + 1)
        return result


class CheckoutRuntime(EnvBuilder):
    """Build an isolated Python runtime bound to one verified checkout identity."""

    def __init__(self, checkout: Path | NativePath, *, flags=(), environment=None):
        super().__init__(symlinks=(os.name == "posix"), with_pip=False)
        self.checkout_id = NativePath.from_parent(checkout)
        self.checkout_id.require_existing("checkout", kind="dir")
        self.flags = tuple(flags)
        self.environment = environment
        self.root_id: NativePath | None = None
        self.command_id: NativePath | None = None
        self.command: str = ""

    def create(self, env_dir):
        guard_direct_only()
        self.root_id = NativePath.from_parent(env_dir)
        super().create(self.root_id.process_text())

    def post_setup(self, context):
        selected = getattr(context, "env_exec_cmd", context.env_exe)
        self.command_id = NativePath.from_parent(selected)
        self.command_id.require_existing("command", kind="file")
        self.command = self.command_id.process_text()
        purelib = self._query_purelib()
        literal = (
            ascii(self.checkout_id.text)
            if os.name == "nt"
            else "os.fsdecode(" + ascii(self.checkout_id.raw) + ")"
        )
        bootstrap = "import os, sys; sys.path.insert(0, " + literal + ")\n"
        purelib.child("checkout.pth").path.write_text(bootstrap, encoding="ascii")

    def _query_purelib(self) -> NativePath:
        code = (
            "import json, os, sysconfig; "
            "pure = sysconfig.get_path('purelib'); "
            "print(json.dumps(pure if os.name == 'nt' else os.fsencode(pure).hex()))"
        )
        result = capture_command(
            [self.command, "-I", *self.flags, "-c", code],
            env=self.environment,
            timeout=30,
        )
        assert result.returncode == 0, "isolated Python runtime metadata lookup failed"
        pure_val = read_json(result.stdout)
        resolved = NativePath.from_parent(
            pure_val if os.name == "nt" else bytes.fromhex(pure_val)
        )
        resolved.require_existing("purelib", kind="dir")
        return resolved

    def query_native_path(self, setup: str) -> NativePath:
        code = (
            "import json, os; " + setup + "; "
            "print(json.dumps(path if os.name == 'nt' else os.fsencode(path).hex()))"
        )
        result = capture_command(
            [self.command, "-I", *self.flags, "-c", code],
            env=self.environment,
            timeout=30,
        )
        assert result.returncode == 0, "isolated Python path lookup failed"
        value = read_json(result.stdout)
        return NativePath.from_parent(value if os.name == "nt" else bytes.fromhex(value))


class LegacyContextRuntime(CheckoutRuntime):
    """EnvBuilder contexts that only expose env_exe still launch the checkout."""

    def post_setup(self, context):
        super().post_setup(SimpleNamespace(env_exe=context.env_exe, env_dir=context.env_dir))


def shipped_manager_schemas() -> dict[str, dict]:
    """Load the reviewed manager input schemas from the shipped contract snapshot."""
    raw = read_regular_bytes(CONTRACT_SNAPSHOT)
    try:
        document = strict_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise RegistrationRefused("shipped manager contract unreadable") from exc
    tools = document.get("tools") if type(document) is dict else None
    if type(tools) is not list or len(tools) != len(TOOLS):
        raise RegistrationRefused("shipped manager contract invalid")
    schemas: dict[str, dict] = {}
    for item in tools:
        if type(item) is not dict:
            raise RegistrationRefused("shipped manager contract invalid")
        name = item.get("name")
        schema = item.get("inputSchema")
        if type(name) is not str or name in schemas or name not in TOOLS or type(schema) is not dict:
            raise RegistrationRefused("shipped manager contract invalid")
        schemas[name] = schema
    if set(schemas) != TOOLS:
        raise RegistrationRefused("shipped manager contract invalid")
    return schemas


def shipped_manager_actions(
    *,
    expected_schemas: Mapping[str, dict] | None = None,
    policy_actions: frozenset[str] | set[str] = ACTIONS,
) -> tuple[str, ...]:
    """Derive the canonical manager action order from the shipped MCP schema, verified against ACTIONS."""
    from aegis_mcp.manager import TOOL_DEFINITIONS

    schemas = shipped_manager_schemas() if expected_schemas is None else dict(expected_schemas)
    scan_schema = schemas.get("aegis_scan")
    props = scan_schema.get("properties") if type(scan_schema) is dict else None
    action_prop = props.get("action") if type(props) is dict else None
    contract_enum = action_prop.get("enum") if type(action_prop) is dict else None
    product_tools = [
        item for item in TOOL_DEFINITIONS if type(item) is dict and item.get("name") == "aegis_scan"
    ]
    product_schema = product_tools[0].get("inputSchema") if len(product_tools) == 1 else None
    product_props = product_schema.get("properties") if type(product_schema) is dict else None
    product_action = product_props.get("action") if type(product_props) is dict else None
    product_enum = product_action.get("enum") if type(product_action) is dict else None
    if (
        type(contract_enum) is not list
        or type(product_enum) is not list
        or not isinstance(policy_actions, (set, frozenset))
        or not all(type(name) is str and bool(name) for name in contract_enum)
        or contract_enum != product_enum
        or len(product_enum) != len(policy_actions)
        or len(set(product_enum)) != len(product_enum)
        or set(product_enum) != set(policy_actions)
    ):
        raise RegistrationRefused("shipped manager action contract invalid")
    return tuple(product_enum)


def verify_advertised_tool_schemas(
    advertised: object,
    expected_schemas: Mapping[str, dict] | None = None,
) -> dict[str, dict]:
    """Verify every advertised manager tool and its exact inputSchema against the shipped contract."""
    contract = shipped_manager_schemas() if expected_schemas is None else dict(expected_schemas)
    if type(advertised) is not list or len(advertised) != len(contract):
        raise RegistrationRefused("direct manager tool schema mismatch")
    verified: dict[str, dict] = {}
    for entry in advertised:
        if type(entry) is not dict:
            raise RegistrationRefused("direct manager tool schema mismatch")
        name = entry.get("name")
        schema = entry.get("inputSchema")
        if (
            type(name) is not str
            or name in verified
            or name not in contract
            or type(schema) is not dict
            or schema != contract[name]
        ):
            raise RegistrationRefused("direct manager tool schema mismatch")
        verified[name] = schema
    if set(verified) != set(contract):
        raise RegistrationRefused("direct manager tool schema mismatch")
    return verified


class StdioClient:
    def __init__(self, process):
        self.process = process
        self.responses: Queue[bytes | None] = Queue()
        self.reader = Thread(target=self.read_responses, daemon=True)
        self.reader.start()
        self.request_id = 0
        self.registration_fingerprint = None
        self.instructions: str | None = None
        self.schemas_verified = False

    def read_responses(self):
        for _ in range(4096):
            try:
                line = self.process.stdout.readline(MAX_FRAME + 1)
            except (OSError, ValueError):
                break
            if not line.endswith(b"\n") or len(line) > MAX_FRAME:
                break
            self.responses.put(line)
        self.responses.put(None)

    def send(self, frame: dict) -> None:
        try:
            self.process.stdin.write((json.dumps(frame) + "\n").encode("ascii"))
            self.process.stdin.flush()
        except OSError:
            if not self.schemas_verified:
                raise RegistrationRefused("direct manager handshake closed early") from None
            pytest.fail("stdio request write failed", pytrace=False)

    def request(self, method: str, **params):
        self.request_id += 1
        self.send({"jsonrpc": "2.0", "id": self.request_id, "method": method, "params": params})
        deadline = monotonic() + 30
        while monotonic() < deadline:
            try:
                line = self.responses.get(timeout=max(0, deadline - monotonic()))
            except Empty:
                if not self.schemas_verified:
                    raise RegistrationRefused("direct manager handshake timed out") from None
                pytest.fail("stdio response deadline elapsed", pytrace=False)
            if line is None:
                if not self.schemas_verified:
                    raise RegistrationRefused("direct manager handshake closed early")
                pytest.fail("stdio response unavailable or exceeds the test budget", pytrace=False)
            response = read_json(line)
            if type(response) is not dict:
                raise RegistrationRefused("direct manager response invalid")
            if "id" in response and "method" not in response:
                if response["id"] != self.request_id or "result" not in response:
                    if not self.schemas_verified:
                        raise RegistrationRefused("direct manager handshake failed")
                    pytest.fail("unexpected stdio response to " + method, pytrace=False)
                return response["result"]
        if not self.schemas_verified:
            raise RegistrationRefused("direct manager handshake timed out")
        pytest.fail("stdio response deadline elapsed", pytrace=False)

    def call(self, name: str, arguments: dict, *, refused: bool = False):
        guard_direct_only()
        if not self.schemas_verified:
            raise RegistrationRefused("direct manager tool schemas unverified")
        if self.registration_fingerprint is not None:
            raise RegistrationRefused("direct manager cannot carry a registration fingerprint")
        result = self.request("tools/call", name=name, arguments=arguments)
        assert bool(result.get("isError")) is refused, "unexpected manager tool error state"
        return read_json(result["content"][0]["text"])


def host_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith(("AEGIS_", "CODEX_", "OPENAI_", "ANTHROPIC_"))
    }


def matching_launcher_serialized(
    command_id: NativePath,
    claimed: str,
    child_encoding: str | None,
) -> bool:
    if claimed == command_id.cli_serialized(child_encoding):
        return True
    if sys.platform == "darwin" and not command_id.is_windows:
        try:
            raw = (
                claimed.encode("ascii", "surrogateescape")
                if codecs.lookup(child_encoding or sys.getfilesystemencoding()).name == "ascii"
                else claimed.encode("utf-8")
            )
        except UnicodeEncodeError:
            return False
        return command_id.same_entry(raw)
    return False


def bind_owned_config(
    config_path: Path | NativePath,
    command_path: Path | NativePath,
    entry: dict,
    *,
    child_encoding: str | None = None,
) -> tuple[dict, NativePath, NativePath]:
    """Verify CLI proposal serialization against existing parent-owned native identities."""
    config_id = NativePath.from_parent(config_path)
    command_id = NativePath.from_parent(command_path)
    command_id.require_existing("command", kind="file")
    config_id.require_existing("config", kind="file")
    if type(entry) is not dict or set(entry) != {"command", "args", "env"}:
        raise RegistrationRefused("CLI manager registration mismatch")
    claimed_command = entry.get("command")
    args = entry.get("args")
    env = entry.get("env")
    if (
        type(claimed_command) is not str
        or not matching_launcher_serialized(command_id, claimed_command, child_encoding)
        or type(args) is not list
        or args != ["-I", "-m", "aegis_mcp"]
        or type(env) is not dict
        or set(env) != {ENV_MANAGER_CONFIG, ENV_MANAGER_CONFIG_SHA256}
    ):
        raise RegistrationRefused("CLI manager registration mismatch")
    claimed_config = env.get(ENV_MANAGER_CONFIG)
    pinned = env.get(ENV_MANAGER_CONFIG_SHA256)
    if (
        type(claimed_config) is not str
        or claimed_config != config_id.cli_serialized(child_encoding)
        or type(pinned) is not str
        or not re.fullmatch(r"[0-9a-f]{64}", pinned)
    ):
        raise RegistrationRefused("CLI manager registration mismatch")
    payload = read_regular_bytes(config_id)
    if hashlib.sha256(payload).hexdigest() != pinned or not config_id.same_entry(config_id.fs_target()):
        raise RegistrationRefused("CLI manager registration mismatch")
    bound_env = {ENV_MANAGER_CONFIG: config_id.process_text(), ENV_MANAGER_CONFIG_SHA256: pinned}
    bound = {"command": command_id.process_text(), "args": list(args), "env": bound_env}
    return bound, config_id, command_id


@dataclass(frozen=True)
class ManagerHost:
    home_id: NativePath
    sessions_id: NativePath
    entry: dict = field(repr=False)
    environment: dict = field(repr=False)
    config_id: NativePath | None = None
    command_id: NativePath | None = None
    expected_args: tuple[str, ...] = ("-I", "-m", "aegis_mcp")

    @property
    def home(self) -> Path:
        return self.home_id.path

    def json_entry(self) -> dict:
        command = self.command_id.utf8() if self.command_id is not None else self.entry["command"]
        config_utf8 = (
            self.config_id.utf8()
            if self.config_id is not None
            else self.entry["env"].get(ENV_MANAGER_CONFIG)
        )
        env = {
            key: (config_utf8 if key == ENV_MANAGER_CONFIG and config_utf8 is not None else value)
            for key, value in self.entry["env"].items()
        }
        return {"command": command, "args": list(self.entry["args"]), "env": env}


def build_direct_environment(
    parent_env: Mapping[str, str],
    entry_env: Mapping[str, str],
    *,
    is_windows: bool,
) -> dict[str, str]:
    """Validate and merge parent-owned base env with exact manager config bindings."""
    if not isinstance(parent_env, Mapping) or not isinstance(entry_env, Mapping):
        raise RegistrationRefused("direct manager environment invalid")
    if set(entry_env) != {ENV_MANAGER_CONFIG, ENV_MANAGER_CONFIG_SHA256}:
        raise RegistrationRefused("direct manager environment mismatch")
    merged: dict[str, str] = {}
    seen_upper: dict[str, str] = {}
    for key, value in parent_env.items():
        if type(key) is not str or type(value) is not str or not key or "\x00" in key or "\x00" in value:
            raise RegistrationRefused("direct manager environment invalid")
        if key.upper().startswith("AEGIS_"):
            raise RegistrationRefused("direct manager environment mismatch")
        if is_windows:
            prev = seen_upper.get(key.upper())
            if prev is not None and prev != key:
                merged.pop(prev, None)
            seen_upper[key.upper()] = key
        merged[key] = value
    for key, value in entry_env.items():
        if type(key) is not str or type(value) is not str or not value or "\x00" in key or "\x00" in value:
            raise RegistrationRefused("direct manager environment invalid")
        if is_windows:
            prev = seen_upper.get(key.upper())
            if prev is not None and prev != key:
                merged.pop(prev, None)
            seen_upper[key.upper()] = key
        merged[key] = value
    return merged


def prepare_direct_launch(
    host: ManagerHost,
    session_cwd: NativePath,
    *,
    environ: Mapping[str, str] | None = None,
) -> tuple[list[str], dict[str, str], str]:
    """Verify exact command, args, env, cwd, and config digest before spawning direct stdio."""
    guard_direct_only(environ=environ)
    if host.command_id is None or host.config_id is None:
        raise RegistrationRefused("direct manager launch identity missing")
    host.command_id.require_existing("command", kind="file")
    host.config_id.require_existing("config", kind="file")
    if not isinstance(session_cwd, NativePath):
        raise RegistrationRefused("direct manager cwd identity unavailable")
    session_cwd.require_existing("cwd", kind="dir")

    entry = host.entry
    if type(entry) is not dict or set(entry) != {"command", "args", "env"}:
        raise RegistrationRefused("direct manager launch mismatch")
    command_text = host.command_id.process_text()
    if entry.get("command") != command_text or not host.command_id.same_entry(command_text):
        raise RegistrationRefused("direct manager command mismatch")

    args = entry.get("args")
    if (
        type(args) is not list
        or len(args) < 3
        or not all(type(part) is str and bool(part) and "\x00" not in part for part in args)
        or tuple(args) != tuple(host.expected_args)
        or args[0] != "-I"
        or args[-2:] != ["-m", "aegis_mcp"]
    ):
        raise RegistrationRefused("direct manager args mismatch")

    entry_env = entry.get("env")
    if type(entry_env) is not dict or set(entry_env) != {ENV_MANAGER_CONFIG, ENV_MANAGER_CONFIG_SHA256}:
        raise RegistrationRefused("direct manager environment mismatch")
    spelled = entry_env.get(ENV_MANAGER_CONFIG)
    pinned = entry_env.get(ENV_MANAGER_CONFIG_SHA256)
    if (
        type(spelled) is not str
        or spelled != host.config_id.process_text()
        or type(pinned) is not str
        or not re.fullmatch(r"[0-9a-f]{64}", pinned)
    ):
        raise RegistrationRefused("direct manager config mismatch")
    payload = read_regular_bytes(host.config_id)
    if hashlib.sha256(payload).hexdigest() != pinned or not host.config_id.same_entry(spelled):
        raise RegistrationRefused("direct manager config digest mismatch")

    launch_env = build_direct_environment(
        host.environment,
        entry_env,
        is_windows=host.command_id.is_windows,
    )
    cwd_text = session_cwd.process_text()
    if not session_cwd.same_entry(cwd_text):
        raise RegistrationRefused("direct manager cwd identity unavailable")
    return [command_text, *args], launch_env, cwd_text


def discover_wire(
    client: StdioClient,
    *,
    expected_schemas: Mapping[str, dict] | None = None,
) -> str:
    """Confirm server identity, standing instructions, and each shipped tool inputSchema."""
    init = client.request(
        "initialize",
        protocolVersion="2024-11-05",
        clientInfo={"name": CLIENT, "version": "1"},
        capabilities={},
    )
    if (
        type(init) is not dict
        or type(init.get("serverInfo")) is not dict
        or init["serverInfo"].get("name") != "aegis-manager-mcp"
        or type(init.get("instructions")) is not str
        or not init["instructions"]
    ):
        raise RegistrationRefused("direct manager initialize mismatch")
    client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    listed_reply = client.request("tools/list")
    if type(listed_reply) is not dict:
        raise RegistrationRefused("direct manager tool schema mismatch")
    verify_advertised_tool_schemas(listed_reply.get("tools"), expected_schemas)
    client.schemas_verified = True
    return init["instructions"]


def finish_stdio_process(
    process,
    reader: Thread | None,
    *,
    had_error: bool,
    timeout: float = 5.0,
) -> None:
    """Bound process/reader cleanup, preserve the first refusal, and surface bad exit otherwise."""
    teardown_problem: str | None = None
    stdin = getattr(process, "stdin", None)
    if stdin is not None:
        try:
            stdin.close()
        except (OSError, BufferError, ValueError):
            teardown_problem = "direct manager stdin close failed"

    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        teardown_problem = teardown_problem or "direct manager process teardown timed out"
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            teardown_problem = "direct manager process did not terminate after kill"
        except OSError:
            teardown_problem = teardown_problem or "direct manager process wait failed"
    except OSError:
        teardown_problem = teardown_problem or "direct manager process wait failed"

    stdout = getattr(process, "stdout", None)
    if reader is not None:
        reader.join(timeout=timeout)
        if reader.is_alive():
            if stdout is not None:
                try:
                    stdout.close()
                except (OSError, BufferError, ValueError):
                    pass
            reader.join(timeout=min(1.0, timeout))
            if reader.is_alive():
                teardown_problem = teardown_problem or "direct manager reader teardown timed out"
    if stdout is not None:
        try:
            stdout.close()
        except (OSError, BufferError, ValueError):
            teardown_problem = teardown_problem or "direct manager stdout close failed"

    if teardown_problem is None and process.returncode != 0:
        teardown_problem = "direct manager process exited unsuccessfully"

    if not had_error and teardown_problem is not None:
        raise RegistrationRefused(teardown_problem)


@contextmanager
def connect(
    host: ManagerHost,
    *,
    session_cwd: NativePath | None = None,
    popen=subprocess.Popen,
    teardown_timeout: float = 5.0,
    expected_schemas: Mapping[str, dict] | None = None,
    environ: Mapping[str, str] | None = None,
):
    guard_direct_only(environ=environ)
    if session_cwd is None:
        host.sessions_id.require_existing("sessions", kind="dir")
        session_root = host.sessions_id.child("conn-" + uuid.uuid4().hex)
        session_root.mkdir(mode=0o700)
        active_cwd = session_root.child("cwd")
        active_cwd.mkdir(mode=0o700)
    else:
        active_cwd = session_cwd

    command, env, cwd_text = prepare_direct_launch(host, active_cwd, environ=environ)
    try:
        process = popen(
            command,
            env=env,
            cwd=cwd_text,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        raise RegistrationRefused("direct manager launch failed") from None
    client = StdioClient(process)
    had_error = False
    try:
        client.instructions = discover_wire(client, expected_schemas=expected_schemas)
        yield client
    except BaseException:
        had_error = True
        raise
    finally:
        finish_stdio_process(
            process,
            client.reader,
            had_error=had_error,
            timeout=teardown_timeout,
        )


def check_step_bounds(
    result: subprocess.CompletedProcess | None,
    operation: str,
) -> subprocess.CompletedProcess:
    if result is None or result.returncode is None:
        pytest.fail("disposable Git SSH capability failed: timeout (" + operation + ")", pytrace=False)
    if len(result.stdout or b"") > MAX_FRAME or len(result.stderr or b"") > MAX_FRAME:
        pytest.fail("disposable Git SSH capability response exceeds the test budget", pytrace=False)
    if result.returncode < 0:
        pytest.fail("disposable Git SSH capability failed: interrupted (" + operation + ")", pytrace=False)
    return result


def signing_result(result: subprocess.CompletedProcess | None, operation: str) -> None:
    checked = check_step_bounds(result, operation)
    if checked.returncode != 0:
        pytest.fail("disposable Git SSH capability failed: " + operation, pytrace=False)


def require_product_owner_verification(result: subprocess.CompletedProcess | None) -> None:
    """Require product Git log verification to report G and exact single owner principal."""
    checked = check_step_bounds(result, "verify commit")
    if checked.returncode != 0:
        pytest.fail("disposable Git SSH capability failed: verify commit", pytrace=False)
    if (checked.stdout or b"").splitlines() != [b"G", b"owner"]:
        pytest.fail("disposable Git SSH capability failed: product owner verification", pytrace=False)


@dataclass(frozen=True)
class SshEvidence:
    sign: subprocess.CompletedProcess | None
    principals: subprocess.CompletedProcess | None = None
    verify: subprocess.CompletedProcess | None = None
    signature_ready: bool = False
    signature_armor: bool = False


def require_ssh_capability(evidence: SshEvidence) -> None:
    """Require complete disposable signing, owner lookup, and independent verification."""
    sign = check_step_bounds(evidence.sign, "sign commit")
    if sign.returncode != 0 or not evidence.signature_ready or not evidence.signature_armor:
        pytest.fail("disposable Git SSH capability failed: sign commit", pytrace=False)
    principals = check_step_bounds(evidence.principals, "owner lookup")
    if principals.returncode != 0:
        pytest.fail("disposable Git SSH capability failed: owner lookup", pytrace=False)
    owners = (principals.stdout or b"").splitlines()
    if [line.strip() for line in owners if line.strip()] != [b"owner"] or len(owners) != 1:
        pytest.fail("disposable Git SSH capability failed: wrong owner", pytrace=False)
    verify = check_step_bounds(evidence.verify, "verify signature")
    if verify.returncode != 0:
        pytest.fail("disposable Git SSH capability failed: verify signature", pytrace=False)


def run_tool(command, args, cwd: Path | NativePath, environment: dict):
    return capture_command([command, *args], cwd=cwd, env={**environment, "LC_ALL": "C"}, timeout=15)


@dataclass(frozen=True)
class SigningTools:
    git: str
    ssh: str
    key_id: NativePath
    signers_id: NativePath
    environment: dict = field(repr=False)

    @property
    def key(self) -> Path:
        return self.key_id.path

    @property
    def signers(self) -> Path:
        return self.signers_id.path

    def git_result(self, root: Path | NativePath, *args):
        return run_tool(
            self.git,
            ("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", *args),
            root,
            self.environment,
        )

    def git_text(self, root: Path | NativePath, *args) -> str:
        result = self.git_result(root, *args)
        assert result.returncode == 0 and len(result.stdout) <= MAX_FRAME, "disposable Git command failed"
        return result.stdout.decode("ascii").strip()

    def sign(self, root: Path | NativePath, message: str):
        return self.git_result(
            root,
            "-c",
            "gpg.format=ssh",
            "-c",
            "gpg.ssh.program=" + self.ssh,
            "-c",
            "user.signingkey=" + self.key_id.process_text(),
            "commit",
            "--allow-empty",
            "--no-verify",
            "-S",
            "-qm",
            message,
        )


def signing_tools(
    root: Path | NativePath,
    environment: dict,
    *,
    release: bool = False,
) -> SigningTools:
    guard_direct_only()
    root_id = NativePath.from_parent(root)
    root_id.require_existing("signing root", kind="dir")
    search = environment.get("PATH", os.defpath)
    extensions = environment.get("PATHEXT")
    fence = root_id.path
    git = pathlookup.which("git", path=search, outside=fence, fence_program=True, pathext=extensions)
    ssh = pathlookup.which("ssh-keygen", path=search, outside=fence, pathext=extensions)
    if git is None or ssh is None:
        if release:
            pytest.fail("disposable Git SSH capability failed: git or ssh-keygen missing", pytrace=False)
        pytest.skip("disposable Git SSH capability unavailable: git or ssh-keygen missing")
    return SigningTools(git, ssh, root_id.child("owner-key"), root_id.child("trusted-signers"), environment)


def signing_environment(home: Path | NativePath, source: dict) -> dict:
    home_id = NativePath.from_parent(home)
    home_id.mkdir(mode=0o700)
    empty_config = home_id.child("gitconfig")
    empty_config.path.write_text("", encoding="ascii")
    inherited = {
        key: value
        for key, value in source.items()
        if not key.upper().startswith(("GIT_", "AEGIS_"))
        and key.upper() not in {"HOME", "USERPROFILE", "XDG_CONFIG_HOME"}
    }
    spelled = home_id.process_text()
    return {
        **inherited,
        "HOME": spelled,
        "USERPROFILE": spelled,
        "XDG_CONFIG_HOME": spelled,
        "GIT_CONFIG_GLOBAL": empty_config.process_text(),
        "GIT_CONFIG_NOSYSTEM": "1",
    }


def verify_probe_commit(runtime: CheckoutRuntime, tools: SigningTools, control: NativePath):
    program = """\
import sys
from aegis_core import gitsafe, pathlookup

control, git, ssh, signers = sys.argv[1:]
if gitsafe.git_executable(cwd=control) != git or pathlookup.which("ssh-keygen", outside=control) != ssh:
    raise SystemExit("signing tools differ from product verification")
with gitsafe.scrubbed():
    result = gitsafe.run(
        [
            "-c", "gpg.format=ssh",
            "-c", "gpg.ssh.program=" + ssh,
            "-c", "gpg.ssh.allowedSignersFile=" + signers,
            "log", "-1", "--format=%G?%n%GS",
        ],
        control,
        timeout=5,
    )
sys.stdout.buffer.write(result.stdout)
sys.stderr.buffer.write(result.stderr)
raise SystemExit(result.returncode)
"""
    return capture_command(
        [
            runtime.command_id,
            "-I",
            *runtime.flags,
            "-c",
            program,
            control,
            tools.git,
            tools.ssh,
            tools.signers_id,
        ],
        cwd=control,
        env=tools.environment,
        timeout=15,
    )


def read_bounded_artifact(path: Path | NativePath, *, budget_message: str) -> bytes:
    """Read an optional regular non-symlink artifact within MAX_FRAME, closing fd on every path."""
    target = path.fs_target() if isinstance(path, NativePath) else path
    try:
        info = os.lstat(target)
    except OSError:
        return b""
    if _is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
        return b""
    if info.st_size > MAX_FRAME:
        pytest.fail(budget_message, pytrace=False)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        fd = os.open(target, flags)
    except OSError:
        return b""
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            return b""
        if opened.st_size > MAX_FRAME:
            pytest.fail(budget_message, pytrace=False)
        if os.name != "nt" and not os.path.samestat(info, opened):
            return b""
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read(MAX_FRAME + 1)
    except OSError:
        return b""
    finally:
        os.close(fd)
    if len(raw) > MAX_FRAME:
        pytest.fail(budget_message, pytrace=False)
    return raw


def read_signature(path: NativePath) -> bytes:
    return read_bounded_artifact(
        path,
        budget_message="disposable Git SSH capability response exceeds the test budget",
    )


def probe_git_ssh(tools: SigningTools, control: Path | NativePath, runtime: CheckoutRuntime) -> None:
    control_id = NativePath.from_parent(control)
    control_id.require_existing("control repository", kind="dir")
    signing_result(tools.git_result(control_id, "--version"), "read Git version")
    generated = run_tool(
        tools.ssh,
        ("-q", "-t", "ed25519", "-N", "", "-f", tools.key_id.process_text()),
        control_id,
        tools.environment,
    )
    signing_result(generated, "generate ed25519 key")
    private_path = tools.key_id.path
    pub_path = Path(tools.key_id.process_text() + ".pub")
    if not private_path.is_file() or not pub_path.is_file():
        pytest.fail("disposable Git SSH capability failed: generate ed25519 key", pytrace=False)
    public = read_bounded_artifact(
        pub_path,
        budget_message="disposable Git SSH capability response exceeds the test budget",
    )
    if not public.strip():
        pytest.fail("disposable Git SSH capability failed: generate ed25519 key", pytrace=False)
    tools.signers_id.path.write_bytes(b"owner " + public)
    if os.name == "posix":
        tools.signers_id.path.chmod(0o600)

    message = b"signing capability probe\n"
    message_id = control_id.child("capability-message")
    signature_id = control_id.child("capability-message.sig")
    message_id.path.write_bytes(message)
    signed = run_tool(
        tools.ssh,
        ("-Y", "sign", "-f", tools.key_id.process_text(), "-n", "git", message_id.process_text()),
        control_id,
        tools.environment,
    )
    signature = read_signature(signature_id)
    principals = None
    verified = None
    if signed.returncode == 0 and signature:
        principals = run_tool(
            tools.ssh,
            ("-Y", "find-principals", "-s", signature_id.process_text(), "-f", tools.signers_id.process_text()),
            control_id,
            tools.environment,
        )
        verified = capture_command(
            [
                tools.ssh,
                "-Y",
                "verify",
                "-f",
                tools.signers_id.process_text(),
                "-I",
                "owner",
                "-n",
                "git",
                "-s",
                signature_id.process_text(),
            ],
            cwd=control_id,
            env={**tools.environment, "LC_ALL": "C"},
            timeout=15,
            stdin=message,
        )
    require_ssh_capability(
        SshEvidence(
            sign=signed,
            principals=principals,
            verify=verified,
            signature_ready=bool(signature),
            signature_armor=b"-----BEGIN SSH SIGNATURE-----" in signature,
        )
    )
    signing_result(tools.sign(control_id, "signing capability probe"), "sign commit")
    verified_product = verify_probe_commit(runtime, tools, control_id)
    require_product_owner_verification(verified_product)


@pytest.fixture(scope="session")
def checkout_runtime(tmp_path_factory):
    guard_direct_only()
    runtime = CheckoutRuntime(REPO)
    runtime.create(tmp_path_factory.mktemp("manager-runtime").resolve())
    return runtime


def disposable_host(
    root: Path | NativePath,
    registration: dict,
    runtime: CheckoutRuntime,
    environment: dict,
    config_path: Path | NativePath,
    *,
    child_encoding: str | None = None,
    adapter: str = "direct-wire",
    requested: object = None,
    environ: Mapping[str, str] | None = None,
) -> ManagerHost:
    guard_direct_only(adapter=adapter, requested=requested, environ=environ)
    root_id = NativePath.from_parent(root)
    root_id.require_existing("host root", kind="dir")
    if type(registration) is not dict or set(registration) != {SERVER}:
        raise RegistrationRefused("CLI manager registration mismatch")
    bound_raw, config_id, command_id = bind_owned_config(
        config_path,
        runtime.command_id,
        registration[SERVER],
        child_encoding=child_encoding,
    )
    expected_args = (bound_raw["args"][0], *runtime.flags, *bound_raw["args"][1:])
    entry = dict(bound_raw, args=list(expected_args))
    host_home = root_id.child("disposable-host")
    host_home.mkdir(mode=0o700)
    sessions = root_id.child("disposable-sessions")
    sessions.mkdir(mode=0o700)
    return ManagerHost(
        host_home,
        sessions,
        entry,
        dict(environment),
        config_id=config_id,
        command_id=command_id,
        expected_args=expected_args,
    )


def write_cutover_policy(
    tools: SigningTools,
    control_id: NativePath,
    member_id: NativePath,
    rules: list[dict],
) -> str:
    control_id.require_existing("control repository", kind="dir")
    member_id.require_existing("member repository", kind="dir")
    policy_dir = control_id.child("manager-policy")
    policy_dir.mkdir()
    policy_dir.child("policy.json").path.write_text(
        json.dumps({"schema": "aegis.manager-policy/v1", "workspace_id": WORKSPACE, "rules": rules}),
        encoding="utf-8",
    )
    policy_dir.child("membership.json").path.write_text(
        json.dumps({
            "schema": "aegis.manager-membership/v1",
            "workspace_id": WORKSPACE,
            "repositories": [{
                "id": SUBJECT["member_id"],
                "common_dir": member_id.child(".git").utf8(),
                "worktrees": [{"id": SUBJECT["worktree_id"], "path": member_id.utf8()}],
            }],
        }),
        encoding="utf-8",
    )
    tools.git_text(control_id, "add", "manager-policy")
    tools.git_text(control_id, "commit", "-qm", "review cutover policy")
    return tools.git_text(control_id, "rev-parse", "HEAD")


def review_rules() -> list[dict]:
    return [
        {
            "id": "review-" + action,
            "actions": [action],
            "match": {"phase": "cutover"},
            "text": "Review the cutover record before the management decision.",
        }
        for action in (
            "delegation",
            "ownership",
            "hierarchy",
            "resource_budget",
            "checkpoint",
            "handoff",
            "evidence_review",
            "escalation",
            "policy_change",
        )
    ]


class WorkspaceCLI:
    """Disposable workspace CLI bound to one runtime and one native config path."""

    def __init__(self, runtime: CheckoutRuntime, config: Path | NativePath, environment: dict):
        self.runtime = runtime
        self.config_id = NativePath.from_parent(config)
        self.environment = dict(environment)

    @property
    def config(self) -> Path:
        return self.config_id.path

    @property
    def parent_id(self) -> NativePath:
        if self.config_id.is_windows:
            return NativePath.from_parent(self.config_id.path.parent, mode="nt")
        parent_raw = os.path.dirname(self.config_id.raw)
        return NativePath.from_parent(parent_raw, mode="posix")

    def call(self, operation: str, *arguments):
        guard_direct_only()
        self.runtime.command_id.require_existing("command", kind="file")
        self.parent_id.require_existing("cwd", kind="dir")
        result = capture_command(
            [
                self.runtime.command_id,
                "-I",
                *self.runtime.flags,
                "-m",
                "aegis_cli",
                "workspace",
                operation,
                "--config",
                self.config_id,
                "--json",
                *arguments,
            ],
            cwd=self.parent_id,
            env=self.environment,
            timeout=30,
        )
        assert result.returncode == 0, "disposable workspace CLI exited unsuccessfully"
        return read_json(result.stdout)

    def status(self):
        return self.call("status")


@pytest.fixture
def direct_manager(manager_root, checkout_runtime):
    guard_direct_only()
    rules = review_rules()
    expected_actions = shipped_manager_actions()
    rule_actions = [rule["actions"][0] for rule in rules]
    assert rule_actions == list(expected_actions)
    assert len(rule_actions) == len(ACTIONS) and set(rule_actions) == set(ACTIONS)
    root_id = NativePath.from_parent(manager_root)
    root_id.require_existing("manager root", kind="dir")
    environment = signing_environment(root_id.child("signing-home"), host_environment())
    tools = signing_tools(root_id, environment)
    control_id = root_id.child("control")
    member_id = root_id.child("member")
    for repo in (control_id, member_id):
        repo.mkdir()
        tools.git_text(repo, "init", "-q")
    probe_git_ssh(tools, control_id, checkout_runtime)
    tools.git_text(member_id, "commit", "--allow-empty", "-qm", "baseline")
    revision = write_cutover_policy(tools, control_id, member_id, rules)
    config_id = root_id.child("cutover-config.json")
    cli = WorkspaceCLI(checkout_runtime, config_id, environment)
    proposal = cli.call(
        "init",
        "--workspace-id",
        WORKSPACE,
        "--control-repo",
        control_id,
        "--store",
        root_id.child("cutover-audit"),
        "--trusted-signers",
        tools.signers_id,
    )
    host = disposable_host(
        root_id,
        proposal["registration"],
        checkout_runtime,
        environment,
        config_id,
    )
    digests = {}
    for name in ("policy", "membership"):
        result = tools.git_result(control_id, "show", revision + ":manager-policy/" + name + ".json")
        assert result.returncode == 0 and len(result.stdout) <= MAX_FRAME, "disposable Git policy lookup failed"
        digests[name + "_digest"] = hashlib.sha256(result.stdout).hexdigest()
    env = {"control": control_id, "member": member_id, "revision": revision, "tools": tools}
    return env, host, cli, rules, digests


def activate(env, cli: WorkspaceCLI) -> None:
    revision, control_id, tools = env["revision"], NativePath.from_parent(env["control"]), env["tools"]
    options = ("--revision", revision, "--expect", "none")
    candidate = cli.call("activate", *options)
    statement = candidate["approval_statement"]
    approval_digest = digest(statement)
    assert re.fullmatch(r"[0-9a-f]{64}", approval_digest)
    signed = tools.sign(control_id, "Owner approval\n\nAegis-Manager-Approve: " + approval_digest)
    signing_result(signed, "sign owner approval")
    approval = {"statement": statement, "commit": tools.git_text(control_id, "rev-parse", "HEAD")}
    approval_id = cli.parent_id.child("approval.json")
    approval_id.path.write_text(json.dumps(approval), encoding="ascii")
    cli.call("activate", *options, "--approval", approval_id)


def scan(client: StdioClient, action: str, context=SUBJECT, **options):
    return client.call("aegis_scan", {"action": action, "context": context}, **options)


def report(client: StdioClient, request: dict, **options):
    return client.call("aegis_report_outcome", request, **options)


def assert_direct_connection(client: StdioClient) -> None:
    assert client.schemas_verified is True
    assert client.registration_fingerprint is None


def first_report(client: StdioClient, action: str, decision: dict, request: dict, revisions: dict):
    assert re.fullmatch("[0-9a-f]{64}", decision["decision_ref"])
    provenance = decision["provenance"]
    assert provenance["transport"] == "mcp"
    assert provenance["client_name"] == CLIENT
    assert provenance["client_identity"] == "self_reported"
    assert provenance["native_identity"] is None
    assert re.fullmatch("[0-9a-f]{32}", provenance["session_id"])
    acknowledgement = report(client, request)
    assert acknowledgement["acknowledgement"] == "recorded"
    assert acknowledgement["decision_ref"] == decision["decision_ref"]
    assert acknowledgement["rule_revisions"] == revisions
    assert acknowledgement["provenance"] == provenance
    assert acknowledgement["fitness_credit"] == 0
    assert acknowledgement["human_approval"] == "not_established"
    assert acknowledgement["execution"] == "unverified"
    assert acknowledgement["verified_completion"] is False
    transcript_row = {
        "action": action,
        "observed_transport": "stdio",
        "adapter": "direct-wire",
        "registration_fingerprint": client.registration_fingerprint,
        "server_transport": provenance["transport"],
        "claimed_client_name": CLIENT,
        "session_id": provenance["session_id"],
        "decision_ref": decision["decision_ref"],
        "rule_revisions": revisions,
        "acknowledgement": "recorded",
    }
    assert classify_observation(transcript_row) == "direct-wire"
    assert is_registered_observation(transcript_row) is False
    print(json.dumps(transcript_row, sort_keys=True))
    return acknowledgement


def serve_compound(host: ManagerHost, cli: WorkspaceCLI, rules: list[dict], digests: dict, revision: str):
    with connect(host) as client:
        assert_direct_connection(client)
        assert "each action in a compound decision" in client.instructions
        listed = client.call("aegis_list_rules", {})
        assert listed["workspace_id"] == WORKSPACE
        assert listed["control_commit"] == revision
        assert {rule["id"] for rule in listed["rules"]} >= {rule["id"] for rule in rules}
        decisions = [scan(client, rule["actions"][0]) for rule in rules]
        decision_refs = [item["decision_ref"] for item in decisions]
        assert len(set(decision_refs)) == len(decisions)
        assert cli.status()["pending_decisions"] == sorted(decision_refs)
        for rule, decision in zip(rules, decisions):
            served = dict(rule, revision=digest(rule))
            assert served in listed["rules"]
            assert decision["rules"] == [served]
            assert {key: decision[key] for key in digests} == digests
            assert decision["activation_ref"] == listed["activation_ref"]
            request = {
                "decision_ref": decision["decision_ref"],
                "rules_used": [rule["id"]],
                "outcome": "success",
                "idempotency_key": "cutover-" + rule["id"],
            }
            acknowledgement = first_report(
                client,
                rule["actions"][0],
                decision,
                request,
                {rule["id"]: served["revision"]},
            )
        assert cli.status()["pending_decisions"] == []
    return request, decision, acknowledgement


def replay_historical_cli_report(host: ManagerHost, cli: WorkspaceCLI, rule: dict) -> str:
    action = rule["actions"][0]
    historical = cli.call("scan", "--action", action, "--context", json.dumps(SUBJECT))
    assert historical["provenance"] == {"transport": "cli", "native_identity": None}
    previous = cli.call(
        "report",
        "--decision",
        historical["decision_ref"],
        "--rules",
        rule["id"],
        "--outcome",
        "success",
        "--idempotency-key",
        "prior-cli",
    )
    assert previous["decision_ref"] == historical["decision_ref"]
    assert previous["provenance"] == historical["provenance"]
    assert previous["acknowledgement"] == "recorded"
    assert re.fullmatch("[0-9a-f]{64}", historical["decision_ref"])
    cli_row = {
        "action": action,
        "observed_transport": "cli",
        "decision_ref": historical["decision_ref"],
        "acknowledgement": "recorded",
    }
    assert classify_observation(cli_row) == "historical-cli"
    assert is_registered_observation(cli_row) is False
    print(json.dumps(cli_row, sort_keys=True))
    before = cli.status()
    request = {
        "decision_ref": historical["decision_ref"],
        "rules_used": [rule["id"]],
        "outcome": "success",
        "idempotency_key": "prior-cli",
    }
    with connect(host) as reconnected:
        assert_direct_connection(reconnected)
        assert report(reconnected, request) == previous
    assert cli.status() == before
    return historical["decision_ref"]


def test_direct_manager_serves_each_action_and_replays_matching_report(direct_manager):
    env, host, cli, rules, digests = direct_manager
    assert [rule["actions"][0] for rule in rules] == list(shipped_manager_actions())
    assert {rule["actions"][0] for rule in rules} == set(ACTIONS)
    activate(env, cli)
    historical_ref = replay_historical_cli_report(host, cli, rules[-1])
    action = rules[-1]["actions"][0]
    # Two compound decisions, with the public report rate limit applied per connection.
    serve_compound(host, cli, rules[:4], digests, env["revision"])
    request, decision, acknowledgement = serve_compound(host, cli, rules[4:], digests, env["revision"])
    assert decision["decision_ref"] != historical_ref
    before_retry = cli.status()
    assert before_retry["outcomes"] == len(rules) + 1
    assert before_retry["pending_decisions"] == []
    with connect(host) as reconnected:
        assert_direct_connection(reconnected)
        assert report(reconnected, request) == acknowledgement
        assert (
            report(reconnected, dict(request, outcome="failure"), refused=True)["error"]
            == "idempotency_conflict"
        )
        assert cli.status()["audit_head"] == before_retry["audit_head"]
        repeated = scan(reconnected, action)
        assert repeated["decision_ref"] != decision["decision_ref"]
        assert repeated["provenance"]["session_id"] != decision["provenance"]["session_id"]
        assert repeated["rules"] == decision["rules"]
        assert {key: repeated[key] for key in digests} == digests
        assert repeated["activation_ref"] == decision["activation_ref"]
        assert cli.status()["pending_decisions"] == [repeated["decision_ref"]]
        replay = dict(request, decision_ref=repeated["decision_ref"], idempotency_key="repeat-cutover")
        before = cli.status()["audit_head"]
        assert (
            report(reconnected, dict(replay, rules_used=["other-rule"]), refused=True)["error"]
            == "unserved_rules"
        )
        unchanged_status = cli.status()
        assert unchanged_status["audit_head"] == before
        assert unchanged_status["pending_decisions"] == [repeated["decision_ref"]]
        recorded = first_report(reconnected, action, repeated, replay, acknowledgement["rule_revisions"])
        after_first = cli.status()
        assert after_first["outcomes"] == before_retry["outcomes"] + 1
        assert after_first["pending_decisions"] == []

        with connect(host) as competing, ThreadPoolExecutor(max_workers=2) as workers:
            assert_direct_connection(competing)
            ready = Barrier(2, timeout=5)

            def submit_report(connection):
                ready.wait()
                return report(connection, replay)

            first = workers.submit(submit_report, reconnected)
            second = workers.submit(submit_report, competing)
            assert first.result(timeout=35) == second.result(timeout=35) == recorded
    status = cli.status()
    assert status == after_first
    assert status["pending_decisions"] == []


def test_direct_manager_review_paths_never_record_an_outcome(direct_manager):
    env, host, cli, _, _ = direct_manager
    draft_head = cli.status()["audit_head"]
    member_path = env["member"].path
    with connect(host) as client:
        assert_direct_connection(client)
        assert "Stop and request review" in client.instructions
        inactive = {"status": "FAIL", "error": "policy_not_active"}
        assert client.call("aegis_list_rules", {}, refused=True) == inactive
        assert scan(client, "handoff", refused=True) == inactive
        assert cli.status()["audit_head"] == draft_head
        activate(env, cli)
        assert client.call("aegis_list_rules", {})["rules"]
        unchanged = cli.status()["audit_head"]
        wrong_subject = dict(SUBJECT, worktree_id="unknown")
        assert scan(client, "handoff", wrong_subject, refused=True)["error"] == "unauthorized_membership"
        removed = member_path.with_name("removed")
        member_path.rename(removed)
        assert scan(client, "handoff", refused=True)["error"] == "membership_unavailable"
        assert cli.status()["audit_head"] == unchanged
        assert cli.status()["pending_decisions"] == []
        removed.rename(member_path)
        empty = scan(client, "handoff", dict(SUBJECT, phase="planning"))
        assert empty["rules"] == []
        status = cli.status()
        assert status["pending_decisions"] == [empty["decision_ref"]]
        assert status["outcomes"] == 0
        review_row = {
            "adapter": "direct-wire",
            "observed_transport": "stdio",
            "registration_fingerprint": client.registration_fingerprint,
            "review": [
                "policy_not_active",
                "unauthorized_membership",
                "membership_unavailable",
                "empty_match",
            ],
            "pending": len(status["pending_decisions"]),
            "outcomes": status["outcomes"],
        }
        assert classify_observation(review_row) == "direct-wire"
        assert is_registered_observation(review_row) is False
        print(json.dumps(review_row, sort_keys=True))


def make_non_ascii_child(parent: NativePath, label: str, *, release: bool = False) -> NativePath:
    """Create a valid non-ASCII directory under the host's observed native encoding."""
    try:
        target = parent.child(label)
        target.mkdir(mode=0o700)
    except (UnicodeEncodeError, OSError, ValueError):
        if release:
            pytest.fail("release host cannot create valid non-ASCII path under native encoding", pytrace=False)
        pytest.skip("host native encoding or filesystem cannot create non-ASCII filenames")
    return target


def test_isolated_checkout_identity_under_native_non_ascii_paths(manager_root):
    """One native identity under a valid non-ASCII ancestor across runtime, checkout, repos, config, and CLI."""
    guard_direct_only()
    observed_encoding = codecs.lookup(sys.getfilesystemencoding()).name
    root_id = NativePath.from_parent(manager_root)
    ancestor = make_non_ascii_child(root_id, "r\u00e9view-space")
    checkout_id = ancestor.child("r\u00e9view-checkout")
    runtime_root = ancestor.child("r\u00e9view-runtime")
    control_id = ancestor.child("r\u00e9view-control")
    member_id = ancestor.child("r\u00e9view-member")
    config_id = ancestor.child("r\u00e9view-config.json")

    checkout_id.mkdir()
    repo_id = NativePath.from_parent(REPO)
    for package in ("aegis_core", "aegis_mcp", "aegis_cli", "aegis_sdk"):
        shutil.copytree(
            repo_id.child(package).process_text(),
            checkout_id.child(package).process_text(),
            ignore=shutil.ignore_patterns("__pycache__"),
        )

    environment = signing_environment(ancestor.child("r\u00e9view-signing-home"), host_environment())
    runtime = LegacyContextRuntime(checkout_id, environment=environment)
    runtime.create(runtime_root)

    probe = capture_command(
        [
            runtime.command_id,
            "-I",
            "-c",
            "import sys; print(sys.getfilesystemencoding())",
        ],
        env=environment,
        timeout=15,
    )
    assert probe.returncode == 0, "isolated filesystem encoding probe failed"
    child_encoding = codecs.lookup(probe.stdout.decode("ascii").strip()).name
    assert child_encoding == observed_encoding

    for package in ("aegis_mcp", "aegis_cli"):
        imported = runtime.query_native_path("import " + package + " as module; path = module.__file__")
        assert imported.same_entry(checkout_id.child(package).child("__init__.py"))

    tools = signing_tools(ancestor, environment)
    for repo in (control_id, member_id):
        repo.mkdir()
        tools.git_text(repo, "init", "-q")
    probe_git_ssh(tools, control_id, runtime)
    tools.git_text(member_id, "commit", "--allow-empty", "-qm", "baseline")
    rules = review_rules()
    assert [rule["actions"][0] for rule in rules] == list(shipped_manager_actions())
    revision = write_cutover_policy(tools, control_id, member_id, rules)

    cli = WorkspaceCLI(runtime, config_id, environment)
    proposal = cli.call(
        "init",
        "--workspace-id",
        WORKSPACE,
        "--control-repo",
        control_id,
        "--store",
        ancestor.child("r\u00e9view-audit"),
        "--trusted-signers",
        tools.signers_id,
    )
    host = disposable_host(
        ancestor,
        proposal["registration"],
        runtime,
        environment,
        config_id,
        child_encoding=observed_encoding,
    )
    spelled = host.entry["env"][ENV_MANAGER_CONFIG]
    pinned = host.entry["env"][ENV_MANAGER_CONFIG_SHA256]
    assert spelled == config_id.process_text()
    assert config_id.same_entry(spelled)
    assert hashlib.sha256(read_regular_bytes(config_id)).hexdigest() == pinned
    assert verify_json_identity(config_id, host.json_entry()["env"][ENV_MANAGER_CONFIG])
    assert verify_json_identity(host.home_id, host.home_id.utf8())
    print(
        json.dumps(
            {"native_encoding": observed_encoding, "config_digest": pinned, "same_file": True},
            sort_keys=True,
        )
    )

    status = cli.status()
    assert status["workspace_id"] == WORKSPACE and status["policy_approval"] == "draft"
    with connect(host) as client:
        assert_direct_connection(client)
        assert client.call("aegis_list_rules", {}, refused=True) == {
            "status": "FAIL",
            "error": "policy_not_active",
        }
    env = {"control": control_id, "member": member_id, "revision": revision, "tools": tools}
    activate(env, cli)
    with connect(host) as active_client:
        assert_direct_connection(active_client)
        listed = active_client.call("aegis_list_rules", {})
        assert listed["control_commit"] == revision
        decision = scan(active_client, rules[0]["actions"][0])
        served = dict(rules[0], revision=digest(rules[0]))
        assert decision["rules"] == [served]
        report_request = {
            "decision_ref": decision["decision_ref"],
            "rules_used": [rules[0]["id"]],
            "outcome": "success",
            "idempotency_key": "identity-" + rules[0]["id"],
        }
        acknowledged = first_report(
            active_client,
            rules[0]["actions"][0],
            decision,
            report_request,
            {rules[0]["id"]: served["revision"]},
        )
    before_reconnect = cli.status()
    with connect(host) as reconnected:
        assert_direct_connection(reconnected)
        assert report(reconnected, report_request) == acknowledged
    assert cli.status() == before_reconnect
    replay_historical_cli_report(host, cli, rules[-1])


def test_explicit_registered_qualification_holds_before_any_launch(tmp_path):
    root_id = NativePath.from_parent(tmp_path.resolve())
    home_id = root_id.child("home")
    home_id.mkdir(mode=0o700)
    sessions_id = root_id.child("sessions")
    sessions_id.mkdir(mode=0o700)
    launcher_id = root_id.child("manager-python")
    launcher_id.path.write_text("", encoding="ascii")
    config_id = root_id.child("manager.json")
    payload = b'{"schema":"aegis.manager-config/v1"}\n'
    config_id.path.write_bytes(payload)
    pinned = hashlib.sha256(payload).hexdigest()
    entry = {
        "command": launcher_id.process_text(),
        "args": ["-I", "-m", "aegis_mcp"],
        "env": {ENV_MANAGER_CONFIG: config_id.process_text(), ENV_MANAGER_CONFIG_SHA256: pinned},
    }
    host = ManagerHost(
        home_id,
        sessions_id,
        entry,
        {"PATH": os.defpath},
        config_id=config_id,
        command_id=launcher_id,
    )

    launches: list[object] = []

    def forbidden_popen(*args, **kwargs):
        launches.append((args, kwargs))
        raise AssertionError("registered qualification request launched a subprocess")

    for env_case in (
        {CODEX_SELECTION: "codex"},
        {CODEX_SELECTION: sys.executable},
        {CODEX_SELECTION: ""},
        {ADAPTER_SELECTION: "registered-adapter"},
        {ADAPTER_SELECTION: "codex-app-server"},
        {"AEGIS_TEST_MANAGER_HOST": "1"},
    ):
        with pytest.raises(
            pytest.fail.Exception,
            match=r"^HOLD: registered-host qualification is deferred to MANAGER-RULES-SERVING-d",
        ):
            with connect(host, popen=forbidden_popen, environ=env_case):
                pass
        assert launches == []

    for bad_kwargs in (
        {"adapter": "registered-adapter"},
        {"requested": "codex"},
        {"requested": ""},
        {"environ": {CODEX_SELECTION: "codex"}},
    ):
        with pytest.raises(
            pytest.fail.Exception,
            match=r"^HOLD: registered-host qualification is deferred to MANAGER-RULES-SERVING-d",
        ):
            disposable_host(
                root_id,
                {SERVER: entry},
                SimpleNamespace(command_id=launcher_id, flags=()),
                {"PATH": os.defpath},
                config_id,
                **bad_kwargs,
            )
    assert launches == []
    assert list(sessions_id.path.iterdir()) == []


def test_direct_cli_and_skipped_observations_never_count_as_registered():
    direct_row = {
        "action": "handoff",
        "observed_transport": "stdio",
        "adapter": "direct-wire",
        "registration_fingerprint": None,
        "server_transport": "mcp",
        "claimed_client_name": CLIENT,
        "session_id": "a" * 32,
        "decision_ref": "b" * 64,
        "rule_revisions": {"review-handoff": "c" * 64},
        "acknowledgement": "recorded",
    }
    serialized = json.dumps(direct_row, sort_keys=True)
    assert '"adapter": "direct-wire"' in serialized
    assert '"registration_fingerprint": null' in serialized
    assert classify_observation(direct_row) == "direct-wire"
    assert is_registered_observation(direct_row) is False

    cli_row = {
        "action": "handoff",
        "observed_transport": "cli",
        "decision_ref": "d" * 64,
        "acknowledgement": "recorded",
    }
    assert classify_observation(cli_row) == "historical-cli"
    assert is_registered_observation(cli_row) is False
    assert classify_observation(None, status="skipped") == "skipped"
    assert classify_observation(direct_row, status="skipped") == "skipped"
    assert is_registered_observation(direct_row, status="skipped") is False

    for invalid_row in (
        dict(direct_row, adapter="codex-app-server"),
        dict(direct_row, registration_fingerprint="e" * 64),
        {k: v for k, v in direct_row.items() if k != "registration_fingerprint"},
        dict(cli_row, adapter="direct-wire"),
        {"observed_transport": "http"},
    ):
        with pytest.raises(RegistrationRefused):
            is_registered_observation(invalid_row)


def test_direct_launch_enforces_exact_args_env_config_digest_and_existing_identities(
    tmp_path, checkout_runtime
):
    from tests.conftest import symlink_or_skip

    root_id = NativePath.from_parent(tmp_path.resolve())
    config_id = root_id.child("draft-config.json")
    payload = b'{"schema":"aegis.manager-config/v1"}\n'
    config_id.path.write_bytes(payload)
    pinned = hashlib.sha256(payload).hexdigest()
    sentinel_env = {**host_environment(), "MANAGER_PARENT_SENTINEL": "exact-parent-value"}
    registration = {
        SERVER: {
            "command": checkout_runtime.command_id.cli_serialized(),
            "args": ["-I", "-m", "aegis_mcp"],
            "env": {
                ENV_MANAGER_CONFIG: config_id.cli_serialized(),
                ENV_MANAGER_CONFIG_SHA256: pinned,
            },
        }
    }
    host = disposable_host(root_id, registration, checkout_runtime, sentinel_env, config_id)
    explicit_cwd = root_id.child("explicit-cwd")
    explicit_cwd.mkdir(mode=0o700)

    recorded_spawns: list[tuple[list[str], dict[str, str], str]] = []

    def recording_popen(command, *, env, cwd, stdin, stdout, stderr):
        recorded_spawns.append((list(command), dict(env), cwd))
        return subprocess.Popen(
            command,
            env=env,
            cwd=cwd,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
        )

    with connect(host, session_cwd=explicit_cwd, popen=recording_popen) as client:
        assert_direct_connection(client)
        assert "Aegis manager decision audit" in client.instructions
        refusal = client.call("aegis_list_rules", {}, refused=True)
        assert refusal.get("status") == "FAIL" or isinstance(refusal.get("reason"), str)

    assert len(recorded_spawns) == 1
    launched_cmd, launched_env, launched_cwd = recorded_spawns[0]
    assert launched_cmd == [checkout_runtime.command_id.process_text(), "-I", *checkout_runtime.flags, "-m", "aegis_mcp"]
    assert launched_cwd == explicit_cwd.process_text()
    assert launched_env["MANAGER_PARENT_SENTINEL"] == "exact-parent-value"
    assert launched_env[ENV_MANAGER_CONFIG] == config_id.process_text()
    assert launched_env[ENV_MANAGER_CONFIG_SHA256] == pinned
    assert "AEGIS_WORKSPACE" not in {k.upper() for k in launched_env}

    # Verify Windows case-insensitive environment key replacement in build_direct_environment.
    win_merged = build_direct_environment(
        {"Path": r"C:\Windows\System32", "TEMP": r"C:\Temp"},
        {ENV_MANAGER_CONFIG: r"C:\Private\manager.json", ENV_MANAGER_CONFIG_SHA256: pinned},
        is_windows=True,
    )
    assert win_merged[ENV_MANAGER_CONFIG] == r"C:\Private\manager.json"

    launches: list[object] = []

    def never_popen(*args, **kwargs):
        launches.append((args, kwargs))
        raise AssertionError("invalid direct launch was not refused before spawn")

    missing_cmd = root_id.child("absent-python")
    missing_cfg = root_id.child("absent-config.json")
    missing_cwd = root_id.child("absent-cwd")
    regular_file = root_id.child("not-a-dir")
    regular_file.path.write_text("file", encoding="ascii")
    unresolvable_child = NativePath.from_parent(regular_file.path / "nested")

    bad_hosts_and_cwds = [
        (ManagerHost(host.home_id, host.sessions_id, dict(host.entry, command=missing_cmd.process_text()), sentinel_env, config_id=config_id, command_id=missing_cmd), explicit_cwd),
        (ManagerHost(host.home_id, host.sessions_id, host.entry, sentinel_env, config_id=config_id, command_id=explicit_cwd), explicit_cwd),
        (ManagerHost(host.home_id, host.sessions_id, dict(host.entry, env={ENV_MANAGER_CONFIG: missing_cfg.process_text(), ENV_MANAGER_CONFIG_SHA256: pinned}), sentinel_env, config_id=missing_cfg, command_id=checkout_runtime.command_id), explicit_cwd),
        (ManagerHost(host.home_id, host.sessions_id, host.entry, sentinel_env, config_id=config_id, command_id=checkout_runtime.command_id), missing_cwd),
        (ManagerHost(host.home_id, host.sessions_id, host.entry, sentinel_env, config_id=config_id, command_id=checkout_runtime.command_id), regular_file),
        (ManagerHost(host.home_id, host.sessions_id, host.entry, sentinel_env, config_id=config_id, command_id=checkout_runtime.command_id), unresolvable_child),
        (ManagerHost(host.home_id, host.sessions_id, dict(host.entry, args=["-m", "aegis_mcp"]), sentinel_env, config_id=config_id, command_id=checkout_runtime.command_id), explicit_cwd),
        (ManagerHost(host.home_id, host.sessions_id, dict(host.entry, args=["-I", "-O", "-m", "aegis_mcp"]), sentinel_env, config_id=config_id, command_id=checkout_runtime.command_id), explicit_cwd),
        (ManagerHost(host.home_id, host.sessions_id, dict(host.entry, env={**host.entry["env"], "AEGIS_WORKSPACE": str(REPO)}), sentinel_env, config_id=config_id, command_id=checkout_runtime.command_id), explicit_cwd),
        (ManagerHost(host.home_id, host.sessions_id, host.entry, {**sentinel_env, "AEGIS_WORKSPACE": str(REPO)}, config_id=config_id, command_id=checkout_runtime.command_id), explicit_cwd),
    ]
    for candidate_host, candidate_cwd in bad_hosts_and_cwds:
        with pytest.raises(RegistrationRefused):
            with connect(candidate_host, session_cwd=candidate_cwd, popen=never_popen):
                pass

    # Config digest mismatch after post-bind modification must refuse before spawn.
    tampered_cfg = root_id.child("tampered.json")
    tampered_cfg.path.write_bytes(b'{"schema":"aegis.manager-config/v1","tampered":true}\n')
    tampered_host = ManagerHost(
        host.home_id,
        host.sessions_id,
        dict(host.entry, env={ENV_MANAGER_CONFIG: tampered_cfg.process_text(), ENV_MANAGER_CONFIG_SHA256: pinned}),
        sentinel_env,
        config_id=tampered_cfg,
        command_id=checkout_runtime.command_id,
    )
    with pytest.raises(RegistrationRefused, match="digest mismatch"):
        with connect(tampered_host, session_cwd=explicit_cwd, popen=never_popen):
            pass

    # Symlink config, dangling symlink command/cwd, and symlink loop refusal before spawn.
    try:
        cfg_link = root_id.child("config-link.json")
        symlink_or_skip(config_id.path, cfg_link.path)
    except pytest.skip.Exception:
        pass
    else:
        dangling_link = root_id.child("dangling-link")
        symlink_or_skip(root_id.path / "no-such-target", dangling_link.path)
        loop_a = root_id.child("loop-a")
        loop_b = root_id.child("loop-b")
        symlink_or_skip(loop_b.path, loop_a.path)
        symlink_or_skip(loop_a.path, loop_b.path)

        for sym_host, sym_cwd in (
            (ManagerHost(host.home_id, host.sessions_id, dict(host.entry, env={ENV_MANAGER_CONFIG: cfg_link.process_text(), ENV_MANAGER_CONFIG_SHA256: pinned}), sentinel_env, config_id=cfg_link, command_id=checkout_runtime.command_id), explicit_cwd),
            (ManagerHost(host.home_id, host.sessions_id, dict(host.entry, command=dangling_link.process_text()), sentinel_env, config_id=config_id, command_id=dangling_link), explicit_cwd),
            (ManagerHost(host.home_id, host.sessions_id, dict(host.entry, command=loop_a.process_text()), sentinel_env, config_id=config_id, command_id=loop_a), explicit_cwd),
            (host, dangling_link),
            (host, loop_a),
        ):
            with pytest.raises(RegistrationRefused):
                with connect(sym_host, session_cwd=sym_cwd, popen=never_popen):
                    pass

    # Non-executable regular file as launcher surfaces a fixed refusal rather than raw OSError.
    non_exec = root_id.child("non-exec-launcher")
    non_exec.path.write_text("", encoding="ascii")
    non_exec_host = ManagerHost(
        host.home_id,
        host.sessions_id,
        dict(host.entry, command=non_exec.process_text()),
        sentinel_env,
        config_id=config_id,
        command_id=non_exec,
    )
    with pytest.raises(RegistrationRefused, match="^direct manager launch failed$"):
        with connect(non_exec_host, session_cwd=explicit_cwd):
            pass

    assert launches == []


def test_read_regular_bytes_enforces_limits_and_closes_fd_when_fdopen_raises(tmp_path):
    valid = tmp_path / "valid.json"
    valid.write_bytes(b"{}\n")
    closed_check: list[int] = []

    def failing_fdopen(fd, *_args, **_kwargs):
        closed_check.append(fd)
        raise RuntimeError("simulated fdopen failure")

    with pytest.raises(RuntimeError, match="^simulated fdopen failure$"):
        read_regular_bytes(valid, fdopen_fn=failing_fdopen)
    assert len(closed_check) == 1
    with pytest.raises(OSError) as err:
        os.fstat(closed_check[0])
    assert err.value.errno == errno.EBADF

    io_closed: list[int] = []

    def io_failing_fdopen(fd, *_args, **_kwargs):
        io_closed.append(fd)
        raise OSError(errno.EIO, "raw secret path /private/valid.json")

    with pytest.raises(RegistrationRefused, match="^direct manager file unreadable$") as refused_io:
        read_regular_bytes(valid, fdopen_fn=io_failing_fdopen)
    assert "valid.json" not in str(refused_io.value)
    assert len(io_closed) == 1
    with pytest.raises(OSError) as io_err:
        os.fstat(io_closed[0])
    assert io_err.value.errno == errno.EBADF

    reparse_stat = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=3, st_file_attributes=0x400)
    with pytest.raises(RegistrationRefused, match="^direct manager file mismatch$"):
        read_regular_bytes(valid, lstat_fn=lambda _p: reparse_stat)

    oversize = tmp_path / "oversize.json"
    oversize.write_bytes(b"x" * (MAX_FRAME + 1))
    with pytest.raises(RegistrationRefused, match="exceeds the test budget"):
        read_regular_bytes(oversize)


def _fake_stdio_exchange(tools_payload) -> tuple[StdioClient, list[dict]]:
    sent: list[dict] = []
    replies = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "serverInfo": {"name": "aegis-manager-mcp", "version": "1"},
                "instructions": "Aegis manager decision audit.",
            },
        },
        {"jsonrpc": "2.0", "id": 2, "result": {"tools": tools_payload}},
    ]
    stdout_bytes = b"".join((json.dumps(frame) + "\n").encode("ascii") for frame in replies)

    class _Stdin:
        def write(self, data: bytes) -> None:
            for line in data.splitlines():
                if line:
                    sent.append(json.loads(line.decode("ascii")))

        def flush(self) -> None:
            return None

    fake_proc = SimpleNamespace(stdin=_Stdin(), stdout=io.BytesIO(stdout_bytes), returncode=0)
    return StdioClient(fake_proc), sent


def test_discover_wire_checks_each_advertised_input_schema_against_shipped_contract():
    from aegis_mcp.manager import TOOL_DEFINITIONS

    shipped = shipped_manager_schemas()
    assert shipped == {item["name"]: item["inputSchema"] for item in TOOL_DEFINITIONS}

    baseline_tools = [
        {"name": name, "inputSchema": copy.deepcopy(schema)}
        for name, schema in sorted(shipped.items())
    ]
    ok_client, sent = _fake_stdio_exchange(baseline_tools)
    # Calling tools before discover_wire verifies schemas is refused before sending tools/call.
    with pytest.raises(RegistrationRefused, match="^direct manager tool schemas unverified$"):
        ok_client.call("aegis_list_rules", {})
    assert [msg["method"] for msg in sent] == []

    assert discover_wire(ok_client) == "Aegis manager decision audit."
    assert ok_client.schemas_verified is True

    mutations: list[object] = [
        baseline_tools[:-1],
        [*baseline_tools, {"name": "aegis_create_rule", "inputSchema": {"type": "object"}}],
        [baseline_tools[0], baseline_tools[0], baseline_tools[1]],
        "not-a-list",
    ]
    for target_name in ("aegis_scan", "aegis_list_rules", "aegis_report_outcome"):
        relaxed = copy.deepcopy(baseline_tools)
        for item in relaxed:
            if item["name"] == target_name:
                item["inputSchema"]["additionalProperties"] = True
        mutations.append(relaxed)

        injected_prop = copy.deepcopy(baseline_tools)
        for item in injected_prop:
            if item["name"] == target_name:
                item["inputSchema"] = dict(item["inputSchema"], properties={**item["inputSchema"].get("properties", {}), "workspace": {"type": "string"}})
        mutations.append(injected_prop)

    for bad_tools in mutations:
        bad_client, bad_sent = _fake_stdio_exchange(bad_tools)
        with pytest.raises(RegistrationRefused, match="^direct manager tool schema mismatch$"):
            discover_wire(bad_client)
        assert bad_client.schemas_verified is False
        with pytest.raises(RegistrationRefused, match="^direct manager tool schemas unverified$"):
            bad_client.call("aegis_list_rules", {})
        assert "tools/call" not in [msg.get("method") for msg in bad_sent]


def test_review_rules_match_shipped_canonical_action_order_and_refuse_drift():
    expected = shipped_manager_actions()
    rule_actions = tuple(rule["actions"][0] for rule in review_rules())
    assert rule_actions == expected
    assert len(rule_actions) == len(ACTIONS) and set(rule_actions) == set(ACTIONS)

    doc_text = (REPO / "docs" / "manager-workspaces.md").read_text(encoding="utf-8")
    doc_match = re.search(r"Supported actions are ([^.]+)\.", doc_text, re.DOTALL)
    assert doc_match is not None
    documented = tuple(re.findall(r"`([a-z_]+)`", doc_match.group(1)))
    assert documented == expected

    scrambled_set = frozenset(reversed(expected))
    assert shipped_manager_actions(policy_actions=scrambled_set) == expected

    base_schemas = shipped_manager_schemas()
    reordered = copy.deepcopy(base_schemas)
    reordered["aegis_scan"]["properties"]["action"]["enum"] = list(reversed(expected))
    truncated = copy.deepcopy(base_schemas)
    truncated["aegis_scan"]["properties"]["action"]["enum"] = list(expected[:-1])
    duplicated = copy.deepcopy(base_schemas)
    duplicated["aegis_scan"]["properties"]["action"]["enum"] = [expected[0], *expected[:-1]]

    for bad_schemas, bad_set in (
        (reordered, ACTIONS),
        (truncated, ACTIONS),
        (duplicated, ACTIONS),
        (base_schemas, frozenset(expected[:-1])),
        (base_schemas, frozenset((*expected[:-1], "other_action"))),
    ):
        with pytest.raises(RegistrationRefused, match="^shipped manager action contract invalid$"):
            shipped_manager_actions(expected_schemas=bad_schemas, policy_actions=bad_set)


def _build_stub_server_runtime(tmp_path: Path) -> tuple[CheckoutRuntime, NativePath, str]:
    root_id = NativePath.from_parent(tmp_path.resolve() / "stub-runtime-root")
    root_id.mkdir(mode=0o700)
    config_id = root_id.child("config.json")
    payload = b'{"schema":"aegis.manager-config/v1"}\n'
    config_id.path.write_bytes(payload)
    pinned = hashlib.sha256(payload).hexdigest()

    pkg_dir = root_id.child("aegis_mcp")
    pkg_dir.mkdir(mode=0o700)
    pkg_dir.child("__init__.py").path.write_text("", encoding="ascii")
    shipped_json = json.dumps(
        [{"name": k, "inputSchema": v} for k, v in sorted(shipped_manager_schemas().items())]
    )
    stub_main = f"""\
import json, os, sys, time

MODE = os.environ.get("MANAGER_STUB_MODE", "")
TOOLS = json.loads({shipped_json!r})
if MODE == "bad_schema_hang":
    TOOLS[0]["inputSchema"]["additionalProperties"] = True

for line in sys.stdin:
    req = json.loads(line)
    method = req.get("method")
    if method == "initialize":
        reply = {{"jsonrpc": "2.0", "id": req["id"], "result": {{"serverInfo": {{"name": "aegis-manager-mcp"}}, "instructions": "stub instructions"}}}}
        sys.stdout.write(json.dumps(reply) + "\\n")
        sys.stdout.flush()
    elif method == "tools/list":
        reply = {{"jsonrpc": "2.0", "id": req["id"], "result": {{"tools": TOOLS}}}}
        sys.stdout.write(json.dumps(reply) + "\\n")
        sys.stdout.flush()
        if MODE == "bad_schema_hang":
            time.sleep(30)

if MODE == "hang_on_eof":
    time.sleep(30)
if MODE in ("exit_nonzero", "body_refusal_and_nonzero"):
    raise SystemExit(3)
raise SystemExit(0)
"""
    pkg_dir.child("__main__.py").path.write_text(stub_main, encoding="utf-8")
    runtime = CheckoutRuntime(root_id)
    runtime.create(root_id.child("runtime"))
    return runtime, config_id, pinned


def _make_stub_server_host(
    tmp_path: Path,
    runtime: CheckoutRuntime,
    config_id: NativePath,
    pinned: str,
    mode: str,
) -> tuple[ManagerHost, NativePath]:
    case_root = NativePath.from_parent(tmp_path.resolve() / mode)
    case_root.mkdir(mode=0o700)
    home_id = case_root.child("home")
    home_id.mkdir(mode=0o700)
    sessions_id = case_root.child("sessions")
    sessions_id.mkdir(mode=0o700)
    cwd_id = case_root.child("cwd")
    cwd_id.mkdir(mode=0o700)
    entry = {
        "command": runtime.command_id.process_text(),
        "args": ["-I", "-m", "aegis_mcp"],
        "env": {ENV_MANAGER_CONFIG: config_id.process_text(), ENV_MANAGER_CONFIG_SHA256: pinned},
    }
    host = ManagerHost(
        home_id,
        sessions_id,
        entry,
        {**host_environment(), "MANAGER_STUB_MODE": mode},
        config_id=config_id,
        command_id=runtime.command_id,
    )
    return host, cwd_id


def test_connect_teardown_preserves_first_refusal_bounds_cleanup_and_surfaces_bad_exit(tmp_path):
    stub_runtime, config_id, pinned = _build_stub_server_runtime(tmp_path)

    # 1. Bad exit on otherwise successful completion is surfaced.
    bad_exit_host, bad_exit_cwd = _make_stub_server_host(tmp_path, stub_runtime, config_id, pinned, "exit_nonzero")
    with pytest.raises(RegistrationRefused, match="^direct manager process exited unsuccessfully$"):
        with connect(bad_exit_host, session_cwd=bad_exit_cwd, teardown_timeout=5.0) as client:
            assert_direct_connection(client)

    # 2. First refusal in discover_wire is preserved even when child hangs; cleanup is bounded.
    hang_schema_host, hang_schema_cwd = _make_stub_server_host(tmp_path, stub_runtime, config_id, pinned, "bad_schema_hang")
    started = time.monotonic()
    with pytest.raises(RegistrationRefused, match="^direct manager tool schema mismatch$"):
        with connect(hang_schema_host, session_cwd=hang_schema_cwd, teardown_timeout=0.3):
            pass
    assert time.monotonic() - started < 10.0

    # 3. First refusal in body is preserved even when child exits non-zero on teardown.
    body_err_host, body_err_cwd = _make_stub_server_host(tmp_path, stub_runtime, config_id, pinned, "body_refusal_and_nonzero")
    with pytest.raises(RegistrationRefused, match="^caller body refusal preserved$"):
        with connect(body_err_host, session_cwd=body_err_cwd, teardown_timeout=5.0):
            raise RegistrationRefused("caller body refusal preserved")

    # 4. Hang on EOF after otherwise successful completion is killed within bound and surfaced.
    eof_hang_host, eof_hang_cwd = _make_stub_server_host(tmp_path, stub_runtime, config_id, pinned, "hang_on_eof")
    started = time.monotonic()
    with pytest.raises(RegistrationRefused, match="^direct manager process teardown timed out$"):
        with connect(eof_hang_host, session_cwd=eof_hang_cwd, teardown_timeout=0.3) as client:
            assert_direct_connection(client)
    assert time.monotonic() - started < 10.0

    # 5. Pipe close failures preserve prior refusal when had_error=True and surface when False.
    class _BrokenStdin:
        def close(self):
            raise BrokenPipeError("broken pipe")

    class _BrokenStdout:
        def close(self):
            raise BufferError("exported pointers exist")

    proc = SimpleNamespace(
        stdin=_BrokenStdin(),
        stdout=io.BytesIO(b""),
        returncode=1,
        wait=lambda timeout=None: 1,
        kill=lambda: None,
    )
    finish_stdio_process(proc, None, had_error=True, timeout=0.2)
    with pytest.raises(RegistrationRefused, match="^direct manager stdin close failed$"):
        finish_stdio_process(proc, None, had_error=False, timeout=0.2)

    proc_stdout_err = SimpleNamespace(
        stdin=io.BytesIO(b""),
        stdout=_BrokenStdout(),
        returncode=0,
        wait=lambda timeout=None: 0,
        kill=lambda: None,
    )
    finish_stdio_process(proc_stdout_err, None, had_error=True, timeout=0.2)
    with pytest.raises(RegistrationRefused, match="^direct manager stdout close failed$"):
        finish_stdio_process(proc_stdout_err, None, had_error=False, timeout=0.2)


def test_native_path_identity_across_boundaries_and_windows_unicode(tmp_path):
    from tests.conftest import symlink_or_skip

    base = NativePath.from_parent(tmp_path.resolve())
    ancestor = make_non_ascii_child(base, "r\u00e9view-boundary")
    home_id = ancestor.child("r\u00e9view-home")
    home_id.mkdir(mode=0o700)
    cwd_id = ancestor.child("r\u00e9view-cwd")
    cwd_id.mkdir(mode=0o700)
    config_id = ancestor.child("r\u00e9view.json")
    command_id = NativePath.from_parent(sys.executable)
    payload = b'{"schema":"aegis.manager-config/v1"}\n'
    config_id.path.write_bytes(payload)
    pinned = hashlib.sha256(payload).hexdigest()

    # Verify JSON UTF-8 spelling + existing native same-file identity.
    for target in (home_id, cwd_id, config_id):
        assert verify_json_identity(target, target.utf8())
        assert not verify_json_identity(target, target.utf8() + "-other")

    # Absent and unresolvable filesystem identities are unconditionally refused.
    absent_id = ancestor.child("absent.json")
    assert absent_id.resolve_existing() is None
    assert not absent_id.same_entry(absent_id)
    assert not verify_json_identity(absent_id, absent_id.utf8())
    with pytest.raises(RegistrationRefused, match="identity unavailable"):
        absent_id.require_existing("config", kind="file")

    # Unsupported/unresolvable real_key returning None and Windows samefile checks refuse resolution.
    win_probe = NativePath.from_parent("C:\\Users\\r\u00e9view\\config.json", mode="nt")
    if os.name != "nt":
        assert win_probe.resolve_existing() is None
    fake_reg_stat = lambda _p: os.stat_result((stat.S_IFREG | 0o600, 1, 1, 1, 0, 0, 4, 0, 0, 0))
    assert (
        win_probe.resolve_existing(
            os_name="nt",
            key_fn=lambda _p: None,
            path_fn=lambda p: p,
            stat_fn=fake_reg_stat,
            samefile_fn=lambda _a, _b: True,
        )
        is None
    )
    assert (
        win_probe.resolve_existing(
            os_name="nt",
            key_fn=lambda _p: "c:\\users\\r\u00e9view\\config.json",
            path_fn=lambda p: p,
            stat_fn=fake_reg_stat,
            samefile_fn=lambda _a, _b: False,
        )
        is None
    )
    resolved_win = win_probe.resolve_existing(
        os_name="nt",
        key_fn=lambda _p: "c:\\users\\r\u00e9view\\config.json",
        path_fn=lambda p: p,
        stat_fn=fake_reg_stat,
        samefile_fn=lambda _a, _b: True,
        kind="file",
    )
    assert resolved_win == win_probe
    assert (
        win_probe.resolve_existing(
            os_name="nt",
            key_fn=lambda _p: "c:\\users\\r\u00e9view\\config.json",
            path_fn=lambda p: p,
            stat_fn=fake_reg_stat,
            samefile_fn=lambda _a, _b: True,
            kind="dir",
        )
        is None
    )

    try:
        dangling = ancestor.child("dangling.json")
        symlink_or_skip(ancestor.path / "missing-target.json", dangling.path)
    except pytest.skip.Exception:
        pass
    else:
        assert dangling.resolve_existing() is None
        assert not dangling.same_entry(dangling)
        assert not verify_json_identity(dangling, dangling.utf8())

    # Keep the inexpensive ASCII-parent boundary regression alongside UTF-8.
    for encoding in ("utf-8",) if os.name == "nt" else ("ascii", "utf-8"):
        entry = {
            "command": command_id.cli_serialized(encoding),
            "args": ["-I", "-m", "aegis_mcp"],
            "env": {
                ENV_MANAGER_CONFIG: config_id.cli_serialized(encoding),
                ENV_MANAGER_CONFIG_SHA256: pinned,
            },
        }
        bound, verified_cfg, verified_cmd = bind_owned_config(
            config_id, command_id, entry, child_encoding=encoding
        )
        assert verified_cfg == config_id and verified_cmd == command_id
        assert bound["command"] == command_id.process_text()
        assert bound["env"][ENV_MANAGER_CONFIG] == config_id.process_text()
        assert config_id.utf8().endswith("r\u00e9view.json")
        assert config_id.same_entry(bound["env"][ENV_MANAGER_CONFIG])

    # Absent command_id or absent config_id in bind_owned_config refuses immediately.
    valid_entry = {
        "command": command_id.cli_serialized("utf-8"),
        "args": ["-I", "-m", "aegis_mcp"],
        "env": {ENV_MANAGER_CONFIG: config_id.cli_serialized("utf-8"), ENV_MANAGER_CONFIG_SHA256: pinned},
    }
    with pytest.raises(RegistrationRefused, match="command identity unavailable"):
        bind_owned_config(config_id, ancestor.child("missing-python"), valid_entry, child_encoding="utf-8")
    with pytest.raises(RegistrationRefused, match="config identity unavailable"):
        bind_owned_config(absent_id, command_id, valid_entry, child_encoding="utf-8")

    if os.name != "nt":
        wrong_encoding_entry = {
            "command": command_id.cli_serialized("ascii"),
            "args": ["-I", "-m", "aegis_mcp"],
            "env": {
                ENV_MANAGER_CONFIG: config_id.cli_serialized("utf-8"),
                ENV_MANAGER_CONFIG_SHA256: pinned,
            },
        }
        with pytest.raises(RegistrationRefused, match="^CLI manager registration mismatch$"):
            bind_owned_config(config_id, command_id, wrong_encoding_entry, child_encoding="ascii")

    other = ancestor.child("other.json")
    other.path.write_bytes(payload)
    wrong_file = {
        "command": command_id.cli_serialized("utf-8"),
        "args": ["-I", "-m", "aegis_mcp"],
        "env": {ENV_MANAGER_CONFIG: other.cli_serialized("utf-8"), ENV_MANAGER_CONFIG_SHA256: pinned},
    }
    with pytest.raises(RegistrationRefused, match="^CLI manager registration mismatch$"):
        bind_owned_config(config_id, command_id, wrong_file, child_encoding="utf-8")

    wrong_digest = {
        "command": command_id.cli_serialized("utf-8"),
        "args": ["-I", "-m", "aegis_mcp"],
        "env": {ENV_MANAGER_CONFIG: config_id.cli_serialized("utf-8"), ENV_MANAGER_CONFIG_SHA256: "0" * 64},
    }
    with pytest.raises(RegistrationRefused, match="^CLI manager registration mismatch$"):
        bind_owned_config(config_id, command_id, wrong_digest, child_encoding="utf-8")

    # Native Windows Unicode spelling and absent-path refusal across platforms.
    win_id = NativePath.from_parent("C:\\Users\\r\u00e9view\\nonexistent-9912\\config.json", mode="nt")
    assert win_id.process_text() == win_id.utf8() == win_id.cli_serialized("ascii")
    assert win_id.child("nested.json").utf8().endswith("nested.json")
    assert not win_id.same_entry("c:\\users\\r\u00e9view\\nonexistent-9912\\config.json")
    assert not verify_json_identity(win_id, "c:\\users\\r\u00e9view\\nonexistent-9912\\config.json")
    with pytest.raises(TypeError, match="native Unicode"):
        NativePath.from_parent(b"C:\\Users\\config.json", mode="nt")
    with pytest.raises(ValueError, match="lone surrogates"):
        NativePath.from_parent("C:\\Users\\\udcc3\\config.json", mode="nt")


def test_runtime_accepts_legacy_env_builder_context_under_non_ascii_ancestor(tmp_path):
    base = NativePath.from_parent(tmp_path.resolve())
    ancestor = make_non_ascii_child(base, "r\u00e9view-space")
    runtime_dir = ancestor.child("runtime")
    runtime = LegacyContextRuntime(REPO)
    runtime.create(runtime_dir)
    imported = runtime.query_native_path("import aegis_mcp; path = aegis_mcp.__file__")
    assert imported.same_entry(REPO / "aegis_mcp" / "__init__.py")
    assert not (runtime_dir.path / "aegis-launches").exists()
    assert list(runtime_dir.path.rglob("_aegis_test_runtime_hook.py")) == []


@pytest.mark.parametrize(
    "evidence,expected",
    [
        (
            SshEvidence(
                sign=subprocess.CompletedProcess([], 1, stderr=b"artifact left behind"),
                principals=subprocess.CompletedProcess([], 0, stdout=b"owner\n"),
                verify=subprocess.CompletedProcess([], 0),
                signature_ready=True,
                signature_armor=True,
            ),
            "sign commit",
        ),
        (
            SshEvidence(
                sign=subprocess.CompletedProcess([], 0),
                signature_ready=False,
                signature_armor=False,
            ),
            "sign commit",
        ),
        (
            SshEvidence(
                sign=subprocess.CompletedProcess([], 0),
                signature_ready=True,
                signature_armor=False,
            ),
            "sign commit",
        ),
        (
            SshEvidence(
                sign=subprocess.CompletedProcess([], 1, stderr=b"invalid option -- Y"),
                signature_ready=False,
                signature_armor=False,
            ),
            "sign commit",
        ),
        (
            SshEvidence(
                sign=subprocess.CompletedProcess([], -11),
                signature_ready=False,
                signature_armor=False,
            ),
            r"interrupted \(sign commit\)",
        ),
        (
            SshEvidence(
                sign=subprocess.CompletedProcess([], None),
                signature_ready=False,
                signature_armor=False,
            ),
            r"timeout \(sign commit\)",
        ),
        (
            SshEvidence(
                sign=subprocess.CompletedProcess([], 0),
                principals=subprocess.CompletedProcess([], -11),
                verify=subprocess.CompletedProcess([], 0),
                signature_ready=True,
                signature_armor=True,
            ),
            r"interrupted \(owner lookup\)",
        ),
        (
            SshEvidence(
                sign=subprocess.CompletedProcess([], 0),
                principals=None,
                verify=subprocess.CompletedProcess([], 0),
                signature_ready=True,
                signature_armor=True,
            ),
            r"timeout \(owner lookup\)",
        ),
        (
            SshEvidence(
                sign=subprocess.CompletedProcess([], 0),
                principals=subprocess.CompletedProcess([], 0, stdout=b"other\n"),
                verify=subprocess.CompletedProcess([], 0),
                signature_ready=True,
                signature_armor=True,
            ),
            "wrong owner",
        ),
        (
            SshEvidence(
                sign=subprocess.CompletedProcess([], 0),
                principals=subprocess.CompletedProcess([], 0, stdout=b"owner\nextra\n"),
                verify=subprocess.CompletedProcess([], 0),
                signature_ready=True,
                signature_armor=True,
            ),
            "wrong owner",
        ),
        (
            SshEvidence(
                sign=subprocess.CompletedProcess([], 0),
                principals=subprocess.CompletedProcess([], 0, stdout=b""),
                verify=subprocess.CompletedProcess([], 0),
                signature_ready=True,
                signature_armor=True,
            ),
            "wrong owner",
        ),
        (
            SshEvidence(
                sign=subprocess.CompletedProcess([], 0),
                principals=subprocess.CompletedProcess([], 0, stdout=b"owner\n"),
                verify=None,
                signature_ready=True,
                signature_armor=True,
            ),
            r"timeout \(verify signature\)",
        ),
        (
            SshEvidence(
                sign=subprocess.CompletedProcess([], 0),
                principals=subprocess.CompletedProcess([], 0, stdout=b"owner\n"),
                verify=subprocess.CompletedProcess([], 1),
                signature_ready=True,
                signature_armor=True,
            ),
            "verify signature",
        ),
        (
            SshEvidence(
                sign=subprocess.CompletedProcess([], 0),
                principals=subprocess.CompletedProcess([], 0, stdout=b"owner\n"),
                verify=subprocess.CompletedProcess([], -9),
                signature_ready=True,
                signature_armor=True,
            ),
            r"interrupted \(verify signature\)",
        ),
    ],
)
def test_ssh_capability_fails_closed_on_every_incomplete_or_wrong_step(evidence, expected):
    with pytest.raises(pytest.fail.Exception, match="disposable Git SSH capability failed: " + expected):
        require_ssh_capability(evidence)


def test_ssh_capability_accepts_complete_verified_owner_and_enforces_bounds():
    require_ssh_capability(
        SshEvidence(
            sign=subprocess.CompletedProcess([], 0),
            principals=subprocess.CompletedProcess([], 0, stdout=b"owner\n"),
            verify=subprocess.CompletedProcess([], 0, stdout=b'Good "git" signature for owner\n'),
            signature_ready=True,
            signature_armor=True,
        )
    )
    require_product_owner_verification(subprocess.CompletedProcess([], 0, stdout=b"G\nowner\n"))
    for bad_product, expected_msg in (
        (None, r"timeout \(verify commit\)"),
        (subprocess.CompletedProcess([], 1, stdout=b"G\nowner\n"), "verify commit"),
        (subprocess.CompletedProcess([], 0, stdout=b"U\nowner\n"), "product owner verification"),
        (subprocess.CompletedProcess([], 0, stdout=b"B\nowner\n"), "product owner verification"),
        (subprocess.CompletedProcess([], 0, stdout=b"G\nother\n"), "product owner verification"),
        (subprocess.CompletedProcess([], 0, stdout=b"G\nowner\nextra\n"), "product owner verification"),
    ):
        with pytest.raises(pytest.fail.Exception, match="disposable Git SSH capability failed: " + expected_msg):
            require_product_owner_verification(bad_product)
    oversize = SshEvidence(
        sign=subprocess.CompletedProcess([], 0, stdout=b"x" * (MAX_FRAME + 1)),
        signature_ready=True,
        signature_armor=True,
    )
    with pytest.raises(pytest.fail.Exception, match="exceeds the test budget"):
        require_ssh_capability(oversize)


@pytest.mark.parametrize("path_kind", ["missing", "relative", "inside-control"])
def test_signing_lookup_refuses_unsuitable_tool_locations(tmp_path, checkout_runtime, path_kind):
    root = tmp_path.resolve() / "control"
    root.mkdir()
    bin_dir = root / "bin"
    bin_dir.mkdir()
    suffix = ".exe" if os.name == "nt" else ""
    for name in ("git", "ssh-keygen"):
        program = bin_dir / (name + suffix)
        program.touch()
        if os.name != "nt":
            program.chmod(0o700)
    path = {
        "missing": str(tmp_path.resolve() / "missing"),
        "relative": "bin",
        "inside-control": str(bin_dir),
    }[path_kind]
    environment = {**host_environment(), "PATH": path}
    program = (
        "import json, os; from aegis_core.pathlookup import which; "
        "print(json.dumps([which(name, outside=os.getcwd()) for name in ('git', 'ssh-keygen')]))"
    )
    result = capture_command(
        [checkout_runtime.command, "-I", "-c", program],
        cwd=root,
        env=environment,
        timeout=15,
    )
    assert result.returncode == 0, "isolated executable lookup failed"
    assert read_json(result.stdout) == [None, None]
    with pytest.raises(pytest.skip.Exception, match="git or ssh-keygen missing"):
        signing_tools(root, environment)
    with pytest.raises(pytest.fail.Exception, match="git or ssh-keygen missing"):
        signing_tools(root, environment, release=True)


def test_git_ssh_probe_and_approval_ignore_ambient_signer(manager_root, checkout_runtime):
    ambient = manager_root / "ambient-home"
    ambient.mkdir()
    ambient_git = ambient / ".gitconfig"
    ambient_git.write_text('[gpg "ssh"]\n\tprogram = unavailable-signing-program\n', encoding="ascii")
    ambient_env = signing_environment(ambient / "unrelated-home", host_environment())
    ambient_env.update(HOME=str(ambient), USERPROFILE=str(ambient), GIT_CONFIG_GLOBAL=str(ambient_git))
    environment = signing_environment(manager_root / "disposable-home", ambient_env)
    tools = signing_tools(manager_root, environment)
    control = manager_root / "control"
    control.mkdir()
    tools.git_text(control, "init", "-q")
    inherited = run_tool(tools.git, ("config", "--get", "gpg.ssh.program"), control, ambient_env)
    assert inherited.returncode == 0 and inherited.stdout.strip() == b"unavailable-signing-program"
    probe_git_ssh(tools, control, checkout_runtime)
    assert tools.git_result(control, "config", "--get", "gpg.ssh.program").returncode == 1
    signing_result(tools.sign(control, "owner approval control"), "sign owner approval")
