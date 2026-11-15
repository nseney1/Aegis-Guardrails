"""Owner policy and process-bound queue grants; no environment enrolls a caller.

Deployment requires child sandboxes to exclude the account authority directory.
Same-UID unrestricted execution is outside this configuration-bound authority.
"""
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time
import uuid

from aegis_core import primitives, storage, storage_confined, team_queue
from aegis_core.workspace.layout import UserLayout

MAX_BYTES = 65536
MAX_DEPTH = 12
MAX_WORKSPACE = 4096
MAX_LANES = 64
MAX_CAPABILITIES = team_queue.MAX_FIELDS
# A JSON escape can use six bytes for each character of the longest field.
MAX_TOKEN = 6 * MAX_WORKSPACE
# Quotes, commas and containers: root/session overhead plus each lane's policy.
MAX_NODES = 64 + MAX_LANES * (2 * MAX_CAPABILITIES + 16)
LOCK_TIMEOUT = 5.0
_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", re.ASCII)
_NEXT = {
    "invalid_arguments": "Use only id, expect and lane from the queue list and owner policy.",
    "role_missing": "Ask the owner to install the registration and restart the queue connection.",
    "role_invalid": "Ask the owner to repair the authority records and restart the queue connection.",
    "role_foreign": "Restart through the owner registration for this process and workspace.",
    "role_stale": "Ask the owner to restart the queue connection with a fresh session record.",
    "role_forbidden": "Ask the owner to review the role and lane policy; caller fields cannot grant authority.",
    "role_lock_timeout": "Wait for the authority writer, list the queue and retry the current revision.",
    "role_io_unavailable": "Ask the owner to inspect authority storage and restart the queue connection.",
    "unsupported_platform": "Use Linux with descriptor-relative no-follow operations.",
    "queue_io_unavailable": "Check the trusted workspace and queue, then list before retrying.",
}


class RoleRefusal(ValueError):
    """Only a fixed documented code crosses the authority boundary."""

    def __init__(self, reason):
        self.reason = reason if reason in _NEXT else "role_io_unavailable"
        super().__init__(self.reason)

    @property
    def next_action(self):
        return _NEXT[self.reason]


# Launch recovery. Claim text in _NEXT stays on the claim envelope.
_LAUNCH = {
    "invalid_arguments": "Launch with exactly one registration id.",
    "role_missing": "Ask the owner to install the registration and restart the queue connection.",
    "role_invalid": "Ask the owner to repair the authority records and restart the queue connection.",
    "role_stale": "Retry the launch.",
    "role_lock_timeout": "Wait for the authority writer, then restart the queue connection.",
    "role_io_unavailable": "Ask the owner to inspect authority storage and restart the queue connection.",
    "unsupported_platform": "Use Linux with descriptor-relative no-follow operations.",
}


def launch_advice(reason):
    """One fixed sentence for a refusal raised while issuing the session."""
    if reason not in _LAUNCH:
        reason = "role_io_unavailable"
    return _LAUNCH[reason]


def refusal(reason):
    reason = reason if reason in _NEXT else "role_io_unavailable"
    value = primitives.envelope("aegis team queue claim", {}, schema="aegis.team.queue.claim/v1")
    value.update(refused=True, status="refused", reason=reason, error=reason,
                 next_action=_NEXT[reason], exit_code=2 if reason == "invalid_arguments" else 1)
    return value


def require(condition, reason="role_invalid"):
    if not condition:
        raise RoleRefusal(reason)


def identifier(value):
    return type(value) is str and 1 <= len(value) <= 64 and _KEY.fullmatch(value) is not None


def claim_argument_refusal(arguments):
    if (type(arguments) is not dict or len(arguments) != 3 or
            arguments.keys() != {"id", "expect", "lane"}):
        return refusal("invalid_arguments")
    revision, lane = arguments["expect"], arguments["lane"]
    if (not team_queue._key(arguments["id"]) or type(revision) is not str or len(revision) != 64 or
            team_queue._REVISION.fullmatch(revision) is None or not team_queue._lane(lane)):
        return refusal("invalid_arguments")
    return None


def supported():
    return sys.platform.startswith("linux") and storage_confined.descriptor_supported()


def account_home():
    import pwd

    return Path(pwd.getpwuid(os.geteuid()).pw_dir)


def _identity(info):
    return info.st_dev, info.st_ino


def _generation(info):
    return (*_identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode, info.st_uid)


def _owned_directory(info):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022)


@contextmanager
def authority():
    """Anchor every directory through the shared confined opener and hold the lock."""
    try:
        require(supported(), "unsupported_platform")
        home = account_home()
        require(home.is_absolute() and ".." not in home.parts and len(str(home)) <= 4096)
        root = UserLayout(home).aegis_dir / "mcp-queue"
        chain = []
        with ExitStack() as stack:
            for count in range(1, len(root.parts) + 1):
                directory = Path(*root.parts[:count])
                handle = stack.enter_context(storage_confined.confined_file(directory, (".probe",)))
                info = handle.parent_stat()
                # The account database supplies the trusted home anchor. System
                # ancestors may have namespace-mapped owners; pin their identity,
                # and enforce owner/modes from home down to authority storage.
                if count >= len(home.parts):
                    _owned_directory(info)
                chain.append(_identity(info))
            stack.enter_context(storage.file_lock(root / "authority.lock", LOCK_TIMEOUT, dir_fd=handle._parent))
            yield root, tuple(chain)
    except RoleRefusal:
        raise
    except storage.LockTimeoutError:
        raise RoleRefusal("role_lock_timeout") from None
    except FileNotFoundError:
        raise RoleRefusal("role_missing") from None
    except storage_confined.ConfinedFileError as exc:
        reason = {"missing": "role_missing", "unsafe": "role_invalid", "too_large": "role_invalid",
                  "invalid_path": "role_invalid", "unsupported": "unsupported_platform"}.get(exc.reason, "role_io_unavailable")
        raise RoleRefusal(reason) from None
    except (OSError, ValueError, RuntimeError, KeyError, OverflowError):
        raise RoleRefusal("role_io_unavailable") from None


def _prescan(raw):
    require(type(raw) is bytes and len(raw) <= MAX_BYTES)
    depth = nodes = token = 0
    quoted = escaped = False
    for char in raw:
        if quoted:
            if char == 34 and not escaped:
                quoted, token = False, 0
                continue
            token += 1
            require(token <= MAX_TOKEN)
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
        elif char == 34:
            quoted, token = True, 0
            nodes += 1
        elif char in (91, 123):
            token = 0
            depth += 1
            nodes += 1
            require(depth <= MAX_DEPTH)
        elif char in (93, 125):
            token = 0
            depth -= 1
            require(depth >= 0)
        elif char == 44:
            token = 0
            nodes += 1
        elif char not in (9, 10, 13, 32, 58):
            token += 1
            # All schema numbers fit in 20 decimal digits; booleans/null are shorter.
            require(token <= 64)
        else:
            token = 0
        require(nodes <= MAX_NODES)
    require(depth == 0 and not quoted)


def _json(raw):
    _prescan(raw)
    try:
        return primitives.strict_loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        raise RoleRefusal("role_invalid") from None


def _read(root, parts):
    with storage_confined.confined_file(root, parts) as handle:
        _owned_directory(handle.parent_stat())
        before = os.stat(handle._name, dir_fd=handle._parent, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
                not before.st_mode & 0o077 and before.st_nlink == 1 and before.st_size <= MAX_BYTES)
        raw = handle.read_bytes(MAX_BYTES)
        after = os.stat(handle._name, dir_fd=handle._parent, follow_symlinks=False)
        require(_generation(before) == _generation(after), "role_stale")
        return _json(raw), (_generation(after), hashlib.sha256(raw).hexdigest())


def _line(value, limit=128):
    return (type(value) is str and 1 <= len(value) <= limit and
            all(32 <= ord(char) < 127 for char in value))


def _fsencode(value):
    return os.fsencode(value)


def _workspace_path(value):
    # Bound the spelling before encoding or parsing. POSIX form is intentional:
    # this connection runs only on Linux, and the same check is what Windows CI executes.
    if type(value) is not str or not 1 <= len(value) <= MAX_WORKSPACE:
        return False
    for char in value:
        code = ord(char)
        if code <= 31 or code == 127 or 128 <= code <= 159 or 0xD800 <= code <= 0xDFFF:
            return False
    try:
        encoded = _fsencode(value)
    except UnicodeError:
        return False
    if type(encoded) is not bytes or len(encoded) > MAX_WORKSPACE:
        return False
    try:
        path = PurePosixPath(value)
    except ValueError:
        return False
    # Same predicate the core queue uses, on the POSIX form. Repeated separators
    # collapse here; a backslash or colon can still hide `..`, and the separator
    # cap still applies. A core rejection is role_invalid before a session exists.
    spelled = PurePosixPath("/", *path.parts[1:]).as_posix()
    return path.is_absolute() and ".." not in path.parts and team_queue.valid_workspace_spelling(spelled)


def _policy(value, registration):
    keys = {"schema", "registration_id", "endpoint", "role", "workspace", "lanes", "ttl_s", "session_ttl_s"}
    require(type(value) is dict and value.keys() == keys)
    require(value["schema"] == "aegis.mcp.queue-registration/v1" and value["registration_id"] == registration)
    require(_line(value["endpoint"]) and identifier(value["role"]))
    require(_workspace_path(value["workspace"]))
    for key in ("ttl_s", "session_ttl_s"):
        require(type(value[key]) is int and 1 <= value[key] <= 86400)
    lanes = value["lanes"]
    require(type(lanes) is dict and 1 <= len(lanes) <= MAX_LANES)
    for lane, options in lanes.items():
        require(team_queue._lane(lane))
        require(type(options) is dict and options.keys() == {"capabilities", "branch"})
        capabilities, branch = options["capabilities"], options["branch"]
        require(type(branch) is str)
        try:
            team_queue._strings(capabilities)
            team_queue._branch_name(branch)
        except team_queue.QueueRefusal:
            raise RoleRefusal("role_invalid") from None
    return value


def process_identity():
    """Read only fixed OS-owned proc records, through descriptor confinement."""
    with storage_confined.confined_file("/proc", ("sys", "kernel", "random", "boot_id")) as handle:
        boot = handle.read_bytes(128).decode("ascii").strip()
    # /proc/self is a kernel symlink; use our numeric PID, never follow that link.
    with storage_confined.confined_file("/proc", (str(os.getpid()), "stat")) as handle:
        raw = handle.read_bytes(4096).decode("ascii")
    require(re.fullmatch(r"[0-9a-f-]{36}", boot) is not None)
    fields = raw[raw.rfind(")") + 2:].split()
    require(len(fields) >= 20 and fields[19].isdigit())
    return {"boot_id": boot, "pid": os.getpid(), "start_ticks": int(fields[19])}


def _session_parts(process):
    return ("sessions", "{boot_id}-{pid}-{start_ticks}.json".format(**process))


def _workspace_identity(workspace):
    path = Path(workspace)
    with storage_confined.confined_file(path, (".identity",)) as handle:
        # The shared descriptor walk validates the original components without
        # following links. Path removes dot/repeated/trailing separators; Linux
        # also treats the POSIX double-slash anchor as the same filesystem root.
        canonical = str(Path("/", *path.parts[1:]))
        return canonical, _identity(handle.parent_stat())


def issue(registration):
    """Owner launch only: create one process-specific record from existing policy."""
    require(identifier(registration), "invalid_arguments")
    with authority() as (root, chain):
        policy, fingerprint = _read(root, ("registrations", registration + ".json"))
        policy = _policy(policy, registration)
        _workspace_identity(policy["workspace"])
        process = process_identity()
        now = int(time.time())
        require(0 <= now <= 4102444800)
        record = {"schema": "aegis.mcp.queue-role/v1", "registration_id": registration,
                  "registration_sha256": fingerprint[1], "process": process, "mcp_session": uuid.uuid4().hex,
                  "created_at": now, "expires_at": now + policy["session_ttl_s"]}
        raw = json.dumps(record, separators=(",", ":")).encode("utf-8")
        require(len(raw) <= MAX_BYTES)
        with storage_confined.confined_file(root, _session_parts(process), create_parents=True) as handle:
            _owned_directory(handle.parent_stat())
            handle.publish_bytes(raw)


def _record(value, registration, digest, process, ttl):
    keys = {"schema", "registration_id", "registration_sha256", "process", "mcp_session", "created_at", "expires_at"}
    require(type(value) is dict and value.keys() == keys)
    require(value["schema"] == "aegis.mcp.queue-role/v1")
    require(value["registration_id"] == registration and value["registration_sha256"] == digest and
            type(value["process"]) is dict and value["process"].keys() == process.keys(), "role_foreign")
    require(all(type(value["process"][k]) is type(v) and value["process"][k] == v for k, v in process.items()), "role_foreign")
    require(type(value["mcp_session"]) is str and re.fullmatch(r"[0-9a-f]{32}", value["mcp_session"]) is not None)
    created, expires = value["created_at"], value["expires_at"]
    require(type(created) is int and type(expires) is int and 0 <= created <= 4102444800 and expires == created + ttl)
    require(created <= time.time() < expires, "role_stale")
    return value


def bind(registration):
    require(identifier(registration), "invalid_arguments")
    with authority() as (root, chain):
        policy, policy_pin = _read(root, ("registrations", registration + ".json"))
        policy = _policy(policy, registration)
        workspace_pin = _workspace_identity(policy["workspace"])
        policy["workspace"] = workspace_pin[0]
        process = process_identity()
        record, record_pin = _read(root, _session_parts(process))
        record = _record(record, registration, policy_pin[1], process, policy["session_ttl_s"])
        return Grant(registration, policy, process, record, chain, policy_pin, record_pin, workspace_pin)


@dataclass
class Grant:
    registration: str
    policy: dict
    process: dict
    record: dict
    chain: tuple
    policy_pin: tuple
    record_pin: tuple
    workspace_pin: tuple
    stale: bool = False

    @property
    def session(self):
        return self.record["mcp_session"]

    @property
    def workspace(self):
        return self.workspace_pin[0]

    def invalidate(self):
        self.stale = True

    def _check(self, root, chain, session):
        require(not self.stale and session == self.session and chain == self.chain, "role_stale")
        policy, policy_pin = _read(root, ("registrations", self.registration + ".json"))
        record, record_pin = _read(root, _session_parts(self.process))
        require(policy_pin == self.policy_pin and record_pin == self.record_pin, "role_stale")
        require(process_identity() == self.process and int(time.time()) < self.record["expires_at"], "role_stale")
        require(_workspace_identity(self.workspace) == self.workspace_pin, "role_stale")

    def _mutate(self, root, chain, arguments, session):
        from aegis_core import team_queue

        try:
            # The queue service's lock is reentrant. Acquire it before the final
            # authority/expiry check, retaining authority -> queue lock order.
            with storage.locked(self.workspace, timeout=5.0):
                self._check(root, chain, session)
                lane = self.policy["lanes"][arguments["lane"]]
                return team_queue.claim(self.workspace, arguments["id"], expect=arguments["expect"],
                                        lane=arguments["lane"], capabilities=lane["capabilities"],
                                        branch=lane["branch"], ttl_s=self.policy["ttl_s"],
                                        caller="mcp-queue:" + self.session)
        except storage.LockTimeoutError:
            return team_queue.refusal("queue_lock_timeout", verb="claim")

    def claim(self, arguments, session):
        """Revalidate the startup snapshot under authority -> queue lock ordering."""
        from aegis_core import team_queue

        invalid = claim_argument_refusal(arguments)
        if invalid is not None:
            return invalid
        try:
            require(not self.stale, "role_stale")
            with authority() as (root, chain):
                try:
                    self._check(root, chain, session)
                except (RoleRefusal, storage_confined.ConfinedFileError):
                    self.stale = True
                    raise RoleRefusal("role_stale") from None
                require(self.policy["role"] == "orchestrator" and arguments["lane"] in self.policy["lanes"], "role_forbidden")
                try:
                    result = self._mutate(root, chain, arguments, session)
                except RoleRefusal:
                    self.stale = True
                    raise RoleRefusal("role_stale") from None
                except (OSError, ValueError, RuntimeError):
                    return refusal("queue_io_unavailable")
                if result.get("refused"):
                    result["error"] = result["reason"]
                return result
        except RoleRefusal as exc:
            if exc.reason in ("role_missing", "role_invalid", "role_foreign"):
                self.stale = True
                return refusal("role_stale")
            return refusal(exc.reason)

