"""Fake-host conformance through the shipped Teams commands and host-plan API.

Model children and their writable files are untrusted. The owner UID is
trusted. The fakes record process entry and supply fixture observations.
"""

from collections import Counter
from contextlib import contextmanager
import errno
import hashlib
import importlib
from inspect import getsource
import json
import os
from pathlib import Path
from shlex import quote
import shutil
import struct
import subprocess
import sys
import tempfile

import pytest

from aegis_cli.cli import main
from aegis_core import team_host_registry, team_hosts, team_profile, team_queue
from aegis_core.hosts import all_hosts
from aegis_mcp import schemas
from aegis_mcp.tools import execute_tool


PRESETS = ("solo", "pair", "mixed")
PROFILE_HOSTS = tuple(team_profile.PRESET_DATA["hosts"])
TEAM_HOSTS = team_host_registry.TEAM_HOSTS
ROOT_MATRIX_HOSTS = (*TEAM_HOSTS, "grok-cli", "antigravity")
REPOSITORIES = ("aegis-policy", "minimal")
SOURCE = Path(__file__).resolve().parents[2]
THIS_TEST = Path(__file__).resolve().relative_to(SOURCE).as_posix()

CONFIG_ACTION = ("Correct the indicated file or command-line layer, then retry. Run aegis team config presets "
                 "--json for preset and host choices; repository policy changes need aegis approve before merge.")
UNSUPPORTED_PROFILE = "unsupported platform: anchored profile operations unavailable"
UNKNOWN_USAGE = "unknown: usage adapter unavailable or invalid snapshot"
REPAIR_USAGE = "Configure or repair this host kind's usage adapter; capacity advice alone does not block work."
FAKE_FAILURE = "token=fixture-private-usage\n\x1b[31m"
NATIVE_BINDING_MODULES = ("ctypes", "_ctypes", "cffi", "_cffi_backend")
AEGIS_POLICY = {
    "landing": {"target_branch": "develop"},
    "gates": [{"name": "contract", "runner": "local", "selector": "list",
               "tests": ["tests/contract/test_module_size.py", THIS_TEST], "must_pass": True}],
}
MINIMAL_POLICY = {"landing": {"target_branch": "delivery/trunk"}, "gates": []}
CHECKOUT_BRANCH = "working/seed"


def cli(root, capsys, *words):
    code = main(["team", *words, "--workspace", str(root), "--json"])
    captured = capsys.readouterr()
    assert captured.err == ""
    return code, json.loads(captured.out)


def refusal(result, code, schema, reason, next_action):
    exit_code, payload = result
    assert (exit_code, payload["schema"], payload["status"], payload["reason"], payload["next_action"]) == (
        code, schema, "refused", reason, next_action
    )


def same_snapshot(cli_payload, tool, arguments):
    from aegis_core.pathlookup_gitcache import bound_ordinary_root

    # The server binds ordinary Git lookup before dispatch to this adapter.
    with bound_ordinary_root(arguments["workspace"]):
        mcp_payload = execute_tool(tool, arguments)
    # Each frontend captures its own observation time.
    assert cli_payload["checked_at"] and mcp_payload["checked_at"]
    assert {k: v for k, v in cli_payload.items() if k != "checked_at"} == {
        k: v for k, v in mcp_payload.items() if k != "checked_at"
    }


@pytest.fixture
def isolated(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    # The suite's autouse hermetic environment fixture restores these values.
    os.environ.update(HOME=str(home), USERPROFILE=str(home))
    os.environ.pop("AEGIS_WORKSPACE", None)
    return tmp_path.resolve()


def launch_event_policy():
    # CPython 3.9–3.13. The value identifies the executable argument,
    # or None when the event must be refused without inspecting its arguments.
    return {
        "_winapi.CreateProcess": 0,
        "os.exec": 0,
        "os.fork": None,
        "os.forkpty": None,
        "os.posix_spawn": 0,
        "os.spawn": 1,
        "os.startfile": None,
        "os.startfile/2": None,
        "os.system": None,
        "pty.spawn": None,
        "subprocess.Popen": 0,
        "ctypes.PyObj_FromPtr": None,
        "ctypes.addressof": None,
        "ctypes.call_function": None,
        "ctypes.cdata": None,
        "ctypes.cdata/buffer": None,
        "ctypes.create_string_buffer": None,
        "ctypes.create_unicode_buffer": None,
        "ctypes.dlopen": None,
        "ctypes.dlsym": None,
        "ctypes.dlsym/handle": None,
        "ctypes.get_errno": None,
        "ctypes.get_last_error": None,
        "ctypes.set_errno": None,
        "ctypes.set_exception": None,
        "ctypes.set_last_error": None,
        "ctypes.string_at": None,
        "ctypes.wstring_at": None,
    }


def guard_cffi_imports(record, inspect_loaded=()):
    from contextvars import ContextVar
    from importlib.util import find_spec
    import sys

    probing = ContextVar("conformance_ffi_probe", default=None)

    class NotCached(Exception):
        pass

    class Guard:
        def find_spec(self, fullname, path=None, target=None):
            if fullname == probing.get():
                raise NotCached
            record("import", (fullname,))

    def cached(name):
        token = probing.set(name)
        try:
            find_spec(name)
        except NotCached:
            return False
        except ValueError:
            pass
        finally:
            probing.reset(token)
        return True

    guard = Guard()
    sys.meta_path.insert(0, guard)
    try:
        # A cached module would bypass the finder. Probe without loading one.
        for name in ("cffi", "_cffi_backend"):
            if cached(name):
                record("import", (name,))
        yield tuple(name for name in inspect_loaded if cached(name))
    finally:
        sys.meta_path.remove(guard)


def launch_recorder(directory, trace, origin):
    """Create the hook without importing libraries before it is installed."""
    events = launch_event_policy()
    applications = {}

    def prepare():
        from pathlib import Path
        import sys

        sealed = Path(directory).resolve(strict=True)
        support = {Path(sys.executable).resolve(strict=True)}
        for name in ("git", "ps"):
            link = sealed / name
            if link.is_symlink():
                support.add(link.resolve(strict=True))
        applications.update(sealed=sealed, support=support)

    def executable(event, args, position, sealed):
        import os
        from pathlib import Path
        import shutil

        if position >= len(args):
            return None
        raw = args[position]
        if not isinstance(raw, (str, bytes, os.PathLike)):
            return None
        raw = os.fspath(raw)
        if not raw or len(raw) > 32768:
            return None
        name = os.fsdecode(raw)
        if "\x00" in name:
            return None
        path = Path(name)
        if path.is_absolute():
            return path
        # The os.exec and os.posix_spawn audit events also represent their
        # PATH-searching variants. An ambiguous relative spelling is refused.
        if event != "subprocess.Popen" or os.name != "posix" or len(args) != 4:
            return None
        cwd, env = args[2:]
        if os.path.dirname(name):
            working = Path.cwd()
            if cwd is not None:
                working = working / os.fsdecode(cwd)
            return working / path
        environment = os.environ if env is None else env
        if environment.get("PATH") != str(sealed):
            return None
        found = shutil.which(name, path=str(sealed))
        return Path(found) if found else None

    def record(event, args):
        approved = None
        if event == "import":
            if not args or not isinstance(args[0], str):
                return
            name = args[0]
            if not (name in ("cffi", "_cffi_backend") or name.startswith(("cffi.", "_cffi_backend."))):
                return
            reason = "foreign function access: import"
        elif event not in events:
            return
        elif event.startswith("ctypes."):
            reason = f"foreign function access: {event}"
        elif events[event] is None:
            reason = f"process launch without an executable: {event}"
        else:
            reason = "executable outside conformance fixture"
            if applications:
                sealed = applications["sealed"]
                path = executable(event, args, events[event], sealed)
                if path is not None:
                    try:
                        target = path.resolve(strict=True)
                        inside = path.is_relative_to(sealed) and target.is_relative_to(sealed)
                        if target in applications["support"] or inside:
                            approved = str(target)
                    except (OSError, ValueError, RuntimeError):
                        pass
        # Record approved fixture paths and the event name for refusals.
        # One unbuffered append keeps each row together.
        import json

        row = json.dumps([origin, event, approved]).encode("ascii") + b"\n"
        with open(trace, "ab", buffering=0) as stream:
            if stream.write(row) != len(row):
                raise OSError("incomplete conformance launch audit write")
        if approved is None:
            raise PermissionError(reason)

    return record, prepare


def run_audited_script(preloaded):
    import sys

    if preloaded:
        raise SystemExit(126)
    directory, trace, script, *arguments = sys.argv[1:]
    record, prepare = launch_recorder(directory, trace, "shim")
    sys.addaudithook(record)
    prepare()

    from contextlib import contextmanager
    import runpy

    sys.argv = [script, *arguments]
    with contextmanager(guard_cffi_imports)(record):
        runpy.run_path(script, run_name="__main__")


_launch_audit = {"active": None}


@pytest.fixture(scope="module")
def launch_audit_hook():
    def audit(event, args):
        active = _launch_audit["active"]
        if active is not None:
            active(event, args)

    with contextmanager(guard_cffi_imports)(audit, NATIVE_BINDING_MODULES) as preloaded:
        sys.addaudithook(audit)
    return preloaded


def elf_interpreter(executable):
    """Read the bounded PT_INTERP field of a trusted ELF support executable."""
    with executable.open("rb") as stream:
        size = os.fstat(stream.fileno()).st_size
        header = stream.read(64)
        if header[:4] != b"\x7fELF" or len(header) < 52 or header[5] not in (1, 2):
            raise ValueError("invalid ELF support executable")
        endian = "<" if header[5] == 1 else ">"
        if header[4] == 1:
            header_format = "HHIIIIIHHHHHH"
            program = struct.Struct(endian + "IIIIIIII")
            offset_field, size_field = 1, 4
        elif header[4] == 2:
            header_format = "HHIQQQIHHHHHH"
            program = struct.Struct(endian + "IIQQQQQQ")
            offset_field, size_field = 2, 5
        else:
            raise ValueError("invalid ELF class")
        fields = struct.unpack_from(endian + header_format, header, 16)
        offset, entry_size, entries = fields[4], fields[8], fields[9]
        if entry_size != program.size or entries > 128 or offset + entry_size * entries > size:
            raise ValueError("invalid ELF program table")
        stream.seek(offset)
        for _ in range(entries):
            entry = program.unpack(stream.read(entry_size))
            if entry[0] == 3:  # PT_INTERP
                start, length = entry[offset_field], entry[size_field]
                if not 2 <= length <= 4096 or start + length > size:
                    raise ValueError("invalid ELF interpreter field")
                stream.seek(start)
                filename = stream.read(length)
                if not filename.endswith(b"\0") or b"\0" in filename[:-1]:
                    raise ValueError("invalid ELF interpreter name")
                loader = Path(os.fsdecode(filename[:-1]))
                if not loader.is_absolute():
                    raise ValueError("relative ELF interpreter")
                return loader.resolve(strict=True)
    return None


def memfd_abi_table():
    """One (kind, machine, AUDIT_ARCH, memfd_create nr, execveat nr) table.

    linux/audit.h: AUDIT_ARCH_X86_64 is 0xC000003E, AUDIT_ARCH_AARCH64 is
    0xC00000B7, AUDIT_ARCH_RISCV64 is 0xC00000F3, AUDIT_ARCH_I386 is
    0x40000003 and AUDIT_ARCH_ARM is 0x40000028. x32 is not its own
    architecture: it keeps AUDIT_ARCH_X86_64 and sets bit 0x40000000 in the
    number (include/uapi/asm-generic/unistd.h). memfd_create is 319 for
    x86_64 and x32 (syscall_64.tbl), 356 for i386 (syscall_32.tbl), 279 for
    aarch64 and riscv64, and 385 for AArch32 (arch/arm/tools/syscall.tbl).
    AArch32 execveat is 387 in that same table. The seccomp program, the
    bootstrap probe and the descendant controls all read this tuple.
    """
    return (
        ("native", "x86_64", 0xC000003E, 319, 322),
        ("native", "aarch64", 0xC00000B7, 279, 281),
        ("native", "riscv64", 0xC00000F3, 279, 281),
        ("i386", "x86_64", 0x40000003, 356, 0),
        ("x32", "x86_64", 0xC000003E, 319 | 0x40000000, 0),
        ("aarch32", "aarch64", 0x40000028, 385, 387),
    )


def executable_memfd_flags():
    """Flag attempts for an executable memfd, in order.

    MFD_CLOEXEC|MFD_EXEC (Linux 6.3) is the executable memfd on kernels that
    understand the flag. An older kernel returns EINVAL and the caller retries
    with MFD_CLOEXEC alone, which is executable when memfd_noexec is unset.
    """
    return (0x11, 1)


def memfd_seccomp_words(machine):
    """Classic BPF words that refuse memfd_create for every ABI in the table.

    The first instruction loads ``seccomp_data.arch`` (the 32-bit word at
    offset 4). A syscall whose architecture is not the interpreter's native
    AUDIT_ARCH returns EPERM and is never compared by number. On x86_64 the
    x32 bit from the table is refused next, then the native memfd_create
    number. Every other native syscall, including Landlock and execveat of a
    named file, is allowed. The bootstrap probe uses the returned number.
    """
    native = None
    x32_nr = None
    for kind, host, arch, nr, _execveat in memfd_abi_table():
        if host != machine:
            continue
        if kind == "native":
            native = (arch, nr)
        elif kind == "x32":
            x32_nr = nr
    if native is None:
        raise ValueError("unsupported memfd syscall ABI")
    native_arch, memfd_nr = native
    x32_mask = 0
    if x32_nr is not None:
        x32_mask = (x32_nr ^ memfd_nr) & 0xFFFFFFFF
        if x32_mask == 0:
            raise ValueError("unsupported memfd syscall ABI")
    words = [(0x20, 0, 0, 4)]
    arch_at = len(words)
    words.append((0x15, 0, 0, native_arch))
    words.append((0x20, 0, 0, 0))
    x32_at = None
    if x32_mask:
        x32_at = len(words)
        words.append((0x45, 0, 0, x32_mask))
    memfd_at = len(words)
    words.append((0x15, 0, 0, memfd_nr))
    words.append((0x06, 0, 0, 0x7fff0000))
    deny_at = len(words)
    words.append((0x06, 0, 0, 0x00050001))

    def towards_deny(at):
        return deny_at - (at + 1)

    code, _jt, _jf, k = words[arch_at]
    words[arch_at] = (code, 0, towards_deny(arch_at), k)
    if x32_at is not None:
        code, _jt, _jf, k = words[x32_at]
        words[x32_at] = (code, towards_deny(x32_at), 0, k)
    code, _jt, _jf, k = words[memfd_at]
    words[memfd_at] = (code, towards_deny(memfd_at), 0, k)
    return tuple(words), memfd_nr


def landlock_bootstrap():
    """Install execute-only rules and replace this trusted process with the shim.

    Named files are limited by Landlock. Anonymous memfds live on a kernel
    tmpfs Landlock does not check, so this process also installs a seccomp
    filter that refuses ``memfd_create`` with EPERM for every ABI in
    ``memfd_abi_table`` (native number, the x32 bit on x86_64, and any
    non-native architecture as a whole). The filter is inherited by every
    descendant. A failed install or a probe that does not observe EPERM
    raises, and the caller turns that into the fixed boundary refusal before
    any receipt is published.
    """
    import os
    import sys

    receipt = int(sys.argv[1])
    try:
        import ctypes
        import errno
        import stat

        # These 64-bit Linux architectures share the Landlock syscall numbers.
        if os.uname().machine not in ("x86_64", "aarch64", "riscv64") or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise ValueError("unsupported Landlock syscall ABI")
        create_ruleset, add_rule, restrict_self = 444, 445, 446
        execute, version, path_beneath, no_new_privileges = 1, 1, 1, 38

        class Ruleset(ctypes.Structure):
            _fields_ = [("handled_access_fs", ctypes.c_uint64)]

        class PathRule(ctypes.Structure):
            _pack_ = 1
            _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]

        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
        libc.prctl.restype = ctypes.c_int

        def syscall(number, *arguments):
            result = libc.syscall(number, *arguments)
            if result < 0:
                raise OSError(ctypes.get_errno(), "Landlock syscall failed")
            return result

        def refuse_memfd_create(library):
            # Arch before nr: a foreign AUDIT_ARCH is refused as a whole, and
            # the x86_64 program also refuses every number with the x32 bit.
            # The words and the probed number come from memfd_abi_table.
            program_words, memfd_nr = memfd_seccomp_words(os.uname().machine)

            class SockFilter(ctypes.Structure):
                _fields_ = [
                    ("code", ctypes.c_uint16),
                    ("jt", ctypes.c_uint8),
                    ("jf", ctypes.c_uint8),
                    ("k", ctypes.c_uint32),
                ]

            class SockFprog(ctypes.Structure):
                _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(SockFilter))]

            if ctypes.sizeof(SockFilter) != 8 or ctypes.sizeof(SockFprog) != 16:
                raise ValueError("unsupported seccomp ABI")
            filters = (SockFilter * len(program_words))(
                *(SockFilter(*word) for word in program_words)
            )
            program = SockFprog(len(program_words), filters)
            if library.prctl(22, 2, ctypes.addressof(program), 0, 0) != 0:
                raise OSError(ctypes.get_errno(), "seccomp failed")
            # MFD_CLOEXEC only. EPERM is the proof the filter is installed;
            # EINVAL from MFD_EXEC would be ambiguous here.
            created = library.syscall(memfd_nr, ctypes.c_char_p(b"aegis"), 1)
            if created >= 0:
                try:
                    os.close(int(created))
                except OSError:
                    raise OSError(errno.EPERM, "memfd filter inactive") from None
                raise OSError(errno.EPERM, "memfd filter inactive")
            if ctypes.get_errno() != errno.EPERM:
                raise OSError(ctypes.get_errno(), "memfd filter inactive")

        count = int(sys.argv[2])
        if not 1 <= count <= 128 or len(sys.argv) <= count + 3:
            raise ValueError("invalid launch table")
        files = sys.argv[3:count + 3]
        argv = sys.argv[count + 3:]
        abi = syscall(create_ruleset, None, 0, version)
        if not 1 <= abi <= 0xffffffff:
            raise ValueError("invalid Landlock ABI")
        attr = Ruleset(execute)
        rules = syscall(create_ruleset, ctypes.byref(attr), ctypes.sizeof(attr), 0)
        try:
            for filename in files:
                fd = os.open(filename, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        raise ValueError("launch rule must name a file")
                    rule = PathRule(execute, fd)
                    syscall(add_rule, rules, path_beneath, ctypes.byref(rule), 0)
                finally:
                    os.close(fd)
            if libc.prctl(no_new_privileges, 1, 0, 0, 0) != 0:
                raise OSError(ctypes.get_errno(), "prctl failed")
            restricted = syscall(restrict_self, rules, 0)
            if restricted != 0:
                raise ValueError("missing Landlock confirmation")
            refuse_memfd_create(libc)
        finally:
            os.close(rules)
        if os.write(receipt, abi.to_bytes(4, "little") + b"\0") != 5:
            raise ValueError("missing Landlock confirmation")
    except (ImportError, OSError, ValueError):
        raise SystemExit("launch boundary unavailable")
    finally:
        os.close(receipt)
    try:
        os.execv(argv[0], argv)
    except OSError:
        raise SystemExit("launch boundary unavailable")


_SHELL_FREE_LAUNCHERS = {}


def _whitespace_free_launcher(interpreter):
    """Return a space-free symlink to ``interpreter`` for a Linux shebang."""
    cached = _SHELL_FREE_LAUNCHERS.get(interpreter)
    if cached and os.path.islink(cached):
        return cached
    root = None
    for candidate in (Path("/tmp"), Path("/var/tmp")):
        try:
            name = str(candidate)
            if candidate.is_dir() and os.access(candidate, os.W_OK | os.X_OK) and " " not in name and "\t" not in name:
                root = candidate
                break
        except OSError:
            continue
    if root is None:
        raise OSError(errno.ENOENT, "interpreter launcher unavailable")
    try:
        directory = Path(tempfile.mkdtemp(prefix="aegis-launch-", dir=str(root)))
        link = directory / "python"
        link.symlink_to(interpreter)
    except OSError:
        raise OSError(errno.ENOENT, "interpreter launcher unavailable") from None
    text = str(link)
    if " " in text or "\t" in text or len(text) > 120:
        raise OSError(errno.ENAMETOOLONG, "interpreter launcher unavailable")
    _SHELL_FREE_LAUNCHERS[interpreter] = text
    return text


def write_shell_free_fake(path, body, interpreter=None):
    """Write one executable fake without putting the interpreter path on the #! line.

    Linux splits a shebang on space and tab. The shebang names a whitespace-free
    alias of the interpreter file, which an execute rule for that file still
    allows after resolution. The alias only starts the preamble. The preamble
    execs the original interpreter with an explicit argv so a venv path such as
    '/tmp/ci env/bin/python' remains the fake's interpreter.
    """
    chosen = sys.executable if interpreter is None else interpreter
    chosen = os.fspath(chosen)
    if isinstance(chosen, bytes):
        chosen = os.fsdecode(chosen)
    if not isinstance(chosen, str) or not chosen or len(chosen) > 4096 or "\x00" in chosen:
        raise OSError(errno.EINVAL, "invalid interpreter path")
    chosen = os.path.abspath(chosen)
    if len(chosen) > 4096 or not os.path.isfile(chosen):
        raise OSError(errno.EINVAL, "invalid interpreter path")
    launcher = _whitespace_free_launcher(chosen)
    source = (
        f"#!{launcher} -I\n"
        "import os\n"
        "import sys\n"
        f"_interpreter = {chosen!r}\n"
        "_ready = '--aegis-shell-free-ready'\n"
        "if _ready not in sys.argv:\n"
        "    os.execv(_interpreter, [_interpreter, '-I', sys.argv[0], _ready, *sys.argv[1:]])\n"
        "sys.argv.remove(_ready)\n"
        + body
    )
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)
    return path


class FakeHosts:
    def __init__(self, root):
        self.path = root / "sealed-path"
        self.path.mkdir()
        self.log = root / "executed-hosts.log"
        self.launch_trace = root / "process-launches.jsonl"
        self.expected_refusals = []
        self.checked = 0
        self.kernel_abi = None
        self.support = {}
        self.programs = {binary for host in all_hosts() for binary in host.binaries}
        self.programs.update(row["cli"] for row in team_profile.PRESET_DATA["hosts"].values())
        for name in sorted(self.programs):
            self.install(name)

    def executable(self, name):
        return self.path / (name + (".cmd" if os.name == "nt" else ""))

    def install(self, name, command=None, mark=""):
        path = self.executable(name)
        if os.name == "nt":
            path.write_text(f'@echo %~f0>>"{self.log}"\n@exit /b 97\n', encoding="utf-8")
            return
        if sys.platform == "linux":
            body = "raise SystemExit(97)\n"
            if command:
                body = f"import os\nos.execv({command[0]!r}, {list(command)!r} + sys.argv[1:])\n"
            write_shell_free_fake(
                path,
                f"# {mark}\nimport sys\n"
                "try:\n"
                f"    with open({str(self.log)!r}, 'a', encoding='utf-8') as log:\n"
                "        log.write(sys.argv[0] + '\\n')\n"
                "except OSError:\n"
                "    raise SystemExit(98)\n"
                + body,
            )
        else:
            record = f"printf '%s\\n' \"$0\" >> {quote(str(self.log))} || exit 98\n"
            path.write_text("#!/bin/sh\n" + record + "exit 97\n", encoding="utf-8")
        path.chmod(0o755)

    def expect(self, *executables):
        calls = self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []
        actual = tuple(calls[self.checked:])
        expected = tuple(str(path) for path in executables)
        assert actual == expected, f"host execution: expected {expected}, observed {actual}"
        self.checked = len(calls)

    def legacy_options(self):
        if not all((self.path / name).is_file() for name in ("git", "ps")):
            pytest.skip("git and ps are required by the fake run harness")
        return {"PATH": str(self.path)}

    def run_script(self, script, *words, env=None, timeout=15, preload_ctypes=False):
        # Only the install-refusal control brings a preloaded native module.
        prelude = "import ctypes\n" if preload_ctypes else ""
        functions = (launch_event_policy, guard_cffi_imports, launch_recorder, run_audited_script)
        boot = prelude + "\n".join(map(getsource, functions))
        boot += "\nimport sys\n"
        boot += f"run_audited_script(any(name in sys.modules for name in {NATIVE_BINDING_MODULES!r}))\n"
        argv = [sys.executable, "-I", "-S", "-B", "-c", boot,
                str(self.path), str(self.launch_trace), str(script), *words]
        if sys.platform == "linux":
            return self.run_landlocked(argv, env, timeout)
        return subprocess.run(argv, executable=sys.executable, env=env, capture_output=True, text=True, timeout=timeout)

    def run_landlocked(self, argv, env, timeout):
        try:
            table = {"test interpreter": Path(sys.executable).resolve(strict=True), **self.support}
            for name, executable in tuple(table.items()):
                loader = elf_interpreter(executable)
                if loader is not None:
                    table[f"ELF interpreter for {name}"] = loader
            for name in sorted(self.programs | {"bwrap"}):
                table[f"fake {name}"] = self.executable(name)
            files = tuple(dict.fromkeys(map(str, table.values())))

            reader, writer = os.pipe()
            try:
                try:
                    boot = (
                        getsource(memfd_abi_table) + "\n"
                        + getsource(memfd_seccomp_words) + "\n"
                        + getsource(landlock_bootstrap) + "\nlandlock_bootstrap()\n"
                    )
                    command = [sys.executable, "-I", "-S", "-B", "-c", boot,
                               str(writer), str(len(files)), *files, *argv]
                    result = subprocess.run(command, executable=sys.executable, env=env, pass_fds=(writer,),
                                            capture_output=True, text=True, timeout=timeout)
                finally:
                    os.close(writer)
                os.set_blocking(reader, False)
                receipt = os.read(reader, 6)
            finally:
                os.close(reader)
        except (OSError, ValueError, struct.error):
            pytest.fail("launch boundary unavailable", pytrace=False)
        if len(receipt) != 5 or receipt[4] != 0:
            pytest.fail("launch boundary unavailable", pytrace=False)
        self.kernel_abi = int.from_bytes(receipt[:4], "little")
        if self.kernel_abi < 1 or result.stderr == "launch boundary unavailable\n":
            pytest.fail("launch boundary unavailable", pytrace=False)
        return result

    def launch_rows(self):
        if not self.launch_trace.exists():
            return []
        with self.launch_trace.open("rb") as stream:
            data = stream.read(1048577)
        assert len(data) <= 1048576, "conformance launch audit exceeded its fixture limit"
        return [json.loads(line) for line in data.splitlines()]

    def check_launches(self, record_property):
        rows = self.launch_rows()
        refused = [(origin, event) for origin, event, path in rows if path is None]
        assert refused == self.expected_refusals, f"unexpected executable refusals: {refused}"
        counts = Counter(origin for origin, _, path in rows if path is not None)
        record_property("launches_pytest", counts["pytest"])
        record_property("launches_shim", counts["shim"])
        record_property("launches_refused", len(refused))
        if sys.platform == "linux":
            record_property("launch_boundary", "kernel exec")
            record_property(
                "launch_boundary_scope",
                "Landlock named-file execve and execveat, plus seccomp refusal of anonymous "
                "executable file creation. Executable mappings and fork without exec are in-process.",
            )
            if self.kernel_abi is not None:
                record_property("landlock_abi", self.kernel_abi)
        else:
            record_property("launch_boundary", "audit-only")


@pytest.fixture(autouse=True)
def sealed_hosts(tmp_path, launch_audit_hook, record_property):
    from tests.conftest import symlink_or_skip

    hosts = FakeHosts(tmp_path)
    if os.name == "posix":
        for name in ("git", "ps"):
            executable = shutil.which(name)
            if executable:
                target = Path(executable).resolve(strict=True)
                symlink_or_skip(target, hosts.path / name)
                hosts.support[name] = target
        bwrap = hosts.path / "bwrap"
        if sys.platform == "linux":
            write_shell_free_fake(bwrap, "raise SystemExit(1)\n")
        else:
            bwrap.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            bwrap.chmod(0o755)
    # The suite's hermetic environment fixture restores PATH after the test.
    os.environ["PATH"] = str(hosts.path)
    for name in NATIVE_BINDING_MODULES:
        record_property(f"pytest_preloaded_{name}", int(name in launch_audit_hook))
    record, prepare = launch_recorder(hosts.path, hosts.launch_trace, "pytest")
    _launch_audit["active"] = record
    try:
        prepare()
        with contextmanager(guard_cffi_imports)(record):
            yield hosts
    finally:
        _launch_audit["active"] = None
    hosts.check_launches(record_property)
    hosts.expect()


@pytest.fixture(params=REPOSITORIES)
def repository(request, isolated):
    if not team_profile.descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    git = shutil.which("git")
    if git is None:
        pytest.skip("requires git to create an empty repository")
    root = isolated / "repository"
    root.mkdir()
    policy = AEGIS_POLICY if request.param == "aegis-policy" else MINIMAL_POLICY
    assert CHECKOUT_BRANCH != policy["landing"]["target_branch"]
    subprocess.run([git, "init", "-q", str(root)], check=True, timeout=15)
    subprocess.run([git, "-C", str(root), "symbolic-ref", "HEAD", "refs/heads/" + CHECKOUT_BRANCH],
                   check=True, timeout=15)
    return root, policy


@pytest.mark.parametrize("preset", PRESETS)
@pytest.mark.parametrize("kind", PROFILE_HOSTS)
def test_profile_and_capacity_conformance(repository, isolated, sealed_hosts, monkeypatch, capsys, preset, kind):
    root, policy = repository
    init_args = ("config", "init", "--preset", preset, "--host", kind)
    path = root.joinpath(*team_profile.REPO_PATH)
    if not team_profile.PRESET_DATA["hosts"][kind]["writer"]:
        for _ in range(2):
            refusal(cli(root, capsys, *init_args), 2, "aegis.team.config.init/v1",
                    "host kind is not qualified for a preset binding", CONFIG_ACTION)
            assert not path.exists()
        return

    code, initialized = cli(root, capsys, *init_args)
    assert (code, initialized["schema"], initialized["status"]) == (0, "aegis.team.config.init/v1", "done")
    configured = json.loads(path.read_text(encoding="utf-8"))
    settings = initialized["profile"]["model_settings"]
    assert settings["hosts"][settings["roles"]["writer"]["hosts"][0]]["kind"] == kind
    assert initialized["profile"]["policy"]["review"]["require_cross_family"] is (preset != "solo")
    configured["policy"] = policy
    model_settings = configured["model_settings"]
    capacity = {name: {"usage_source": "credits"} for name in settings["hosts"]}
    model_settings["capacity"] = capacity
    writer = settings["roles"]["writer"]["hosts"][0]
    if preset != "solo":
        pinned_role = "reviewer.security"
        pinned = settings["roles"][pinned_role]["hosts"][0]
        other_family = next(name for name, host in settings["hosts"].items()
                            if host["kind"] != settings["hosts"][pinned]["kind"])
        same_family = "security-spare"
        model_settings["hosts"][same_family] = dict(settings["hosts"][pinned])
        capacity[same_family] = {"usage_source": "credits"}
        capacity[pinned]["fallback"] = {"doc": [other_family], pinned_role: [other_family]}
        path.write_text(json.dumps(configured), encoding="utf-8")
        for _ in range(2):
            refusal(cli(root, capsys, "config", "show"), 1, "aegis.team.config.show/v1",
                    "pinned lens fallback changes family", CONFIG_ACTION)
        del capacity[pinned]["fallback"][pinned_role]
        model_settings.setdefault("roles", {})[pinned_role] = {
            **settings["roles"][pinned_role], "hosts": [pinned, same_family],
        }
    path.write_text(json.dumps(configured), encoding="utf-8")
    before = path.read_bytes()

    code, shown = cli(root, capsys, "config", "show")
    assert (code, shown["schema"], shown["status"]) == (0, "aegis.team.config.show/v1", "done")
    same_snapshot(shown, "aegis_team_config", {"workspace": str(root)})
    assert shown["profile"]["preset"] == preset
    assert shown["profile"]["policy"]["landing"]["target_branch"] == policy["landing"]["target_branch"]
    assert shown["profile"]["policy"]["gates"] == policy["gates"]
    assert shown["values"]["policy.gates"]["layer"] == "repo"

    settings = shown["profile"]["model_settings"]
    if preset != "solo":
        route = team_profile.plan(shown["profile"], pinned_role, start_host=pinned)
        assert route["pinned"] is True
        assert route["binding"] == route["admitted"] == [pinned, same_family]
        assert [entry["host"] for entry in route["entries"]] == [pinned, same_family]

    snapshots = {name: {"credits_left": 42} for name in settings["hosts"]}
    adapter = team_hosts.FakeUsageAdapter(snapshots)
    requested = []

    def usage_adapter(host_kind):
        requested.append(host_kind)
        return adapter

    monkeypatch.setattr(team_hosts, "usage_adapter", usage_adapter)
    code, doctor = cli(root, capsys, "doctor")
    assert (code, doctor["schema"], doctor["status"], doctor["healthy"]) == (
        0, "aegis.team.doctor/v1", "done", True
    )
    assert doctor["checks"] == {"profile": "complete", "cli": "PATH only", "login": "not checked",
                                "network": "not checked"}
    assert {row["kind"] for row in doctor["hosts"]} == {host["kind"] for host in settings["hosts"].values()}

    for verb in ("status", "usage"):
        requested.clear()
        adapter.calls.clear()
        code, result = cli(root, capsys, "hosts", verb)
        schema = "aegis.team.hosts." + verb + "/v1"
        assert (code, result["schema"], result["status"]) == (0, schema, "done")
        actual = {row["host"]: (row["host_kind"], row["usage"]) for row in result["hosts"]}
        assert actual == {name: (host["kind"], snapshots[name]) for name, host in settings["hosts"].items()}
        assert adapter.calls == [(name, "credits") for name in settings["hosts"]]
        assert requested == [settings["hosts"][name]["kind"] for name, _ in adapter.calls]

    check = ("hosts", "check", writer, "writer")
    for snapshot in (OSError(FAKE_FAILURE), OSError(FAKE_FAILURE), {"credits_left": 0}, {"credits_left": 42}):
        adapter.calls.clear()
        snapshots[writer] = snapshot
        code, checked = cli(root, capsys, *check)
        assert checked["schema"] == "aegis.team.hosts.check/v1"
        assert checked["selected_host"] == writer and adapter.calls == [(writer, "credits")]
        if isinstance(snapshot, OSError):
            assert (code, checked["decision"], checked["usage"]["usage_status"],
                    checked["reason"], checked["next_action"]) == (
                0, "go", "unknown", UNKNOWN_USAGE, REPAIR_USAGE
            )
            assert "fixture-private-usage" not in json.dumps(checked)
        elif snapshot["credits_left"]:
            assert (code, checked["decision"], checked["reason"], checked["next_action"]) == (
                0, "go", "credits available",
                "Start the job on " + writer + "; capacity advice grants no execution authority."
            )
        else:
            assert (code, checked["decision"], checked["reason"], checked["next_action"]) == (
                3, "hold", "credits exhausted; fallback chain exhausted or held",
                "Replenish this host's credits, then recheck."
            )

    if preset != "solo":
        check_capacity_routes(root, capsys, settings, adapter, requested, pinned, other_family, same_family)

    missing = team_profile.PRESET_DATA["hosts"][kind]["cli"]
    executable = sealed_hosts.executable(missing)
    removed = executable.rename(isolated / "removed-host-cli")
    try:
        refusal(cli(root, capsys, "doctor"), 1, "aegis.team.doctor/v1", "a declared host CLI is missing from PATH",
                "Install the missing declared CLI: " + missing + "; rerun aegis team doctor --json.")
    finally:
        removed.rename(executable)
    assert path.read_bytes() == before
    if policy["gates"]:
        # Doctor validates the declared gate against the runners in the actual
        # profile. A bad mapping must stop before even consulting a host.
        configured["policy"] = {**policy, "gates": [{**policy["gates"][0], "runner": "unknown-runner"}]}
        path.write_text(json.dumps(configured), encoding="utf-8")
        requested.clear()
        refusal(cli(root, capsys, "doctor"), 1, "aegis.team.doctor/v1",
                "gate references undeclared runner", CONFIG_ACTION)
        assert requested == []


def check_capacity_routes(root, capsys, settings, adapter, requested, primary, alternate, spare):
    adapter.snapshots[primary] = {"credits_left": 0}
    adapter.snapshots[alternate] = {"credits_left": 42}
    adapter.snapshots[spare] = {"credits_left": 42}
    adapter.calls.clear()
    requested.clear()
    code, healthy = cli(root, capsys, "hosts", "check", spare, "reviewer.security")
    assert code == 0, healthy
    assert (code, healthy["decision"], healthy["selected_host"], healthy["reason"]) == (
        0, "go", spare, "credits available",
    )
    assert adapter.calls == [(spare, "credits")] and requested == [settings["hosts"][spare]["kind"]]
    for kind, outcome, hosts in (
        ("doc", (4, "fallback:" + alternate, alternate, "credits exhausted; fallback credits available",
                 "Run aegis team hosts check " + alternate + " doc --json; use that declared host if admitted."),
         (primary, alternate)),
        ("reviewer.security", (3, "hold", primary, "credits exhausted; pinned role or lens cannot fall back",
                               "Replenish this host's credits, then recheck."), (primary,)),
    ):
        for _ in range(2):
            adapter.calls.clear()
            requested.clear()
            code, row = cli(root, capsys, "hosts", "check", primary, kind)
            assert (code, row["decision"], row["selected_host"], row["reason"], row["next_action"]) == outcome
            assert adapter.calls == [(alias, "credits") for alias in hosts]
            assert requested == [settings["hosts"][alias]["kind"] for alias in hosts]


def test_profile_refusals_match_cli_and_mcp(isolated, monkeypatch, capsys):
    path = isolated.joinpath(*team_profile.REPO_PATH)
    path.parent.mkdir(parents=True)
    path.write_bytes(b'{"version": 1, "preset": "solo", "preset": "pair"}')
    if team_profile.descriptor_supported():
        result = cli(isolated, capsys, "config", "show")
        refusal(result, 1, "aegis.team.config.show/v1", "duplicate key in profile JSON", CONFIG_ACTION)
        same_snapshot(result[1], "aegis_team_config", {"workspace": str(isolated)})

    monkeypatch.setattr(team_profile, "descriptor_supported", lambda: False)
    result = cli(isolated, capsys, "config", "show")
    refusal(result, 1, "aegis.team.config.show/v1", UNSUPPORTED_PROFILE, CONFIG_ACTION)
    same_snapshot(result[1], "aegis_team_config", {"workspace": str(isolated)})


def test_config_mcp_is_closed_and_read_only():
    tool = next(tool for tool in schemas.TOOL_DEFINITIONS if tool["name"] == "aegis_team_config")
    assert tool["inputSchema"] == {"type": "object", "properties": {}, "additionalProperties": False}
    assert tool["annotations"]["readOnlyHint"] is True
    payload = execute_tool("aegis_team_config", {"workspace": FAKE_FAILURE}, client_arguments=True)
    assert (payload["schema"], payload["status"], payload["reason"], payload["next_action"]) == (
        "aegis.team.config.show/v1", "refused", "aegis_team_config accepts no arguments",
        "Call aegis_team_config with an empty arguments object."
    )
    assert "fixture-private-usage" not in json.dumps(payload)


def test_queue_round_trip_and_stale_retry(repository, capsys):
    if not team_queue.descriptor_supported():
        pytest.skip("requires descriptor-relative nofollow operations")
    root, policy = repository
    has_queue_policy = policy is AEGIS_POLICY
    (root / ".aegis" / "rules").mkdir(parents=True)
    if has_queue_policy:
        (root / ".aegis" / "team.json").write_text(
            json.dumps({"v": 1, "lanes": {"writer": ["src/**"]}}), encoding="utf-8"
        )
    item = {"id": "ONE", "title": "Conformance work", "paths": ["src/**"], "capabilities": ["test"]}
    code, added = cli(root, capsys, "queue", "add", "--item", json.dumps(item))
    assert (code, added["schema"], added["refused"]) == (0, "aegis.team.queue.add/v1", False), added
    claim = ("queue", "claim", "ONE", "--expect", added["item"]["revision"],
             "--lane", "writer", "--capability", "test")
    expected_item = added["item"]
    if has_queue_policy:
        code, claimed = cli(root, capsys, *claim)
        assert code == 0 and claimed["refused"] is False, claimed
        expected_item = claimed["item"]
        assert expected_item["state"] == "claimed"
        reason = "stale_revision"
        action = "List the item again and decide whether to retry with its current revision."
    else:
        reason = "blocked"
        action = "Resolve the listed blockers, then list and retry the current revision."
    for _ in range(2):
        code, refused = cli(root, capsys, *claim)
        assert (code, refused["refused"], refused["reason"], refused["next_action"]) == (
            1, True, reason, action
        )
    code, listed = cli(root, capsys, "queue", "list")
    assert (code, listed["schema"]) == (0, "aegis.team.queue.list/v1")
    [item] = listed["items"]
    assert (item["id"], item["revision"], item["state"]) == ("ONE", expected_item["revision"], expected_item["state"])
    if not has_queue_policy:
        assert item["conditions_met"] is False and item["blockers"] == refused["blockers"]
    same_snapshot(listed, "aegis_team_queue", {"workspace": str(root)})


@pytest.mark.parametrize("root_host", ROOT_MATRIX_HOSTS)
@pytest.mark.parametrize("team_host", ROOT_MATRIX_HOSTS)
def test_root_and_team_hosts_bind_independently(root_host, team_host):
    from tools import hierarchy_hosts

    args = ("conformance", root_host, team_host, {}, "0" * 64)
    if root_host not in TEAM_HOSTS or team_host not in TEAM_HOSTS:
        field = "root" if root_host not in TEAM_HOSTS else "team"
        with pytest.raises(ValueError, match="^host plan " + field + " must be "):
            hierarchy_hosts.plan_record(*args)
        return
    plan = hierarchy_hosts.plan_record(*args)
    for role, declared in (("root", root_host), ("orchestrator", team_host)):
        endpoint = "conformance/" + role
        other = next(host for host in TEAM_HOSTS if host != declared)
        for _ in range(2):
            with pytest.raises(ValueError) as caught:
                hierarchy_hosts.require_binding(plan, endpoint, other, False)
            assert str(caught.value) == f"{endpoint} runs on {declared} in this run's host plan, not {other}"
        assert hierarchy_hosts.require_binding(plan, endpoint, declared, False) == {"boundary": "no write tools"}
    assert hierarchy_hosts.require_binding(None, "conformance/root", root_host, False) is None


@pytest.mark.parametrize("team_host,root_host", [
    (team, root) for team in ROOT_MATRIX_HOSTS for root in ROOT_MATRIX_HOSTS
    if (team in TEAM_HOSTS) != (root in TEAM_HOSTS)
])
def test_unqualified_root_is_refused_at_run_init(isolated, sealed_hosts, root_host, team_host):
    # The independent host-plan matrix covers the supported pairs and the
    # both-invalid pairs. Here the second input is always reachable.
    assert (root_host in TEAM_HOSTS) != (team_host in TEAM_HOSTS)
    field = "team" if root_host in TEAM_HOSTS else "root"
    run = isolated / "run"
    config = isolated / "team-run.json"
    # Host admission precedes project validation and creation of owner state.
    value = {"schema": "aegis.team-run/v2", "hosts": {"root": root_host, "team": team_host},
             "run": str(run), "project": str(isolated), "base": "0" * 40, "branch": "delivery/topic",
             "initiative": {}, "roles": [], "lanes": [], "recipes": {}, "limits": {}, "preflight": {}, "team": {}}
    config.write_text(json.dumps(value), encoding="utf-8")
    script = SOURCE / "tools" / "hierarchy_team.py"
    environment = {**os.environ, "PATH": str(sealed_hosts.path)}
    for _ in range(2):
        result = sealed_hosts.run_script(script, "--config", str(config), "init", env=environment)
        sealed_hosts.expect()
        assert result.returncode == 2 and result.stderr == ""
        assert json.loads(result.stdout)["error"].startswith(f"hosts.{field} must be claude-code or codex-cli")
        assert not run.exists()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="legacy team runs require Linux process custody")
def test_resume_refuses_mismatched_host_profile(isolated, sealed_hosts):
    from tests.integration.hierarchy_fake_wrapper import python_argv
    from tests.integration.test_hierarchy_launcher import FAKE_CODEX, LAUNCHER, REVIEW
    from tests.integration.test_hierarchy_mailbox import HELPER
    from tests.integration.test_hierarchy_provision import INITIATIVE, LANES, PROVISION, build_source

    options = sealed_hosts.legacy_options()
    program = team_profile.PRESET_DATA["hosts"][team_host_registry.CODEX]["cli"]
    sealed_hosts.install(program, python_argv(program, FAKE_CODEX, isolated), FAKE_CODEX.name)
    executable = sealed_hosts.executable(program)
    source, store, base = (isolated / name for name in ("source", "store", "initiatives/pilot"))
    mailbox = base / "mailbox"
    request = isolated / "launcher-request.json"
    codex_log = isolated / "fake-codex.log"
    host_log = isolated / "fake-host.log"
    host_plan = isolated / "fake-host-plan.json"
    host_plan.write_text("{}", encoding="utf-8")
    environment = {**os.environ, **options, "CODEX_HOME": str(isolated / "codex-home"),
                   "FAKE_CODEX_LOG": str(codex_log), "FAKE_HOST_LOG": str(host_log), "FAKE_HOST_PLAN": str(host_plan),
                   "FAKE_CODEX_THREAD": "019a6c3e-1111-7222-8333-444455556666"}

    def run(script, *words, document=None, expect=0):
        if document is not None:
            request.write_text(json.dumps(document), encoding="utf-8")
            words = (*words, "--request", str(request))
        result = sealed_hosts.run_script(script, *words, env=environment, timeout=60)
        assert result.returncode == expect and result.stderr == "", (result.stdout, result.stderr)
        return json.loads(result.stdout)

    def binding():
        return run(HELPER, "--root", str(mailbox), "status")["bindings"].get(REVIEW)

    run(SOURCE / "tools" / "hierarchy_workspace.py", "--store", str(store), "init",
        document={"writer_limit": 3, "heavy_limit": 3})
    build_source(source)
    run(PROVISION, "init", document={"store": str(store), "base": str(base), "source": str(source),
                                     "initiative": INITIATIVE, "lanes": LANES})
    sealed_hosts.expect()
    started = run(LAUNCHER, "--base", str(base), "start", document={"endpoint": REVIEW})
    sealed_hosts.expect(executable)
    sender = run(PROVISION, "add-role", document={"base": str(base), "endpoint": "pilot/orchestrator",
                                                 "host": team_host_registry.CLAUDE, "cwd": str(isolated)})
    run(HELPER, "--root", str(mailbox), "publish", document={
        "message_id": "for-review", "from": "pilot/orchestrator", "to": REVIEW,
        "host": sender["host"], "session": sender["session"], "binding_generation": sender["generation"],
        "type": "info", "body": "UNTRUSTED-BODY",
    })
    original_binding = binding()
    profile = Path(started["wake_profile"])
    original = profile.read_bytes()
    document = json.loads(original)
    assert document["host"] == original_binding["host"] == team_host_registry.CODEX
    profile.write_text(json.dumps({**document, "host": team_host_registry.CLAUDE}), encoding="utf-8")
    start_calls = codex_log.read_bytes()
    for _ in range(2):
        refused = run(LAUNCHER, "--base", str(base), "resume", "--endpoint", REVIEW, expect=2)
        sealed_hosts.expect()
        assert (refused["state"], refused["error"], refused["wake_exit_code"]) == (
            "refused", "profile does not match the current binding", 2,
        )
        assert binding() == original_binding
        assert codex_log.read_bytes() == start_calls and not host_log.exists()

    profile.write_bytes(original)
    assert run(LAUNCHER, "--base", str(base), "resume", "--endpoint", REVIEW)["state"] == "resumed"
    sealed_hosts.expect(executable)
    assert host_log.exists() and binding() == original_binding


def root_run_fixture(isolated, sealed_hosts, team_host, policy, capsys):
    from tests.integration import hierarchy_fake_claude
    from tests.integration import test_hierarchy_team as harness
    from tests.integration.hierarchy_fake_wrapper import python_argv

    options = sealed_hosts.legacy_options()
    fake_bin = sealed_hosts.path
    codex_wrapper = fake_bin / "codex-wrapper.py"
    codex_wrapper.write_text(
        harness.CODEX_WRAPPER % {"fake": str(harness.FAKE_CODEX), "agent": str(harness.AGENT_TOOLS)},
        encoding="utf-8",
    )
    sealed_hosts.install("codex", python_argv("codex", codex_wrapper, isolated), harness.FAKE_CODEX.name)
    claude_script = hierarchy_fake_claude.HERE
    sealed_hosts.install("claude", python_argv("claude", claude_script, isolated), claude_script.name)
    assert harness.real_codex_on(str(fake_bin)) is None
    hierarchy_fake_claude.require_fake(str(fake_bin))

    source = isolated / "source"
    (source / "tools").mkdir(parents=True)
    for tool in (SOURCE / "tools").glob("hierarchy_*.py"):
        shutil.copy2(tool, source / "tools" / tool.name)
    shutil.copytree(SOURCE / "tools" / "hierarchy_templates", source / "tools" / "hierarchy_templates")
    project = isolated / "project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "sample.txt").write_text("fixture\n", encoding="utf-8")
    profile_path = project.joinpath(*team_profile.REPO_PATH)
    profile_path.parent.mkdir(parents=True)
    profile_path.write_text(json.dumps({"version": 1, "preset": "solo", "policy": policy}), encoding="utf-8")
    code, shown = cli(project, capsys, "config", "show")
    assert code == 0
    resolved = shown["profile"]["policy"]
    target = resolved["landing"]["target_branch"]
    # The legacy run API receives its preflight and initiative settings
    # explicitly. Exercise the shipped consumers with those projected fields.
    gates = resolved["gates"]
    preflight = {"recipes": [], "expect": {}}
    recipes = {"probe": harness.command(["$python", "-c", "print('probe')"])}
    if gates:
        [gate] = gates
        assert gate["selector"] == "list" and gate["runner"] == "local" and gate["must_pass"]
        preflight = {"recipes": [gate["name"]], "expect": {gate["name"]: {"min_passed": 2, "failed": 0}},
                     "paths": {gate["name"]: gate["tests"]}}
        for relative in gate["tests"]:
            sample = project / relative
            sample.parent.mkdir(parents=True, exist_ok=True)
            sample.write_text("def test_selected():\n    assert True\n", encoding="utf-8")
        (project / "tests" / "test_excluded.py").write_text(
            "def test_excluded():\n    raise AssertionError('selector widened')\n", encoding="utf-8"
        )
        recipes[gate["name"]] = harness.command(
            ["$python", "-B", "-c", harness.RUNNER, "$scratch/junit.xml", "$paths"],
            require_clean=True, expects_tests=True, keep=["run/junit.xml"]
        )
    for repo in (source, project):
        harness.git(repo, "init", "-q", "-b", CHECKOUT_BRANCH)
        harness.git(repo, "add", ".")
        harness.git(repo, "commit", "-qm", "test seed")

    recipe = isolated / "recipes.json"
    recipe.write_text(json.dumps({"schema": "aegis.hierarchy-job-recipes/v1", "python": sys.executable,
                                  "path": [str(fake_bin)], "recipes": recipes}),
                      encoding="utf-8")
    run = isolated / "run"
    base = harness.git(project, "rev-parse", "HEAD")
    tree = harness.git(project, "rev-parse", "HEAD^{tree}")
    config = isolated / "team-run.json"
    config.write_text(json.dumps({
        "schema": "aegis.team-run/v2", "hosts": {"root": team_host_registry.CODEX, "team": team_host},
        "run": str(run), "source": str(source), "project": str(project), "base": base, "branch": "delivery/topic",
        "initiative": {"id": "pilot", "project": "fixture", "repository": "fixture",
                       "priority": 5, "target_branch": target},
        "roles": [], "lanes": [{"id": "review", "kind": "reviewer"}],
        "recipes": {"keep": list(recipes), "commit_identity": {"name": "Fixture", "email": "fixture@example.invalid"},
                    "template": str(recipe), "python": sys.executable},
        "limits": {"writer_limit": 1, "heavy_limit": 1, "heavy_tests_limit": 1},
        "preflight": preflight,
        "team": harness.TEAM_SETTINGS, "min_free_gb": 1,
    }), encoding="utf-8")
    request = isolated / "request.json"
    request.write_text(json.dumps({
        "id": "feature-1", "version": 1, "team": "pilot", "owner": "pilot/orchestrator",
        "next_decision": "implement the feature", "phase": "implementation", "operation": "feature",
        "source": {"commit": base, "tree": tree, "dirty_sha256": hashlib.sha256(b"").hexdigest()},
        "paths": [str(project / "src")], "prerequisites": [], "authority": "feature-1",
        "continuation": {"members": [], "max_starts": 1, "expires_at": "2099-01-01T00:00:00Z"},
    }), encoding="utf-8")
    log = isolated / "fake-root.jsonl"
    environment = team_host_registry.child_environment(dict(os.environ), "no-host")
    for variable in ("CODEX_HOME", "CLAUDE_CONFIG_DIR"):
        environment.pop(variable, None)
    environment.update(**options, FAKE_TEAM_LOG=str(log))
    return run, config, request, log, environment, base


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="legacy team runs require Linux process custody")
@pytest.mark.parametrize("team_host", TEAM_HOSTS)
def test_fake_codex_root_records_one_restricted_turn(isolated, sealed_hosts, team_host, capsys):
    from tests.integration.hierarchy_fake_host import server_definitions

    os.environ.update(CODEX_HOME=str(isolated / "foreign-codex"),
                      CLAUDE_CONFIG_DIR=str(isolated / "foreign-claude"))
    policy = AEGIS_POLICY if team_host == team_host_registry.CODEX else MINIMAL_POLICY
    run, config, request, log, environment, base = root_run_fixture(isolated, sealed_hosts, team_host, policy, capsys)
    assert {"CODEX_HOME", "CLAUDE_CONFIG_DIR"}.isdisjoint(environment)
    fake_bin = Path(environment["PATH"])
    assert fake_bin == sealed_hosts.path
    assert {path.name for path in fake_bin.iterdir() if os.access(path, os.X_OK)} == sealed_hosts.programs | {
        "bwrap", "git", "ps"
    }
    script = SOURCE / "tools" / "hierarchy_team.py"

    def team(*words, expect=0, executables=()):
        result = sealed_hosts.run_script(script, "--config", str(config), *words, env=environment, timeout=60)
        sealed_hosts.expect(*executables)
        assert result.returncode == expect and result.stderr == "", (result.stdout, result.stderr)
        return json.loads(result.stdout)

    assert team("init")["init"] == "complete"
    plan = json.loads((run / "initiatives" / "pilot" / "host-plan.json").read_text(encoding="utf-8"))
    assert (plan["root"], plan["team"]) == (team_host_registry.CODEX, team_host)
    assert plan["config_sha256"] == hashlib.sha256(config.read_bytes()).hexdigest()
    preflight = json.loads((run / "evidence" / "preflight-results.json").read_text(encoding="utf-8"))
    if team_host == team_host_registry.CODEX:
        [result] = preflight["results"]
        assert (result["recipe"], result["state"], result["tests"]["passed"], result["tests"]["failed"]) == (
            "contract", "completed", 2, 0
        )
    else:
        assert preflight["results"] == []
    opened = team("root", "--session", "root-session")
    assert opened["tools"] == ["root_decide", "team_status", "team_pending", "team_request"]
    published = team("request", "feature-1", "--file", str(request))
    program = team_profile.PRESET_DATA["hosts"][plan["root"]]["cli"]
    executable = sealed_hosts.executable(program)
    decision = team("approve", "feature-1", "--reason", "fixture approval", executables=(executable,))
    assert decision["request_sha256"] == published["sha256"] and decision["decision"] == "approve"
    calls = log.read_bytes()
    [call] = [json.loads(line) for line in calls.splitlines()]
    assert call["kind"] == "root"
    argv = call["argv"]
    disabled = [value for flag, value in zip(argv, argv[1:]) if flag == "--disable"]
    assert Counter(disabled) == Counter(("apps", "plugins", "remote_plugin", "multi_agent", "multi_agent_v2",
                                        "memories", "computer_use", "browser_use", "browser_use_external",
                                        "browser_use_full_cdp_access", "goals", "shell_tool", "unified_exec"))
    params = [value for flag, value in zip(argv, argv[1:]) if flag == "-c"]
    assert len(params) == 2 and params[0] == 'approval_policy="never"' and params[1].startswith("mcp_servers=")
    restriction_flags = [word for feature in disabled for word in ("--disable", feature)]
    assert argv[:-1] == [*restriction_flags, "exec", "--ignore-user-config", "--sandbox", "read-only",
                         "-c", params[0], "-c", params[1], "--json", "-C", str(isolated / "project"),
                         "resume", "root-session"]
    assert argv[-1].startswith("Call team_pending, find request feature-1,")
    definitions = json.loads(Path(opened["connection"]).read_text(encoding="utf-8"))["mcpServers"]
    assert set(definitions) == {"aegis_decision"}
    assert server_definitions(argv) == {"aegis_decision": {
        **definitions["aegis_decision"], "required": True, "enabled_tools": opened["tools"],
        "tools": {name: {"approval_mode": "approve"} for name in opened["tools"]},
    }}
    evidence_file = run / "evidence" / "root-turns.jsonl"
    evidence = evidence_file.read_bytes()
    events = [json.loads(line) for line in evidence.splitlines()]
    assert sum(event["type"] == "turn.completed" for event in events) == 1
    index = json.loads((evidence_file.parent / "index.json").read_text(encoding="utf-8"))
    assert index["files"]["root-turns.jsonl"]["sha256"] == hashlib.sha256(evidence).hexdigest()
    refused = team("approve", "feature-1", "--reason", "repeated", expect=2)
    assert refused == {"error": "request feature-1 is not pending a ROOT decision (journal state: approved)"}
    assert log.read_bytes() == calls
    assert evidence_file.read_bytes() == evidence
    assert_target_branch_routing(run, isolated, sealed_hosts, environment, policy, base)


def assert_target_branch_routing(run, isolated, sealed_hosts, environment, policy, base):
    script = SOURCE / "tools" / "hierarchy_workspace.py"
    target = policy["landing"]["target_branch"]
    checkout = subprocess.run(["git", "-C", str(isolated / "project"), "symbolic-ref", "--short", "HEAD"],
                              env=environment, capture_output=True, text=True, check=True, timeout=15).stdout.strip()
    assert checkout == CHECKOUT_BRANCH and checkout != target

    def workspace(expect, *words):
        result = sealed_hosts.run_script(script, "--store", str(run / "store"), *words, env=environment)
        assert result.returncode == expect and result.stderr == "", (result.stdout, result.stderr)
        return json.loads(result.stdout)

    def mark_merge(branch):
        path = isolated / "merge.json"
        path.write_text(json.dumps({"repository": "fixture", "branch": branch, "commit": base,
                                    "source": "fixture"}), encoding="utf-8")
        return workspace(0, "mark-merge", "--request", str(path))

    assert mark_merge(checkout)["marked"] == []
    assert workspace(0, "check-delivery", "--initiative", "pilot")["ready"] is True
    assert mark_merge(target)["marked"] == ["pilot"]
    blocked = workspace(3, "check-delivery", "--initiative", "pilot")
    assert blocked["ready"] is False and blocked["base_moved"]["commit"] == base


def test_registered_axes_have_explicit_expected_cardinality():
    assert set(team_profile.PRESET_DATA["presets"]) == {*PRESETS, "ci-only"}
    assert len(PROFILE_HOSTS) == 4
    assert len(ROOT_MATRIX_HOSTS) == len(set(ROOT_MATRIX_HOSTS)) == 4
    assert len(REPOSITORIES) == 2


@pytest.mark.skipif(os.name != "posix", reason="executes POSIX logging fakes")
def test_sealed_path_records_wrong_host_execution(sealed_hosts):
    profiles = team_profile.PRESET_DATA["hosts"]
    expected = sealed_hosts.executable(profiles[team_host_registry.CODEX]["cli"])
    wrong = sealed_hosts.executable(profiles[team_host_registry.CLAUDE]["cli"])
    ran = subprocess.run([str(wrong)], capture_output=True, timeout=15)
    assert ran.returncode == 97
    with pytest.raises(AssertionError, match="host execution: expected .*codex.*observed .*claude"):
        sealed_hosts.expect(expected)
    sealed_hosts.expect(wrong)


@pytest.mark.skipif(os.name != "posix", reason="executes POSIX logging fakes")
def test_sealed_path_distinguishes_same_named_executable(sealed_hosts, tmp_path):
    uninstrumented = tmp_path / "uninstrumented-host"
    marker = tmp_path / "uninstrumented-ran"
    uninstrumented.write_text(f"#!/bin/sh\nprintf ran > {quote(str(marker))}\n", encoding="utf-8")
    uninstrumented.chmod(0o755)
    with pytest.raises(PermissionError, match="executable outside conformance fixture"):
        subprocess.run([str(uninstrumented)], capture_output=True, timeout=15)
    sealed_hosts.expected_refusals.extend((
        ("pytest", "subprocess.Popen"), ("pytest", "os.system"),
        ("shim", "subprocess.Popen"), ("shim", "os.exec"), ("shim", "os.system"),
    ))

    parent_refusal = None
    try:
        os.system(quote(str(uninstrumented)))
    except PermissionError as refusal:
        parent_refusal = str(refusal)

    probe = tmp_path / "audit-probe.py"
    probe.write_text(
        "import os, subprocess, sys\n"
        "from shlex import quote\n"
        "assert __name__ == '__main__' and sys.argv[2:] == ['two words', '--unchanged']\n"
        "program = sys.argv[1]\n"
        "for run in (lambda: subprocess.run([program]), lambda: os.execv(program, [program])):\n"
        "    try:\n"
        "        run()\n"
        "    except PermissionError:\n"
        "        print('blocked')\n"
        "try:\n"
        "    os.system(quote(program))\n"
        "except PermissionError as refusal:\n"
        "    print(refusal)\n",
        encoding="utf-8",
    )
    refused = sealed_hosts.run_script(probe, str(uninstrumented), "two words", "--unchanged")
    message = "process launch without an executable: os.system"
    assert (parent_refusal, refused.returncode, refused.stdout.splitlines(), refused.stderr) == (
        message, 0, ["blocked", "blocked", message], "",
    )
    assert not marker.exists()

    program = team_profile.PRESET_DATA["hosts"][team_host_registry.CODEX]["cli"]
    expected = sealed_hosts.executable(program)
    shadow = sealed_hosts.path / "shadow" / program
    shadow.parent.mkdir()
    shutil.copy2(expected, shadow)
    assert shutil.which(program) == str(expected)

    wrong = subprocess.run([str(shadow)], capture_output=True, timeout=15)
    assert wrong.returncode == 97
    assert sealed_hosts.log.read_text(encoding="utf-8").splitlines() == [str(shadow)]
    with pytest.raises(AssertionError, match="host execution:"):
        sealed_hosts.expect(expected)
    sealed_hosts.expect(shadow)

    selected = subprocess.run([str(expected)], capture_output=True, timeout=15)
    assert selected.returncode == 97
    sealed_hosts.expect(expected)


@pytest.mark.skipif(not hasattr(os, "startfile"), reason="requires os.startfile")
def test_sealed_path_refuses_startfile(sealed_hosts, tmp_path):
    missing = tmp_path / "unapproved-launch.exe"
    with pytest.raises(PermissionError, match=r"^process launch without an executable: os\.startfile$"):
        os.startfile(str(missing))
    sealed_hosts.expected_refusals.append(("pytest", "os.startfile"))


@pytest.fixture(scope="module")
def ctypes_available():
    if importlib.util.find_spec("ctypes") is None or importlib.util.find_spec("_ctypes") is None:
        pytest.skip("requires ctypes")


def test_sealed_path_refuses_ctypes_call(sealed_hosts, ctypes_available, tmp_path):
    probe = tmp_path / "ctypes-probe.py"
    # The Windows library loader can translate PermissionError to AttributeError.
    # The fixture's exact refusal ledger verifies why the binding stopped.
    probe.write_text(
        "try:\n"
        "    import ctypes\n"
        "    ctypes.PYFUNCTYPE(ctypes.c_char_p)(('Py_GetVersion', ctypes.pythonapi))\n"
        "except (PermissionError, AttributeError):\n"
        "    print('binding refused')\n"
        "else:\n"
        "    raise AssertionError('native binding ran inside the seal')\n",
        encoding="utf-8",
    )
    result = sealed_hosts.run_script(probe)
    assert (result.returncode, result.stdout.splitlines(), result.stderr) == (0, ["binding refused"], "")
    sealed_hosts.expected_refusals.append(("shim", "ctypes.dlopen"))


def test_sealed_path_refuses_ctypes_preload(sealed_hosts, ctypes_available, tmp_path):
    probe = tmp_path / "preload-probe.py"
    probe.write_text("print('target ran')\n", encoding="utf-8")
    result = sealed_hosts.run_script(probe, preload_ctypes=True)
    assert (result.returncode, result.stdout, result.stderr) == (126, "", "")
    assert not any(origin == "shim" for origin, _, _ in sealed_hosts.launch_rows())


def test_sealed_path_refuses_cffi_import(sealed_hosts):
    for name in ("cffi", "_cffi_backend"):
        for load in (__import__, importlib.import_module):
            with pytest.raises(PermissionError, match="^foreign function access: import$"):
                load(name)
            sealed_hosts.expected_refusals.append(("pytest", "import"))


def test_sealed_path_audit_event_inventory(sealed_hosts, tmp_path):
    policy = launch_event_policy()
    assert len(policy) == 28
    assert sum(position is not None for position in policy.values()) == 5
    outside = tmp_path / "unapproved-application.exe"
    outside.touch()
    expected = []
    for event, position in policy.items():
        # An audit event can be exercised without launching a process.
        arguments = [None, "fixture command text", None, None]
        if position is not None:
            arguments[position] = sys.executable
            sys.audit(event, *arguments)
            expected.append(["pytest", event, str(Path(sys.executable).resolve())])
            arguments[position] = str(outside)
            with pytest.raises(PermissionError):
                sys.audit(event, *arguments)
            sealed_hosts.expected_refusals.append(("pytest", event))
            expected.append(["pytest", event, None])
            arguments[position] = None
        with pytest.raises(PermissionError):
            sys.audit(event, *arguments)
        sealed_hosts.expected_refusals.append(("pytest", event))
        expected.append(["pytest", event, None])
    sys.audit("conformance.unrelated")
    assert sealed_hosts.launch_rows() == expected


def call_winapi_probe(application, missing):
    import _winapi
    import subprocess

    command = subprocess.list2cmdline([missing])
    process, thread, _, _ = _winapi.CreateProcess(
        application, command, None, None, False, 0, None, None, subprocess.STARTUPINFO(),
    )
    try:
        _winapi.CloseHandle(thread)
    finally:
        _winapi.CloseHandle(process)


@pytest.mark.skipif(os.name != "nt", reason="requires the Windows process API")
def test_sealed_path_refuses_winapi_launch(sealed_hosts, tmp_path):
    missing = str(tmp_path / "unapproved-launch.exe")
    for application in (missing, None):
        with pytest.raises(PermissionError, match="^executable outside conformance fixture$"):
            call_winapi_probe(application, missing)
        sealed_hosts.expected_refusals.append(("pytest", "_winapi.CreateProcess"))

    probe = tmp_path / "winapi-probe.py"
    probe.write_text(
        getsource(call_winapi_probe) + "\n"
        "import sys\n"
        "missing = sys.argv[1]\n"
        "for application in (missing, None):\n"
        "    try:\n"
        "        call_winapi_probe(application, missing)\n"
        "    except PermissionError as refusal:\n"
        "        assert str(refusal) == 'executable outside conformance fixture'\n"
        "        print('blocked')\n",
        encoding="utf-8",
    )
    result = sealed_hosts.run_script(probe, missing)
    assert (result.returncode, result.stdout.splitlines(), result.stderr) == (0, ["blocked", "blocked"], "")
    sealed_hosts.expected_refusals.extend([("shim", "_winapi.CreateProcess")] * 2)


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux kernel exec enforcement")
@pytest.mark.parametrize("method", (
    "execv",
    pytest.param("posix_spawn", marks=pytest.mark.skipif(not hasattr(os, "posix_spawn"),
                                                        reason="requires posix_spawn")),
    "subprocess",
    "shell",
))
def test_kernel_exec_refuses_unlisted_program(sealed_hosts, tmp_path, method):
    marker = tmp_path / "unexpected-launch"
    outside = tmp_path / "unlisted"
    write_shell_free_fake(
        outside,
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n",
    )
    fake = sealed_hosts.executable("codex")
    # This allowed fake is a descendant without a Python audit hook.
    write_shell_free_fake(
        fake,
        "import errno, os, subprocess, sys\n"
        f"with open({str(sealed_hosts.log)!r}, 'a', encoding='utf-8') as log:\n"
        "    log.write(__file__ + '\\n')\n"
        "method, program, marker = sys.argv[1:]\n"
        "command = ['/bin/sh', '-c', 'printf ran > \"$1\"', 'fixture', marker] if method == 'shell' else [program]\n"
        "try:\n"
        "    if method == 'execv':\n"
        "        os.execv(command[0], command)\n"
        "    elif method == 'posix_spawn':\n"
        "        os.waitpid(os.posix_spawn(command[0], command, os.environ), 0)\n"
        "    else:\n"
        "        subprocess.run(command, check=True, timeout=5)\n"
        "except OSError as refusal:\n"
        "    assert refusal.errno == errno.EACCES\n"
        "    print('exec denied')\n",
    )
    probe = tmp_path / "kernel-probe.py"
    probe.write_text(
        "import subprocess, sys\n"
        "subprocess.run(sys.argv[1:], check=True, timeout=10)\n",
        encoding="utf-8",
    )
    result = sealed_hosts.run_script(probe, str(fake), method, str(outside), str(marker))
    sealed_hosts.expect(fake)
    assert not marker.exists()
    assert (result.returncode, result.stdout, result.stderr) == (0, "exec denied\n", "")


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux kernel exec enforcement")
def test_kernel_exec_admits_registered_fakes(sealed_hosts, tmp_path):
    executables = [sealed_hosts.executable(name) for name in sorted(sealed_hosts.programs)]
    probe = tmp_path / "kernel-allowed.py"
    probe.write_text(
        "import subprocess, sys\n"
        "for executable in sys.argv[1:]:\n"
        "    assert subprocess.run([executable], timeout=5).returncode == 97\n",
        encoding="utf-8",
    )
    result = sealed_hosts.run_script(probe, *map(str, executables))
    sealed_hosts.expect(*executables)
    assert (result.returncode, result.stdout, result.stderr) == (0, "", "")


def _single_line_anchor(value):
    """Refuse an anchor that is empty, overlong, NUL, or broken by LF or CR.

    U+2028 and U+2029 are valid inside a path. CPython's configuration reader
    splits on LF (and only trims a CR that sits against that LF), so neither
    character is a configuration delimiter.
    """
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or "\x00" in value
        or "\n" in value
        or "\r" in value
    ):
        raise OSError(errno.EINVAL, "invalid interpreter path")
    return value


def _effective_base_home():
    """Return the pyvenv home of this interpreter's effective base.

    CPython's venv records ``dirname(sys._base_executable)`` as the ``home``
    key. ``Modules/getpath.py`` (3.12) uses that directory as
    ``executable_dir`` and searches upward for the base prefix. When that
    executable cannot be used, ``sys.base_prefix`` is the effective base and
    is itself a valid home. This never reads pyvenv.cfg, so a multi-kilobyte
    config cannot change the anchor or be rejected by a size cap.
    """
    raw = getattr(sys, "_base_executable", None)
    if isinstance(raw, bytes):
        try:
            raw = os.fsdecode(raw)
        except UnicodeError:
            raw = ""
    library = None
    if isinstance(raw, str) and raw and len(raw) <= 4096 and "\x00" not in raw and "\n" not in raw and "\r" not in raw:
        try:
            base = Path(raw)
            parent = str(base.parent)
            if base.is_file() and os.path.isabs(parent):
                library = parent
        except OSError:
            library = None
    if not library:
        prefix = getattr(sys, "base_prefix", None)
        if isinstance(prefix, bytes):
            try:
                prefix = os.fsdecode(prefix)
            except UnicodeError:
                prefix = ""
        if isinstance(prefix, str):
            library = prefix
    return _single_line_anchor(library or "")


def place_admitted_interpreter(home):
    """Point ``home/bin/python`` at the interpreter file ``run_landlocked`` admits.

    ``venv.create`` links ``sys._base_executable``. In a ``--copies`` venv that
    file is a different inode from ``Path(sys.executable).resolve()``, so the
    execute table would refuse the fake. This symlink keeps the admitted inode.
    ``pyvenv.cfg`` ``home`` comes from the running interpreter's effective
    base, so the fake reports that interpreter's ``sys.base_prefix``.
    """
    try:
        admitted = Path(sys.executable).resolve(strict=True)
    except OSError:
        raise OSError(errno.EINVAL, "invalid interpreter path") from None
    if not admitted.is_file():
        raise OSError(errno.EINVAL, "invalid interpreter path")
    library = _effective_base_home()
    root = Path(home)
    bindir = root / "bin"
    try:
        bindir.mkdir(parents=True, exist_ok=True)
    except OSError:
        raise OSError(errno.ENOENT, "interpreter link unavailable") from None
    spaced = bindir / "python"
    try:
        os.symlink(os.fspath(admitted), os.fspath(spaced))
    except OSError:
        raise OSError(errno.ENOENT, "interpreter link unavailable") from None
    version = "%d.%d.%d" % sys.version_info[:3]
    payload = "home = %s\ninclude-system-site-packages = false\nversion = %s\n" % (library, version)
    try:
        (root / "pyvenv.cfg").write_text(payload, encoding="utf-8")
    except OSError:
        raise OSError(errno.EIO, "interpreter link unavailable") from None
    try:
        if spaced.resolve(strict=True) != admitted:
            raise OSError(errno.EINVAL, "invalid interpreter path")
    except OSError:
        raise OSError(errno.EINVAL, "invalid interpreter path") from None
    return spaced


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux kernel exec enforcement")
def test_shell_free_fake_accepts_whitespace_interpreter(sealed_hosts, tmp_path):
    """A spaced path to the admitted interpreter still runs the fake."""
    rejected = tmp_path / "rejected"
    with pytest.raises(OSError) as caught:
        write_shell_free_fake(rejected, "raise SystemExit(0)\n", interpreter="bad\x00path")
    assert caught.value.errno == errno.EINVAL and not rejected.exists()
    with pytest.raises(OSError) as caught:
        write_shell_free_fake(rejected, "raise SystemExit(0)\n", interpreter="x" * 4097)
    assert caught.value.errno == errno.EINVAL and not rejected.exists()

    home = tmp_path / "ci env"
    spaced = place_admitted_interpreter(home)
    # Same realpath run_landlocked admits at the test-interpreter table entry.
    admitted = Path(sys.executable).resolve(strict=True)
    assert spaced.resolve(strict=True) == admitted
    anchor = _effective_base_home()
    assert (home / "pyvenv.cfg").read_text(encoding="utf-8").split("\n")[0] == "home = %s" % anchor
    fake = sealed_hosts.executable("codex")
    write_shell_free_fake(
        fake,
        "import sys\n"
        f"with open({str(sealed_hosts.log)!r}, 'a', encoding='utf-8') as log:\n"
        "    log.write(sys.argv[0] + '\\n')\n"
        "assert sys.prefix == sys.argv[1]\n"
        "assert sys.executable == sys.argv[2]\n"
        "assert sys.base_prefix == sys.argv[3]\n"
        "raise SystemExit(97)\n",
        interpreter=str(spaced),
    )
    shebang = fake.read_text(encoding="utf-8").splitlines()[0]
    launcher = shebang[2:].split(" ", 1)[0]
    assert shebang.startswith("#!") and launcher and " " not in launcher and "\t" not in launcher
    assert "ci env" not in shebang
    bare = subprocess.run(
        [str(fake), str(home), str(spaced), sys.base_prefix],
        capture_output=True, text=True, timeout=15,
    )
    assert (bare.returncode, bare.stdout, bare.stderr) == (97, "", ""), bare.stderr
    sealed_hosts.expect(fake)
    probe = tmp_path / "whitespace-probe.py"
    probe.write_text(
        "import subprocess, sys\n"
        "completed = subprocess.run(sys.argv[1:], capture_output=True, text=True, timeout=15)\n"
        "sys.stdout.write(completed.stdout)\n"
        "sys.stderr.write(completed.stderr)\n"
        "raise SystemExit(completed.returncode)\n",
        encoding="utf-8",
    )
    result = sealed_hosts.run_script(probe, str(fake), str(home), str(spaced), sys.base_prefix)
    sealed_hosts.expect(fake)
    assert (result.returncode, result.stdout, result.stderr) == (97, "", "")


def test_effective_base_home_refuses_multiline_anchor():
    """The anchor is one line from the interpreter and is not read from pyvenv.cfg."""
    raw = sys._base_executable
    if isinstance(raw, bytes):
        raw = os.fsdecode(raw)
    home = _effective_base_home()
    assert home == os.path.dirname(raw) or home == sys.base_prefix
    assert "\n" not in home and "\r" not in home and "\x00" not in home and len(home) <= 4096
    assert "os.open" not in getsource(_effective_base_home)
    assert "readlines" not in getsource(_effective_base_home)
    for bad in ("", "bad\x00value", "x" * 4097, "one\ntwo", "one\rtwo"):
        with pytest.raises(OSError) as caught:
            _single_line_anchor(bad)
        assert caught.value.errno == errno.EINVAL
        assert caught.value.strerror == "invalid interpreter path"
        assert caught.value.filename is None
    for character in ("\u2028", "\u2029"):
        anchor = _single_line_anchor("/usr/lib%sbin" % character)
        payload = "home = %s\ninclude-system-site-packages = false\n" % anchor
        assert payload.split("\n")[0] == "home = %s" % anchor
        assert character in payload.split("\n")[0]
        assert payload.count("\n") == 2


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux kernel exec enforcement")
def test_place_admitted_interpreter_does_not_replace_link(tmp_path):
    """A second placement leaves the admitted link in place and echoes nothing."""
    home = tmp_path / "ci env"
    first = place_admitted_interpreter(home)
    with pytest.raises(OSError) as caught:
        place_admitted_interpreter(home)
    assert caught.value.errno == errno.ENOENT
    assert caught.value.strerror == "interpreter link unavailable"
    assert caught.value.filename is None
    assert first.resolve(strict=True) == Path(sys.executable).resolve(strict=True)


def cffi_backend_installed():
    spec = importlib.util.find_spec("_cffi_backend")
    origin = getattr(spec, "origin", None)
    return isinstance(origin, str) and origin not in ("", "built-in", "frozen")


def raw_address_execv(program):
    """Exec through a CFuncPtr built from libc execv's integer address."""
    import _ctypes
    import errno
    import os

    encoded = os.fsencode(program)
    if not encoded or len(encoded) > 4096 or b"\x00" in encoded:
        raise OSError(errno.EINVAL, "invalid program path")
    # The address comes from dlsym. The call itself is not a ctypes.CDLL lookup.
    handle = _ctypes.dlopen(None, _ctypes.RTLD_LOCAL)
    address = _ctypes.dlsym(handle, "execv")
    if not isinstance(address, int) or address <= 0:
        raise OSError(errno.EINVAL, "missing execv address")

    class c_int(_ctypes._SimpleCData):
        _type_ = "i"

    class c_char_p(_ctypes._SimpleCData):
        _type_ = "z"

    class Execv(_ctypes.CFuncPtr):
        _argtypes_ = (c_char_p, _ctypes.POINTER(c_char_p))
        _restype_ = c_int
        _flags_ = _ctypes.FUNCFLAG_CDECL | _ctypes.FUNCFLAG_USE_ERRNO

    argv = (c_char_p * 2)(encoded, None)
    if Execv(address)(encoded, argv) < 0:
        error = _ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def fork_exec_arguments(program, encoded, read_fd, write_fd, version=None):
    """Positional ``_posixsubprocess.fork_exec`` arguments for one CPython.

    Cited to ``Lib/subprocess.py`` ``_execute_child`` (the call is stable
    across the patch releases checked):
    3.9.0 and 3.9.22 pass 21 arguments and stop at ``preexec_fn``
    (https://github.com/python/cpython/blob/v3.9.22/Lib/subprocess.py#L1770-L1779).
    3.10.0 and 3.10.16 use that same 21-argument call
    (https://github.com/python/cpython/blob/v3.10.16/Lib/subprocess.py#L1796-L1805).
    3.11.0 adds ``process_group`` before ``gid`` and ``allow_vfork``
    (``_USE_VFORK``) after ``preexec_fn``. The 3.11.0 C parser already
    requires ``allow_vfork`` (Modules/_posixsubprocess.c lines 762-772).
    3.11.13, 3.12.0, 3.12.11, 3.13.0 and 3.13.5 keep that 23-argument shape
    (https://github.com/python/cpython/blob/v3.11.0/Lib/subprocess.py#L1885-L1894,
    https://github.com/python/cpython/blob/v3.12.11/Lib/subprocess.py#L1885-L1894,
    https://github.com/python/cpython/blob/v3.13.5/Lib/subprocess.py#L1902-L1911).
    ``allow_vfork`` is 0 so the slot is present without requesting vfork.
    An interpreter outside 3.9-3.13 is refused before the call.
    """
    import errno
    import sys

    # Arguments after start_new_session.
    # 3.9/3.10: gid, gids, uid, umask, preexec_fn.
    # 3.11+: process_group, gid, gids, uid, umask, preexec_fn, allow_vfork.
    trailing = {
        (3, 9): (None, None, None, -1, None),
        (3, 10): (None, None, None, -1, None),
        (3, 11): (-1, None, None, None, -1, None, 0),
        (3, 12): (-1, None, None, None, -1, None, 0),
        (3, 13): (-1, None, None, None, -1, None, 0),
    }
    selected = sys.version_info[:2] if version is None else version
    chosen = trailing.get(selected)
    if chosen is None:
        raise OSError(errno.EINVAL, "unsupported fork_exec arity")
    return (
        [program], (encoded,),
        True, (write_fd,),
        None, None,
        -1, -1, -1, -1, -1, -1,
        read_fd, write_fd,
        1, 0,
        *chosen,
    )


def subprocess_fork_exec_positional_count(source):
    """Count positional arguments of each fork_exec call in subprocess source."""
    import ast

    tree = ast.parse(source)
    counts = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        else:
            continue
        if name in ("fork_exec", "_fork_exec"):
            counts.append(len(node.args))
    return counts


def direct_fork_exec(program):
    """Exec through _posixsubprocess.fork_exec and surface the child's errno."""
    import _posixsubprocess
    import errno
    import os

    encoded = os.fsencode(program)
    if not encoded or len(encoded) > 4096 or b"\x00" in encoded:
        raise OSError(errno.EINVAL, "invalid program path")
    read_fd, write_fd = os.pipe()
    pid = None
    try:
        try:
            while write_fd < 3:
                replacement = os.dup(write_fd)
                os.close(write_fd)
                write_fd = replacement
            arguments = fork_exec_arguments(program, encoded, read_fd, write_fd)
            pid = _posixsubprocess.fork_exec(*arguments)
        finally:
            os.close(write_fd)
        chunks = []
        remaining = 256
        while remaining:
            part = os.read(read_fd, remaining)
            if not part:
                break
            if len(part) > remaining:
                raise OSError(errno.EIO, "exec status exceeded its limit")
            chunks.append(part)
            remaining -= len(part)
        data = b"".join(chunks)
    finally:
        os.close(read_fd)
        if pid is not None:
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
    if not data:
        return
    fields = data.split(b":", 2)
    token = fields[1] if len(fields) >= 2 else b""
    error = errno.EACCES
    if token and len(token) <= 8:
        try:
            error = int(token, 16)
        except ValueError:
            error = errno.EACCES
    raise OSError(error, os.strerror(error))


def qualified_cffi_exec(program):
    """Exec through a package-qualified _cffi_backend loaded from its file."""
    import errno
    import importlib.util
    import os

    encoded = os.fsencode(program)
    if not encoded or len(encoded) > 4096 or b"\x00" in encoded:
        raise OSError(errno.EINVAL, "invalid program path")
    located = importlib.util.find_spec("_cffi_backend")
    origin = getattr(located, "origin", None)
    if not isinstance(origin, str) or origin in ("", "built-in", "frozen"):
        raise OSError(errno.ENOENT, "cffi backend unavailable")
    spec = importlib.util.spec_from_file_location("probe._cffi_backend", origin)
    if spec is None or spec.loader is None:
        raise OSError(errno.ENOENT, "cffi backend unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    char = module.new_primitive_type("char")
    signed = module.new_primitive_type("int")
    char_p = module.new_pointer_type(char)
    char_pp = module.new_pointer_type(char_p)
    function_type = module.new_function_type((char_p, char_pp), signed)
    library = module.load_library(None, module.RTLD_NOW)
    function = library.load_function(function_type, "execv")
    stored = module.newp(module.new_array_type(char_p, len(encoded) + 1), encoded)
    # newp(..., None) zero-fills the array, so argv[1] is already a NULL pointer.
    argv = module.newp(module.new_array_type(char_pp, 2), None)
    argv[0] = stored
    if function(stored, argv) != 0:
        error = module.get_errno()
        raise OSError(error, os.strerror(error))


def _bounded_program_marker(marker):
    """Refuse an empty, overlong, NUL, or multi-line marker before any syscall."""
    import errno
    import os

    try:
        encoded = os.fsencode(marker)
    except (TypeError, UnicodeError, ValueError):
        raise OSError(errno.EINVAL, "invalid program path") from None
    if (
        not isinstance(encoded, bytes)
        or not encoded
        or len(encoded) > 4096
        or b"\x00" in encoded
        or b"\n" in encoded
        or b"\r" in encoded
    ):
        raise OSError(errno.EINVAL, "invalid program path")
    return encoded


def _native_memfd_pair():
    """Native ``(memfd_create, execveat)`` numbers from the one ABI table."""
    import os

    machine = os.uname().machine if hasattr(os, "uname") else ""
    for kind, host, _arch, nr, execveat_nr in memfd_abi_table():
        if kind == "native" and host == machine:
            return (nr, execveat_nr)
    return None


def _syscall_memfd(libc, number):
    """Create an executable memfd, retrying without ``MFD_EXEC`` on EINVAL.

    The first attempt uses ``MFD_CLOEXEC|MFD_EXEC``. A kernel that does not
    know ``MFD_EXEC`` returns EINVAL and the default executable memfd is
    tried once. ``EPERM`` is not retried: that is the seccomp refusal.
    """
    import ctypes
    import errno

    created = -1
    for flags in executable_memfd_flags():
        ctypes.set_errno(0)
        created = libc.syscall(number, ctypes.c_char_p(b"aegis"), flags)
        if created >= 0 or ctypes.get_errno() != errno.EINVAL:
            break
    return created


def populate_and_exec_memfd(libc, memfd, marker_bytes, execveat_nr, interpreter):
    """Copy ``interpreter`` into ``memfd`` and ``execveat`` it with an empty path.

    ``memfd`` is closed on every return, including when ``os.open`` or
    ``os.read`` fails. A successful ``execveat`` replaces the process.
    """
    import ctypes
    import errno
    import os

    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        try:
            source = os.open(interpreter, flags)
        except OSError:
            raise OSError(errno.EIO, "invalid interpreter path") from None
        try:
            chunks = []
            remaining = 67108865
            while remaining:
                try:
                    block = os.read(source, 1048576 if remaining > 1048576 else remaining)
                except OSError:
                    raise OSError(errno.EIO, "invalid interpreter path") from None
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
        finally:
            os.close(source)
        image = b"".join(chunks)
        if len(image) > 67108864 or len(image) < 64 or image[:4] != b"\x7fELF":
            raise OSError(errno.EINVAL, "invalid interpreter path")
        offset = 0
        while offset < len(image):
            try:
                count = os.write(memfd, image[offset:])
            except OSError:
                raise OSError(errno.EIO, "invalid interpreter path") from None
            if count <= 0:
                raise OSError(errno.EIO, "invalid interpreter path")
            offset += count
        code = b"from pathlib import Path\nimport sys\nPath(sys.argv[1]).touch()\n"
        argv = (ctypes.c_char_p * 6)(b"aegis", b"-I", b"-c", code, marker_bytes, None)
        envp = (ctypes.c_char_p * 1)(None)
        result = libc.syscall(
            execveat_nr, memfd, ctypes.c_char_p(b""), argv, envp, 0x1000,
        )
        error = ctypes.get_errno()
        if result < 0:
            raise OSError(errno.EIO if not error else error, "exec denied")
        raise OSError(errno.EIO, "exec denied")
    finally:
        os.close(memfd)


def anonymous_memfd_exec(marker):
    """Exec an anonymous file through ``execveat`` so it can write ``marker``.

    The memfd is a copy of this interpreter and is executed with
    ``AT_EMPTY_PATH``. ``fexecve`` and ``/proc/self/fd`` are not used: those
    are named paths. ``memfd_create`` runs before the image is read, so a
    seccomp EPERM returns with no launch. Flags come from
    ``executable_memfd_flags``: ``MFD_EXEC`` where the kernel accepts it, and
    the default executable memfd where that flag returns EINVAL. An empty,
    overlong, NUL, or multi-line marker is refused before ctypes is imported.
    """
    import errno
    import os
    import sys

    encoded = _bounded_program_marker(marker)
    chosen = sys.executable
    if isinstance(chosen, bytes):
        try:
            chosen = os.fsdecode(chosen)
        except UnicodeError:
            raise OSError(errno.EINVAL, "invalid interpreter path") from None
    if not isinstance(chosen, str) or not chosen or len(chosen) > 4096 or "\x00" in chosen:
        raise OSError(errno.EINVAL, "invalid interpreter path")
    import ctypes
    pair = _native_memfd_pair()
    if pair is None or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise OSError(errno.EINVAL, "unsupported memfd syscall ABI")
    memfd_nr, execveat_nr = pair
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    created = _syscall_memfd(libc, memfd_nr)
    if created < 0:
        error = ctypes.get_errno()
        raise OSError(errno.EIO if not error else error, "memfd denied")
    populate_and_exec_memfd(libc, int(created), encoded, execveat_nr, chosen)


def install_reviewer_fake(hosts):
    """Write the hook-free allowed fake that performs one reviewer launch form."""
    fake = hosts.executable("codex")
    write_shell_free_fake(
        fake,
        getsource(fork_exec_arguments) + "\n\n"
        + getsource(raw_address_execv) + "\n\n"
        + getsource(direct_fork_exec) + "\n\n"
        + getsource(qualified_cffi_exec) + "\n\n"
        + "import errno\nimport sys\n"
        + f"with open({str(hosts.log)!r}, 'a', encoding='utf-8') as stream:\n"
        + "    stream.write(__file__ + '\\n')\n"
        + "method, program = sys.argv[1], sys.argv[2]\n"
        + "try:\n"
        + "    if method == 'raw_ctypes_execv':\n"
        + "        raw_address_execv(program)\n"
        + "    elif method == 'fork_exec':\n"
        + "        direct_fork_exec(program)\n"
        + "    elif method == 'qualified_cffi':\n"
        + "        qualified_cffi_exec(program)\n"
        + "    else:\n"
        + "        raise OSError(errno.EINVAL, 'unknown launch form')\n"
        + "except OSError as refusal:\n"
        + "    if refusal.errno != errno.EACCES:\n"
        + "        raise\n"
        + "    print('exec denied')\n",
    )
    return fake


def prove_unlisted_kernel_exec(sealed_hosts, tmp_path, method):
    """The form writes the marker outside the domain and gets EACCES inside it."""
    marker = tmp_path / "unexpected-launch"
    outside = tmp_path / "unlisted"
    write_shell_free_fake(
        outside,
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n",
    )
    fake = install_reviewer_fake(sealed_hosts)
    bare = subprocess.run([str(fake), method, str(outside)], capture_output=True, text=True, timeout=15)
    assert (bare.returncode, bare.stdout, bare.stderr, marker.is_file()) == (0, "", "", True)
    marker.unlink()
    sealed_hosts.expect(fake)
    probe = tmp_path / "kernel-probe.py"
    probe.write_text(
        "import subprocess, sys\n"
        "subprocess.run(sys.argv[1:], check=True, timeout=10)\n",
        encoding="utf-8",
    )
    result = sealed_hosts.run_script(probe, str(fake), method, str(outside))
    sealed_hosts.expect(fake)
    assert not marker.exists()
    assert (result.returncode, result.stdout, result.stderr) == (0, "exec denied\n", "")


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux kernel exec enforcement")
@pytest.mark.parametrize("method", (
    "raw_ctypes_execv",
    "fork_exec",
    pytest.param("qualified_cffi", marks=pytest.mark.skipif(not cffi_backend_installed(),
                                                           reason="requires cffi")),
))
def test_kernel_exec_refuses_reviewer_form(sealed_hosts, tmp_path, method):
    prove_unlisted_kernel_exec(sealed_hosts, tmp_path, method)


def test_anonymous_memfd_exec_refuses_unbounded_marker():
    """A bad marker is refused before a memfd exists, with a fixed code and no path."""
    for bad in (None, b"bad\x00", "bad\x00path", "x" * 4097, "", "one\ntwo", "one\rtwo"):
        with pytest.raises(OSError) as caught:
            anonymous_memfd_exec(bad)
        assert caught.value.errno == errno.EINVAL
        assert caught.value.strerror == "invalid program path"
        assert caught.value.filename is None


def _pasted_sources(*functions):
    """Source of ``functions`` in order, for a hook-free descendant to exec."""
    return "\n\n".join(getsource(function) for function in functions) + "\n\n"


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux kernel exec enforcement")
def test_kernel_exec_refuses_anonymous_file(sealed_hosts, tmp_path):
    """Without the filter an executable memfd writes the marker; with it, EPERM and no marker."""
    marker = tmp_path / "unexpected-launch"
    fake = sealed_hosts.executable("codex")
    write_shell_free_fake(
        fake,
        _pasted_sources(
            memfd_abi_table, executable_memfd_flags, _bounded_program_marker,
            _native_memfd_pair, _syscall_memfd, populate_and_exec_memfd, anonymous_memfd_exec,
        )
        + "import errno\nimport sys\n"
        + f"with open({str(sealed_hosts.log)!r}, 'a', encoding='utf-8') as stream:\n"
        + "    stream.write(__file__ + '\\n')\n"
        + "try:\n"
        + "    anonymous_memfd_exec(sys.argv[1])\n"
        + "except OSError as refusal:\n"
        + "    if refusal.errno != errno.EPERM:\n"
        + "        raise\n"
        + "    print('exec denied')\n",
    )
    bare = subprocess.run([str(fake), str(marker)], capture_output=True, text=True, timeout=15)
    assert (bare.returncode, bare.stdout, bare.stderr, marker.is_file()) == (0, "", "", True), (
        bare.returncode, bare.stdout, bare.stderr,
    )
    marker.unlink()
    sealed_hosts.expect(fake)
    probe = tmp_path / "kernel-probe.py"
    probe.write_text(
        "import subprocess, sys\n"
        "subprocess.run(sys.argv[1:], check=True, timeout=15)\n",
        encoding="utf-8",
    )
    result = sealed_hosts.run_script(probe, str(fake), str(marker))
    sealed_hosts.expect(fake)
    assert not marker.exists()
    assert (result.returncode, result.stdout, result.stderr) == (0, "exec denied\n", "")


def _i386_raw_result(number, arg1, arg2, code_address):
    """Invoke ``int 0x80`` and return the raw register result, not libc errno."""
    import ctypes

    code = bytes((
        0xB8, number & 0xFF, (number >> 8) & 0xFF, (number >> 16) & 0xFF, (number >> 24) & 0xFF,
        0xBB, arg1 & 0xFF, (arg1 >> 8) & 0xFF, (arg1 >> 16) & 0xFF, (arg1 >> 24) & 0xFF,
        0xB9, arg2 & 0xFF, (arg2 >> 8) & 0xFF, (arg2 >> 16) & 0xFF, (arg2 >> 24) & 0xFF,
        0xCD, 0x80,
        0xC3,
    ))
    ctypes.memmove(code_address, code, len(code))
    return int(ctypes.CFUNCTYPE(ctypes.c_long)(code_address)())


def _compat_memfd_result(libc, abi, number, name_address):
    """Return ``(fd, errno)`` for one compat ``memfd_create``.

    ``i386`` is ``int 0x80``. ``x32`` is the native syscall instruction with
    the table's high bit set. The name pointer must already be in the low 4GB.
    """
    import ctypes
    import errno

    def attempt(flags):
        if abi == "i386":
            result = _i386_raw_result(number, name_address, flags, name_address + 64)
            if result >= 0:
                return int(result), 0
            if -4096 < result < 0:
                return -1, -result
            return -1, errno.EIO
        ctypes.set_errno(0)
        result = libc.syscall(number, ctypes.c_void_p(name_address), flags)
        if result >= 0:
            return int(result), 0
        error = ctypes.get_errno()
        return -1, errno.EIO if not error else error

    fd, error = -1, errno.EINVAL
    for flags in executable_memfd_flags():
        fd, error = attempt(flags)
        if fd >= 0 or error != errno.EINVAL:
            break
    return fd, error


def compat_memfd_exec(marker, abi):
    """Exec a memfd created with the i386 or x32 ``memfd_create`` number.

    The image is still this interpreter, started with native ``execveat``.
    ``ENOSYS`` means the kernel has no emulation for ``abi``. AArch32 cannot
    be entered from this process; that control is ``aarch32_compat_elf``.
    The marker is checked before ctypes is imported.
    """
    import errno
    import os
    import sys

    encoded = _bounded_program_marker(marker)
    if abi not in ("i386", "x32"):
        raise OSError(errno.EINVAL, "unsupported memfd syscall ABI")
    import ctypes
    machine = os.uname().machine if hasattr(os, "uname") else ""
    execveat_nr = None
    chosen = None
    for kind, host, _arch, nr, native_execveat in memfd_abi_table():
        if host != machine:
            continue
        if kind == "native":
            execveat_nr = native_execveat
        elif kind == abi:
            chosen = nr
    if execveat_nr is None or chosen is None or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise OSError(errno.EINVAL, "unsupported memfd syscall ABI")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    # x86_64 mmap is 9 and munmap is 11. 0x62 is MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT.
    page = libc.syscall(9, ctypes.c_void_p(0), 4096, 7, 0x62, -1, 0)
    if page < 0:
        error = ctypes.get_errno()
        raise OSError(errno.EIO if not error else error, "memfd denied")
    address = int(page)
    memfd = -1
    try:
        if address > 0xFFFFFFFF:
            raise OSError(errno.EIO, "memfd denied")
        ctypes.memmove(address, b"aegis\x00", 6)
        fd, error = _compat_memfd_result(libc, abi, chosen, address)
        if fd < 0:
            if error == errno.ENOSYS:
                raise OSError(errno.ENOSYS, "compat syscall unavailable")
            raise OSError(errno.EIO if not error else error, "memfd denied")
        memfd = fd
        held = memfd
        memfd = -1
        chosen_interpreter = sys.executable
        if isinstance(chosen_interpreter, bytes):
            chosen_interpreter = os.fsdecode(chosen_interpreter)
        populate_and_exec_memfd(libc, held, encoded, execveat_nr, chosen_interpreter)
    finally:
        if memfd >= 0:
            os.close(memfd)
        libc.syscall(11, ctypes.c_void_p(address), 4096)


def compat_memfd_probe(abi):
    """Return ``available`` or ``unavailable`` for one compat ``memfd_create``.

    This is the capability probe, not the launch control. ``ENOSYS`` is the
    only unavailable result. A descriptor is closed before return. Any other
    errno means the emulation ran the syscall. A signal kills the caller and
    is not turned into unavailable.
    """
    import errno
    import os

    if abi not in ("i386", "x32"):
        raise OSError(errno.EINVAL, "unsupported memfd syscall ABI")
    import ctypes

    machine = os.uname().machine if hasattr(os, "uname") else ""
    chosen = None
    for kind, host, _arch, nr, _execveat in memfd_abi_table():
        if host == machine and kind == abi:
            chosen = nr
    if chosen is None or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise OSError(errno.EINVAL, "unsupported memfd syscall ABI")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    # x86_64 mmap is 9 and munmap is 11. 0x62 is MAP_PRIVATE|MAP_ANONYMOUS|MAP_32BIT.
    page = libc.syscall(9, ctypes.c_void_p(0), 4096, 7, 0x62, -1, 0)
    if page < 0:
        error = ctypes.get_errno()
        raise OSError(errno.EIO if not error else error, "memfd denied")
    address = int(page)
    try:
        if address > 0xFFFFFFFF:
            raise OSError(errno.EIO, "memfd denied")
        ctypes.memmove(address, b"aegis\x00", 6)
        fd, error = _compat_memfd_result(libc, abi, chosen, address)
        if fd >= 0:
            os.close(fd)
            return "available"
        if error == errno.ENOSYS:
            return "unavailable"
        return "available"
    finally:
        libc.syscall(11, ctypes.c_void_p(address), 4096)


def aarch32_compat_elf():
    """Build an AArch32 ET_EXEC whose only syscall is ``memfd_create``.

    The number comes from ``memfd_abi_table``. Flags come from
    ``executable_memfd_flags``: ``MFD_EXEC`` first, and the default executable
    memfd when that returns EINVAL. A non-negative result executes ``bkpt``
    (SIGTRAP). A negative result executes ``udf`` (SIGILL). Neither path
    falls through. The image has no open, write, execveat, or exit_group, so
    a foreign-architecture filter cannot stop the child before the syscall.
    The 64-bit parent reads the signal. ENOEXEC at exec means the kernel has
    no AArch32 emulation.
    """
    import struct

    row = [item for item in memfd_abi_table() if item[0] == "aarch32"]
    if len(row) != 1:
        raise OSError(errno.EINVAL, "unsupported memfd syscall ABI")
    memfd_nr = row[0][3]
    first_flags, retry_flags = executable_memfd_flags()

    def mov_imm(rd, imm):
        if not 0 <= int(imm) <= 0xFF:
            raise OSError(errno.EINVAL, "unsupported memfd syscall ABI")
        return 0xE3A00000 | ((rd & 0xF) << 12) | int(imm)

    def movw(rd, imm):
        return 0xE3000000 | ((imm >> 12) << 16) | ((rd & 0xF) << 12) | (imm & 0xFFF)

    words = []
    labels = {}
    branches = []
    pools = []

    def emit(word):
        words.append(word)

    def label(name):
        labels[name] = len(words)

    def branch(cond, name):
        branches.append((len(words), cond, name))
        words.append(0)

    def ldr_pool(rd, slot):
        pools.append((len(words), rd, slot))
        words.append(0)

    # r0 = name, r1 = flags, r7 = memfd_create, svc. Then stop.
    ldr_pool(0, 0)
    emit(mov_imm(1, first_flags))
    emit(movw(7, memfd_nr))
    emit(0xEF000000)
    emit(0xE3500000)  # cmp r0, #0
    branch(0xA, "created")
    emit(0xE3700016)  # cmn r0, #22 EINVAL
    branch(0x1, "denied")
    ldr_pool(0, 0)
    emit(mov_imm(1, retry_flags))
    emit(movw(7, memfd_nr))
    emit(0xEF000000)
    emit(0xE3500000)
    branch(0xB, "denied")
    label("created")
    emit(0xE1200070)  # bkpt #0 -> SIGTRAP, a descriptor was returned
    branch(0xE, "created")
    label("denied")
    emit(0xE7F000F0)  # udf #0 -> SIGILL, the call returned an error
    branch(0xE, "denied")
    pool_at = len(words)
    for index, rd, slot in pools:
        immediate = ((pool_at + slot) - index - 2) * 4
        if not 0 <= immediate <= 0xFFF:
            raise OSError(errno.EIO, "invalid interpreter path")
        words[index] = 0xE59F0000 | ((rd & 0xF) << 12) | immediate
    for index, cond, name in branches:
        offset = labels[name] - index - 2
        if not -0x800000 <= offset <= 0x7FFFFF:
            raise OSError(errno.EIO, "invalid interpreter path")
        words[index] = (cond << 28) | 0x0A000000 | (offset & 0xFFFFFF)
    code = b"".join((word & 0xFFFFFFFF).to_bytes(4, "little") for word in words)
    header_size = 84
    pool = b"\x00\x00\x00\x00"
    name = b"aegis\x00"
    name_vaddr = 0x10000 + header_size + len(code) + len(pool)
    pool = name_vaddr.to_bytes(4, "little")
    body = code + pool + name
    entry = 0x10000 + header_size
    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        b"\x7fELF" + bytes([1, 1, 1]) + bytes(9),
        2, 40, 1, entry, 52, 0, 0x05000000, 52, 32, 1, 0, 0, 0,
    )
    phdr = struct.pack(
        "<IIIIIIII", 1, 0, 0x10000, 0x10000, header_size + len(body), header_size + len(body), 7, 0x1000,
    )
    return ehdr + phdr + body


def _simulate_aarch32_memfd(elf, svc_results):
    """Execute the AArch32 image until ``bkpt`` or ``udf``.

    ``svc_results`` are the successive ``memfd_create`` return values. The
    result is ``created`` or ``denied``. Any other syscall, a spin, or a
    missing result raises ``OSError``.
    """
    if elf[:4] != b"\x7fELF" or elf[4] != 1:
        raise OSError(errno.EINVAL, "invalid interpreter path")
    entry = int.from_bytes(elf[24:28], "little")
    base = 0x10000
    if entry < base or (entry - base) % 4:
        raise OSError(errno.EINVAL, "invalid interpreter path")
    words = {}
    for offset in range(0, len(elf) - 3, 4):
        words[base + offset] = int.from_bytes(elf[offset:offset + 4], "little")
    pc = entry
    r0 = 0
    r1 = None
    r7 = None
    compared = None
    calls = []
    results = list(svc_results)
    for _step in range(64):
        word = words.get(pc)
        if word is None:
            raise OSError(errno.EIO, "invalid interpreter path")
        if word == 0xEF000000:
            if r7 is None or r1 is None:
                raise OSError(errno.EIO, "memfd denied")
            calls.append((r7, r1))
            if not results:
                raise OSError(errno.EIO, "memfd denied")
            r0 = results.pop(0)
            pc += 4
            continue
        if word == 0xE1200070:
            if results:
                raise OSError(errno.EIO, "memfd denied")
            return "created", calls
        if word == 0xE7F000F0:
            if results:
                raise OSError(errno.EIO, "memfd denied")
            return "denied", calls
        if word == 0xE3500000:
            compared = "cmp0"
            pc += 4
            continue
        if word == 0xE3700016:
            compared = "cmn22"
            pc += 4
            continue
        if (word & 0xFFFFF000) == 0xE59F0000:
            literal = words.get(pc + 8 + (word & 0xFFF))
            if literal is None:
                raise OSError(errno.EIO, "invalid interpreter path")
            r0 = literal
            pc += 4
            continue
        if (word & 0xFFFFF000) == 0xE3A01000:
            r1 = word & 0xFF
            pc += 4
            continue
        if (word & 0x0FF0F000) == 0x03007000:
            r7 = ((word >> 16) & 0xF) << 12 | (word & 0xFFF)
            pc += 4
            continue
        if (word & 0x0F000000) == 0x0A000000:
            cond = word >> 28
            raw = word & 0xFFFFFF
            if raw & 0x800000:
                raw -= 0x1000000
            target = pc + 8 + raw * 4
            take = cond == 0xE
            if cond == 0xA and compared == "cmp0":
                take = r0 >= 0
            elif cond == 0xB and compared == "cmp0":
                take = r0 < 0
            elif cond == 0x1 and compared == "cmn22":
                take = r0 + 22 != 0
            elif cond == 0x0 and compared == "cmn22":
                take = r0 + 22 == 0
            elif cond != 0xE:
                raise OSError(errno.EIO, "invalid interpreter path")
            if target == pc:
                raise OSError(errno.EIO, "memfd denied")
            pc = target if take else pc + 4
            continue
        raise OSError(errno.EIO, "invalid interpreter path")
    raise OSError(errno.EIO, "memfd denied")

def _eval_seccomp(words, arch, nr):
    data = (nr & 0xFFFFFFFF).to_bytes(4, "little") + (arch & 0xFFFFFFFF).to_bytes(4, "little") + bytes(8)
    accumulator = 0
    pc = 0
    for _step in range(32):
        code, jt, jf, k = words[pc]
        if code == 0x20:
            accumulator = int.from_bytes(data[k:k + 4], "little")
            pc += 1
        elif code == 0x15:
            pc += 1 + (jt if accumulator == k else jf)
        elif code == 0x45:
            pc += 1 + (jt if accumulator & k else jf)
        elif code == 0x06:
            return k
        else:
            raise AssertionError("unexpected bpf opcode")
    raise AssertionError("seccomp program did not return")


def test_seccomp_program_checks_arch_before_number():
    """Foreign architectures and the x32 bit are refused before nr is compared."""
    allow, deny = 0x7fff0000, 0x00050001
    assert ("native", "x86_64", 0xC000003E, 319, 322) in memfd_abi_table()
    assert ("i386", "x86_64", 0x40000003, 356, 0) in memfd_abi_table()
    assert ("x32", "x86_64", 0xC000003E, 319 | 0x40000000, 0) in memfd_abi_table()
    assert ("aarch32", "aarch64", 0x40000028, 385, 387) in memfd_abi_table()
    words, nr = memfd_seccomp_words("x86_64")
    assert words[0] == (0x20, 0, 0, 4) and nr == 319
    assert _eval_seccomp(words, 0xC000003E, 39) == allow
    assert _eval_seccomp(words, 0xC000003E, 319) == deny
    assert _eval_seccomp(words, 0xC000003E, 319 | 0x40000000) == deny
    assert _eval_seccomp(words, 0xC000003E, 39 | 0x40000000) == deny
    assert _eval_seccomp(words, 0x40000003, 356) == deny
    assert _eval_seccomp(words, 0x40000003, 39) == deny
    arm_words, arm_nr = memfd_seccomp_words("aarch64")
    assert arm_nr == 279 and not any(word[0] == 0x45 for word in arm_words)
    assert arm_words[0] == (0x20, 0, 0, 4)
    assert _eval_seccomp(arm_words, 0xC00000B7, 279) == deny
    assert _eval_seccomp(arm_words, 0x40000028, 385) == deny
    assert _eval_seccomp(arm_words, 0xC00000B7, 281) == allow
    risc_words, risc_nr = memfd_seccomp_words("riscv64")
    assert risc_nr == 279
    assert _eval_seccomp(risc_words, 0xC00000F3, 279) == deny
    assert _eval_seccomp(risc_words, 0xC000003E, 319) == deny
    with pytest.raises(ValueError) as caught:
        memfd_seccomp_words("i686")
    assert str(caught.value) == "unsupported memfd syscall ABI"
    bootstrap = getsource(landlock_bootstrap)
    assert "memfd_seccomp_words(" in bootstrap
    assert "319" not in bootstrap and "0x40000000" not in bootstrap
    assert executable_memfd_flags() == (0x11, 1)


@contextmanager
def without_core_dump():
    """Drop only the core soft limit, then restore the saved pair.

    The hard ceiling stays as it was, so an unprivileged process can put the
    limit back. The AArch32 child's SIGTRAP or SIGILL must not dump a core
    and must not leave the parent pinned at a zero ceiling.
    """
    import resource

    before = resource.getrlimit(resource.RLIMIT_CORE)
    resource.setrlimit(resource.RLIMIT_CORE, (0, before[1]))
    try:
        yield
    finally:
        resource.setrlimit(resource.RLIMIT_CORE, before)


def test_without_core_dump_restores_hard_ceiling():
    """A failed body still restores the hard ceiling for the next test."""
    resource = pytest.importorskip("resource")
    before = resource.getrlimit(resource.RLIMIT_CORE)
    try:
        with without_core_dump():
            assert resource.getrlimit(resource.RLIMIT_CORE) == (0, before[1])
            raise RuntimeError("core limit probe")
    except RuntimeError as failure:
        assert str(failure) == "core limit probe"
    assert resource.getrlimit(resource.RLIMIT_CORE) == before


def aarch32_child_result(returncode):
    """Classify the AArch32 child from its exit status.

    ``SIGTRAP`` is ``bkpt`` after ``memfd_create`` returned a descriptor.
    ``SIGILL`` is ``udf`` after the call returned an error. Every other
    status, including any other signal, is ``memfd denied`` and is not an
    emulation skip.
    """
    import signal

    if returncode == -signal.SIGTRAP:
        return "created"
    if returncode == -signal.SIGILL:
        return "denied"
    raise OSError(errno.EIO, "memfd denied")


def test_aarch32_compat_elf_uses_the_abi_table():
    """The AArch32 child issues only the table's memfd_create and then stops."""
    elf = aarch32_compat_elf()
    assert elf[:4] == b"\x7fELF" and elf[4] == 1 and elf[5] == 1
    assert int.from_bytes(elf[18:20], "little") == 40
    row = [item for item in memfd_abi_table() if item[0] == "aarch32"]
    assert len(row) == 1
    _kind, _host, _arch, memfd_nr, execveat_nr = row[0]
    first_flags, retry_flags = executable_memfd_flags()

    def movw_r7(imm):
        return (0xE3000000 | ((imm >> 12) << 16) | (7 << 12) | (imm & 0xFFF)).to_bytes(4, "little")

    assert movw_r7(memfd_nr) in elf
    for other in (execveat_nr, 319, 322, 248, 6, 4):
        assert movw_r7(other) not in elf
    assert b"\x70\x00\x20\xe1" in elf and b"\xf0\x00\xf0\xe7" in elf
    assert b"exec denied\n" not in elf and b"compat unavailable\n" not in elf
    created, calls = _simulate_aarch32_memfd(elf, [3])
    assert created == "created" and calls == [(memfd_nr, first_flags)]
    denied, calls = _simulate_aarch32_memfd(elf, [-1])
    assert denied == "denied" and calls == [(memfd_nr, first_flags)]
    retried, calls = _simulate_aarch32_memfd(elf, [-22, 4])
    assert retried == "created" and calls == [(memfd_nr, first_flags), (memfd_nr, retry_flags)]
    failed, calls = _simulate_aarch32_memfd(elf, [-22, -1])
    assert failed == "denied" and calls == [(memfd_nr, first_flags), (memfd_nr, retry_flags)]


def _compat_memfd_params():
    if sys.platform != "linux" or not hasattr(os, "uname"):
        return [pytest.param("i386", marks=pytest.mark.skip(reason="requires Linux kernel exec enforcement"))]
    machine = os.uname().machine
    found = [kind for kind, host, _arch, _nr, _exec in memfd_abi_table() if kind != "native" and host == machine]
    if not found:
        return [pytest.param("i386", marks=pytest.mark.skip(reason="requires Linux kernel exec enforcement"))]
    return found


COMPAT_SYSCALL_REASON = "requires compat syscall emulation"


def _compat_capability_report(abi, directory):
    """Run the separate unsandboxed i386/x32 probe and return its stdout.

    The probe process is ``sys.executable``, not a sealed fake. Only the
    explicit words ``available`` and ``unavailable`` are results. A signal
    or any other exit fails the caller.
    """
    script = directory / "compat-capability.py"
    script.write_text(
        _pasted_sources(
            memfd_abi_table, executable_memfd_flags, _i386_raw_result,
            _compat_memfd_result, compat_memfd_probe,
        )
        + "import sys\n"
        + "status = compat_memfd_probe(sys.argv[1])\n"
        + "if status not in ('available', 'unavailable'):\n"
        + "    raise SystemExit(2)\n"
        + "print(status)\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [sys.executable, "-I", str(script), abi],
        capture_output=True, text=True, timeout=20,
    )
    assert (completed.returncode, completed.stdout) in ((0, "available\n"), (0, "unavailable\n")), (
        completed.returncode, completed.stdout,
    )
    return completed.stdout


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux kernel exec enforcement")
@pytest.mark.parametrize("abi", _compat_memfd_params())
def test_kernel_exec_refuses_compat_memfd(sealed_hosts, tmp_path, abi):
    """A non-native memfd_create is refused under the domain and writes no marker.

    i386 and x32 emulation come from a separate unsandboxed probe. The case
    skips only when that probe prints ``unavailable``. A signal from the
    probe, the unsandboxed control, or the in-domain control fails the case.
    The AArch32 child only calls memfd_create. ``ENOEXEC`` is its explicit
    unavailable result. ``SIGTRAP`` means it created an executable memfd and
    ``SIGILL`` means it did not. The 64-bit parent appends the fake path.
    """
    marker = tmp_path / "unexpected-launch"
    fake = sealed_hosts.executable("codex")
    if abi != "aarch32":
        if _compat_capability_report(abi, tmp_path) == "unavailable\n":
            pytest.skip(COMPAT_SYSCALL_REASON)
        write_shell_free_fake(
            fake,
            _pasted_sources(
                memfd_abi_table, executable_memfd_flags, _bounded_program_marker,
                populate_and_exec_memfd, _i386_raw_result, _compat_memfd_result, compat_memfd_exec,
            )
            + "import errno\nimport sys\n"
            + f"with open({str(sealed_hosts.log)!r}, 'a', encoding='utf-8') as stream:\n"
            + "    stream.write(__file__ + '\\n')\n"
            + "try:\n"
            + "    compat_memfd_exec(sys.argv[1], sys.argv[2])\n"
            + "except OSError as refusal:\n"
            + "    if refusal.errno != errno.EPERM:\n"
            + "        raise\n"
            + "    print('exec denied')\n",
        )
        command = [str(fake), str(marker), abi]
        bare = subprocess.run(command, capture_output=True, text=True, timeout=20)
        assert (bare.returncode, bare.stdout, bare.stderr, marker.is_file()) == (0, "", "", True), (
            bare.returncode, bare.stdout, bare.stderr,
        )
        marker.unlink()
        sealed_hosts.expect(fake)
        probe = tmp_path / "kernel-probe.py"
        probe.write_text(
            "import subprocess, sys\n"
            "subprocess.run(sys.argv[1:], check=True, timeout=20)\n",
            encoding="utf-8",
        )
        result = sealed_hosts.run_script(probe, *command)
        sealed_hosts.expect(fake)
        assert not marker.exists()
        assert (result.returncode, result.stdout, result.stderr) == (0, "exec denied\n", "")
        return
    fake.write_bytes(aarch32_compat_elf())
    fake.chmod(0o755)
    with without_core_dump():
        try:
            bare = subprocess.run([str(fake)], capture_output=True, text=True, timeout=20)
        except OSError as failure:
            if getattr(failure, "errno", None) == errno.ENOEXEC:
                pytest.skip(COMPAT_SYSCALL_REASON)
            raise
    assert aarch32_child_result(bare.returncode) == "created"
    assert not marker.exists() and bare.stdout == "" and bare.stderr == ""
    with sealed_hosts.log.open("a", encoding="utf-8") as stream:
        stream.write(str(fake) + "\n")
    sealed_hosts.expect(fake)
    probe = tmp_path / "kernel-probe.py"
    probe.write_text(
        "from contextlib import contextmanager\n"
        + _pasted_sources(without_core_dump, aarch32_child_result)
        + "import os\nimport subprocess\nimport sys\n"
        + "fake, marker, log = sys.argv[1], sys.argv[2], sys.argv[3]\n"
        + "if os.path.exists(marker):\n"
        + "    raise SystemExit(2)\n"
        + "with without_core_dump():\n"
        + "    try:\n"
        + "        completed = subprocess.run([fake], capture_output=True, text=True, timeout=20)\n"
        + "    except OSError:\n"
        + "        raise SystemExit(3)\n"
        + "    except subprocess.TimeoutExpired:\n"
        + "        raise SystemExit(3)\n"
        + "try:\n"
        + "    status = aarch32_child_result(completed.returncode)\n"
        + "except OSError:\n"
        + "    raise SystemExit(3)\n"
        + "if os.path.exists(marker) or status != 'denied' or completed.stdout or completed.stderr:\n"
        + "    raise SystemExit(3)\n"
        + "with open(log, 'a', encoding='utf-8') as stream:\n"
        + "    stream.write(fake + '\\n')\n"
        + "print('exec denied')\n",
        encoding="utf-8",
    )
    result = sealed_hosts.run_script(
        probe, str(fake), str(marker), str(sealed_hosts.log), timeout=25,
    )
    sealed_hosts.expect(fake)
    assert not marker.exists()
    assert (result.returncode, result.stdout, result.stderr) == (0, "exec denied\n", "")


def test_fork_exec_arity_matches_interpreter():
    """The helper's positional count matches this interpreter's own call.

    The 3.9-3.13 widths are fixed by the CPython citations on
    ``fork_exec_arguments``. Only the comparison with ``inspect.getsource``
    is skipped when that source cannot be read. The kernel case does not use
    this skip.
    """
    cited = {(3, 9): 21, (3, 10): 21, (3, 11): 23, (3, 12): 23, (3, 13): 23}
    for version, width in cited.items():
        assert len(fork_exec_arguments("program", b"program", 4, 5, version)) == width
    for version in ((3, 8), (3, 14)):
        with pytest.raises(OSError) as caught:
            fork_exec_arguments("program", b"program", 4, 5, version)
        assert caught.value.errno == errno.EINVAL
        assert caught.value.strerror == "unsupported fork_exec arity"
        assert caught.value.filename is None
    try:
        source = getsource(subprocess)
    except (OSError, TypeError):
        pytest.skip("subprocess source unavailable")
    counts = subprocess_fork_exec_positional_count(source)
    assert counts and len(set(counts)) == 1
    assert len(fork_exec_arguments("program", b"program", 4, 5)) == counts[0]


def unavailable_landlock_bootstrap():
    raise SystemExit("launch boundary unavailable")


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux kernel exec enforcement")
def test_kernel_exec_requires_active_domain(sealed_hosts, tmp_path, monkeypatch):
    monkeypatch.setattr("tests.integration.test_team_conformance.landlock_bootstrap", unavailable_landlock_bootstrap)
    marker = tmp_path / "unexpected-target"
    probe = tmp_path / "unavailable.py"
    probe.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n", encoding="utf-8")
    with pytest.raises(pytest.fail.Exception, match="^launch boundary unavailable$"):
        sealed_hosts.run_script(probe)
    assert not marker.exists()
    assert sealed_hosts.kernel_abi is None
