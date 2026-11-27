"""Isolated process for witnessing real review-copy descriptor exhaustion."""
from __future__ import annotations

from contextlib import ExitStack
import errno
from functools import partial
import math
import os
from pathlib import Path
import select
import shutil
import stat
import subprocess
import sys
from time import monotonic
from types import SimpleNamespace
from unittest.mock import patch

if __name__ == "__main__":
    # The isolated worker resolves product imports from this checkout.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import aegis_core.team_review_copy as review_copy


class GitProcess:
    """Read caller-sized chunks and wait within one Git child deadline."""

    def __init__(self, popen, timeout, deadline):
        self.popen = popen
        self.timeout = timeout
        self.deadline = deadline
        self.closed = False

    def _remaining(self):
        remaining = self.deadline - monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(self.popen.args, self.timeout)
        return remaining

    def close_stdin(self):
        stream = self.popen.stdin
        if stream is not None and not stream.closed:
            stream.close()

    def read(self, count):
        fd = self.popen.stdout.fileno()
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        if not poller.poll(math.ceil(self._remaining() * 1000)):
            raise subprocess.TimeoutExpired(self.popen.args, self.timeout)
        self._remaining()
        return os.read(fd, count)

    def wait(self, timeout):
        status = self.popen.wait(timeout=min(timeout, self._remaining()))
        self._remaining()
        return status

    def kill(self):
        if self.popen.poll() is None:
            self.popen.kill()

    def close(self):
        if self.closed:
            return
        self.closed = True
        with ExitStack() as cleanup:
            cleanup.callback(self.popen.wait, timeout=5)
            cleanup.callback(self.kill)
            cleanup.callback(self.popen.stdout.close)
            self.close_stdin()


def real_spawn(repository, args, env, timeout):
    deadline = monotonic() + timeout
    popen = subprocess.Popen(
        args, env=env, cwd=f"/proc/{os.getpid()}/fd/{repository}",
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0,
    )
    return GitProcess(popen, timeout, deadline)


def require(condition, detail):
    if not condition:
        raise AssertionError(detail)


def prepare_verified(repo, base, candidate, out, **options):
    status, result = review_copy.prepare(repo, base, candidate, out, **options)
    require(status == 0, result)
    digest = result.get("manifest_sha256")
    require(type(digest) is str, "prepare did not return a manifest digest")
    status, verified = review_copy.verify(out, expect_manifest=digest)
    require(status == 0 and verified.get("ok") is True, verified)
    return digest


def review_record(identity, records):
    return Path(records) / f"{identity.st_dev:x}-{identity.st_ino:x}"


def open_descriptors():
    open_fds = {}
    for name in os.listdir("/proc/self/fd"):
        try:
            open_fds[int(name)] = os.readlink("/proc/self/fd/" + name)
        except FileNotFoundError:
            # listdir's own descriptor is gone by the time we inspect its entry.
            continue
    return open_fds


class DescriptorPressure:
    def __init__(self, phase, parent, review_namespace, resource, held):
        self.phase = phase
        self.parent = parent
        self.review_namespace = review_namespace
        self.resource = resource
        self.held = held
        self.stage_fd = None
        self.stage_name = None
        self.witness = None

    def open(self, name, flags, *args, dir_fd=None):
        # The product open helper is one frame back and its operation is two.
        # Match that operation so a similarly named path in preflight cannot qualify.
        operation = sys._getframe(2)
        site = operation.f_code.co_name if operation.f_globals is self.review_namespace else None
        phase = None
        if (site == "_publish" and dir_fd is not None and flags & os.O_DIRECTORY
                and name.startswith(".pending-")
                and os.path.samestat(os.fstat(dir_fd), self.parent.stat())):
            phase = "stage"
            self.stage_name = name
        elif dir_fd is not None and dir_fd == self.stage_fd:
            if site == "_scaffold_sha" and name == ".git" and flags & os.O_DIRECTORY:
                phase = "scaffold"
            elif (site == "_lock_tree" and name == "manifest.json"
                  and flags & (os.O_ACCMODE | os.O_CREAT) == os.O_RDONLY):
                phase = "lock"

        if phase == self.phase and self.witness is None:
            return self.fail_open(phase, name, flags, args, dir_fd)
        fd = os.open(name, flags, *args, dir_fd=dir_fd)
        if phase == "stage":
            self.stage_fd = fd
        return fd

    def fail_open(self, phase, name, flags, args, dir_fd):
        info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        expected_type = stat.S_IFREG if phase == "lock" else stat.S_IFDIR
        require(stat.S_IFMT(info.st_mode) == expected_type, "selected open has the wrong target type")
        live = open_descriptors()
        resource = self.resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        limit = max(live) + 2
        if soft != resource.RLIM_INFINITY:
            limit = min(limit, soft)
        free = limit - len(live)
        require(max(live) < limit and free > 0, "no room to arm descriptor pressure")
        # Leave the borrowed descriptors open until prepare has attempted rollback.
        self.held.callback(resource.setrlimit, resource.RLIMIT_NOFILE, (soft, hard))
        resource.setrlimit(resource.RLIMIT_NOFILE, (limit, hard))
        for _ in range(free):
            self.held.callback(os.close, os.open(os.devnull, os.O_RDONLY))
        try:
            fd = os.open(name, flags, *args, dir_fd=dir_fd)
        except OSError as error:
            self.witness = (phase, error.errno)
            if error.errno == errno.EMFILE:
                wait_for_peer(b"R" + os.fsencode(self.stage_name))
            raise
        os.close(fd)
        raise AssertionError("selected open unexpectedly succeeded at the descriptor limit")


def wait_for_peer(checkpoint):
    os.write(1, checkpoint)
    ready, _, _ = select.select([0], [], [], 30)
    require(bool(ready), "peer did not release the worker")
    reply = os.read(0, 1)
    require(reply == b"G", "peer did not acknowledge the checkpoint")


def run(phase, repo, base, candidate, out, records):
    import resource

    from aegis_core.team_git import object_read_argv, object_read_env
    from aegis_core.team_host_registry import child_environment

    spawn = partial(real_spawn)
    spawn.executable = shutil.which("git")
    options = dict(object_read_argv=object_read_argv, object_read_env=object_read_env,
                   child_environment=child_environment, git_spawn=spawn, preparation_dir=records)
    baseline = open_descriptors()
    require(baseline.keys() == {0, 1, 2}, "worker did not start with only standard I/O")
    limits = resource.getrlimit(resource.RLIMIT_NOFILE)
    destination = Path(out)
    with ExitStack() as held:
        pressure = DescriptorPressure(phase, destination.parent, vars(review_copy), resource, held)
        proxy = SimpleNamespace(**{**vars(os), "open": pressure.open,
                                   "supports_dir_fd": {*os.supports_dir_fd, pressure.open}})
        with patch.object(review_copy, "os", proxy):
            refused = review_copy.prepare(repo, base, candidate, out, **options)

    require(pressure.witness == (phase, errno.EMFILE), ("missing phase witness", pressure.witness, refused))
    require(refused == (2, {
        "reason": "filesystem",
        "code": "filesystem",
        "next_action": "Retry when the output filesystem accepts the copy.",
    }), refused)
    require(resource.getrlimit(resource.RLIMIT_NOFILE) == limits, "worker descriptor limit was not restored")
    require(open_descriptors() == baseline, "descriptor imbalance after rollback")
    wait_for_peer(b"B")

    prepare_verified(repo, base, candidate, out, **options)
    content = (destination / "candidate" / "src" / "app.py").read_bytes()
    require(content == b"value = 2\n", "retry exported unexpected content")
    wait_for_peer(b"P")
    removed = review_copy.remove(out, preparation_dir=records)
    require(removed == (0, {"removed": out}), removed)
    require(open_descriptors() == baseline, "descriptor imbalance after retry removal")


if __name__ == "__main__":
    run(*sys.argv[1:])
