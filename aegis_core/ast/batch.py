"""Bounded NDJSON transport for first-party protocol-v2 AST drivers."""
from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import tempfile
import threading
from typing import Any, Optional

from aegis_core.ast.driver_errors import ASTDriverError, ASTDriverTimeoutError
from aegis_core.ast.schema import NormalizedAST

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
_CAPABILITIES = frozenset({'allow_comments', 'args', 'decorators', 'shadowed', 'test_module'})


class BatchDriver:
    """One sequential, lazy process. A protocol defect permanently poisons the session."""

    def __init__(self, argv: tuple[str, ...], *, label: str, timeout: float = 3.0):
        if not argv or not os.path.isabs(argv[0]) or timeout <= 0:
            raise ValueError('a batch driver needs an absolute executable and positive timeout')
        self.argv, self.label, self.timeout = argv, label, timeout
        self._proc: Optional[subprocess.Popen] = None
        self._windows_job: Any = None
        self._scratch: Any = None
        self._failure: Optional[ASTDriverError] = None
        self._closed = False
        self._next_id = 0
        self._responses: queue.Queue = queue.Queue(maxsize=1)
        self._stopped = threading.Event()
        self._stderr = bytearray()
        self._threads: list[threading.Thread] = []
        self.capabilities: list[str] = []
        self.languages: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    def _offer(self, item: Any) -> None:
        while not self._stopped.is_set():
            try:
                self._responses.put(item, timeout=0.05)
                return
            except queue.Full:
                continue

    def _read_stdout(self) -> None:
        try:
            while not self._stopped.is_set():
                line = self._proc.stdout.readline(MAX_RESPONSE_BYTES + 2)
                if not line:
                    self._offer(ASTDriverError('driver exited before its response'))
                    return
                if len(line) > MAX_RESPONSE_BYTES or not line.endswith(b'\n'):
                    self._offer(ASTDriverError('response exceeds 8 MiB or lacks a newline'))
                    return
                self._offer(line)
        except (OSError, ValueError) as exc:
            self._offer(ASTDriverError(f'cannot read driver response: {exc}'))

    def _read_stderr(self) -> None:
        try:
            while not self._stopped.is_set():
                chunk = self._proc.stderr.read(8192)
                if not chunk:
                    return
                remaining = MAX_STDERR_BYTES - len(self._stderr)
                self._stderr.extend(chunk[:max(0, remaining)])
        except (OSError, ValueError):
            return  # diagnostics only; stdout and the process state decide success

    def _start(self) -> None:
        self._scratch = tempfile.TemporaryDirectory(prefix='aegis-ast-v2-')
        neutral = self._scratch.name
        env = {'HOME': neutral, 'TMPDIR': neutral, 'LC_ALL': 'C'}
        if os.name == 'nt':
            from aegis_core.ast.windows_job import CREATE_SUSPENDED, WindowsJob

            env.update({k: os.environ[k] for k in ('SystemRoot', 'WINDIR') if k in os.environ})
            env.update({'TEMP': neutral, 'TMP': neutral, 'USERPROFILE': neutral})
            self._windows_job = WindowsJob()
            flags = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED}
        else:
            flags = {'start_new_session': True}
        self._proc = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, cwd=neutral, env=env, **flags)
        if self._windows_job is not None:
            self._windows_job.assign_and_resume(self._proc.pid)
        for reader in (self._read_stdout, self._read_stderr):
            thread = threading.Thread(target=reader, daemon=True)
            self._threads.append(thread)
            thread.start()
        hello = self._exchange({'aegis_ast': 2, 'op': 'hello'})
        caps = hello.get('capabilities')
        if (type(hello.get('aegis_ast')) is not int or hello['aegis_ast'] != 2 or hello.get('op') != 'hello'
                or not isinstance(hello.get('driver'), str) or not hello['driver']
                or not isinstance(hello.get('driver_version'), str) or not hello['driver_version']
                or not isinstance(hello.get('languages'), list) or not hello['languages']
                or not all(isinstance(x, str) and x for x in hello['languages'])
                or not isinstance(caps, list) or not all(isinstance(x, str) and x in _CAPABILITIES for x in caps)
                or caps != sorted(set(caps))):
            raise ASTDriverError('invalid protocol-v2 hello')
        self.capabilities = caps
        self.languages = hello['languages']

    def _exchange(self, request: dict) -> dict:
        try:
            self._proc.stdin.write(json.dumps(request).encode('utf-8') + b'\n')
            self._proc.stdin.flush()
            line = self._responses.get(timeout=self.timeout)
        except queue.Empty as exc:
            raise ASTDriverTimeoutError(f'timed out after {self.timeout}s waiting for {request["op"]}') from exc
        if isinstance(line, Exception):
            raise line
        try:
            response = json.loads(line)
        except (ValueError, UnicodeError) as exc:
            raise ASTDriverError('invalid response JSON') from exc
        if not isinstance(response, dict):
            raise ASTDriverError('response JSON must be an object')
        return response

    def parse(self, path: Path) -> NormalizedAST:
        if self._failure is not None:
            raise self._failure
        if self._closed:
            raise ASTDriverError(f"AST driver '{self.label}' session is closed")
        try:
            if self._proc is None:
                self._start()
            self._next_id += 1
            response = self._exchange({'op': 'parse', 'id': self._next_id, 'path': str(path)})
            if (response.get('op') != 'parse' or type(response.get('id')) is not int
                    or response['id'] != self._next_id or type(response.get('ok')) is not bool):
                raise ASTDriverError('invalid parse response or mismatched id')
            if not response['ok']:
                error = response.get('error')
                if (not isinstance(error, dict) or error.get('kind') not in ('syntax', 'limit', 'io')
                        or not isinstance(error.get('message'), str)):
                    raise ASTDriverError('invalid parse error response')
                line = f" at line {error['line']}" if type(error.get('line')) is int else ''
                valid_error = ASTDriverError(f"AST driver '{self.label}' {error['kind']}{line}: {error['message']}")
            else:
                tree = NormalizedAST.from_dict(response['ast'])
                if tree.file_path != str(path):
                    raise ASTDriverError('parse AST path does not match request')
                if tree.language not in self.languages or tree.version != '1.0':
                    raise ASTDriverError('parse AST language or schema version does not match hello')
                object.__setattr__(tree, 'metadata', {**tree.metadata, 'capabilities': self.capabilities})
                return tree
        except Exception as exc:
            error_type = ASTDriverTimeoutError if isinstance(exc, ASTDriverTimeoutError) else ASTDriverError
            self._failure = error_type(str(exc))
            try:
                self.close()
            except (OSError, subprocess.SubprocessError, ASTDriverError) as cleanup:
                exc = ASTDriverError(f'{exc}; cleanup failed: {cleanup}')
            detail = self._stderr.decode('utf-8', 'replace').strip()
            self._failure = error_type(f"AST driver '{self.label}': {exc}" + (f'; {detail}' if detail else ''))
            raise self._failure from exc
        raise valid_error  # a well-formed file error leaves the session usable

    def _terminate_group(self, proc: subprocess.Popen) -> None:
        if self._windows_job is not None:
            self._windows_job.close()
            self._windows_job = None
        elif os.name != 'nt':
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        proc = self._proc
        shutdown_failure = None
        failures: list[Exception] = []
        try:
            if proc is not None:
                try:
                    try:
                        proc.stdin.close()
                    except (OSError, ValueError) as exc:
                        failures.append(exc)
                    if self._failure is None:
                        try:
                            proc.wait(timeout=self.timeout)
                        except subprocess.TimeoutExpired:
                            shutdown_failure = ASTDriverTimeoutError(
                                f"AST driver '{self.label}' timed out during shutdown")
                    self._terminate_group(proc)
                except (OSError, subprocess.SubprocessError, ASTDriverError) as exc:
                    failures.append(exc)
                finally:
                    try:
                        if proc.poll() is None:
                            proc.kill()  # retain any group-cleanup error while reaping the root
                        proc.wait(timeout=3)
                    except (OSError, subprocess.SubprocessError) as exc:
                        failures.append(exc)
        finally:
            # The job outlives the root and must also close if Popen/startup failed.
            if self._windows_job is not None:
                try:
                    self._windows_job.close()
                except OSError as exc:
                    failures.append(exc)
            self._stopped.set()
            for thread in self._threads:
                thread.join(timeout=0.5)
            readers_alive = any(thread.is_alive() for thread in self._threads)
            if readers_alive:
                failures.append(ASTDriverError('driver reader did not stop'))
            if proc is not None:
                for stream in (proc.stdin, proc.stdout, proc.stderr):
                    try:
                        # A failed OS kill must not leave close waiting on a reader's buffer lock.
                        if readers_alive and stream is not proc.stdin:
                            stream.raw.close()
                        else:
                            stream.close()
                    except (OSError, ValueError) as exc:
                        failures.append(exc)
            if self._scratch is not None:
                try:
                    self._scratch.cleanup()
                except OSError as exc:
                    failures.append(exc)
        if failures:
            detail = '; '.join(f'{type(exc).__name__}: {exc}' for exc in failures)
            prior = f'{shutdown_failure}; ' if shutdown_failure is not None else ''
            self._failure = ASTDriverError(f"AST driver '{self.label}': {prior}cleanup failed: {detail}")
            raise self._failure from failures[0]
        if self._failure is None and proc is not None:
            if shutdown_failure is None and proc.returncode != 0:
                shutdown_failure = ASTDriverError(f"AST driver '{self.label}' exited with exit code {proc.returncode}")
            if shutdown_failure is not None:
                self._failure = shutdown_failure
                raise shutdown_failure
