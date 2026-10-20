"""A fake ``subprocess.Popen`` for code that spawns through Popen and kills the process group
with ``aegis_core.checkrun.kill_group``: no process is started and nothing is signalled.

``install_fake_popen`` returns the spawn records, one dict per Popen call: ``args``, ``kwargs``,
``timeouts`` (each ``communicate`` timeout) and ``killed`` (kill_group calls on it).
"""
from __future__ import annotations

import subprocess
from typing import Any, Dict, List, Optional

from aegis_core import checkrun


def install_fake_popen(monkeypatch, returncode: int = 0, stdout: str = "", stderr: str = "", hang: bool = False,
                       spawn_error: Optional[BaseException] = None) -> List[Dict[str, Any]]:
    """Patch Popen and kill_group. ``hang``: communicate with a timeout raises TimeoutExpired
    (without one, as after a kill, it returns empty output). ``spawn_error`` is raised by Popen."""
    spawns: List[Dict[str, Any]] = []

    class _FakePopen:
        def __init__(self, args: Any, **kwargs: Any) -> None:
            if spawn_error is not None:
                raise spawn_error
            self.args = list(args)
            self.pid = 40000 + len(spawns)
            self.returncode: Optional[int] = None
            self.record: Dict[str, Any] = {"args": self.args, "kwargs": kwargs, "timeouts": [], "killed": 0}
            spawns.append(self.record)

        def communicate(self, input: Any = None, timeout: Optional[float] = None):
            self.record["timeouts"].append(timeout)
            if hang and timeout is not None:
                raise subprocess.TimeoutExpired(self.args, timeout)
            self.returncode = -9 if hang else returncode
            return ("", "") if hang else (stdout, stderr)

        def poll(self) -> Optional[int]:
            return self.returncode

        def wait(self, timeout: Optional[float] = None) -> int:
            self.returncode = -9 if self.returncode is None else self.returncode
            return self.returncode

    def kill_group(proc: Any) -> None:
        proc.record["killed"] += 1

    monkeypatch.setattr(subprocess, "Popen", _FakePopen)
    monkeypatch.setattr(checkrun, "kill_group", kill_group)
    return spawns
