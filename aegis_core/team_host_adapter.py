"""Host-neutral candidate adapter contract; standard library only, no host I/O."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, runtime_checkable

__all__ = ["HostAdapter", "HostAdapterError", "copy_environment"]

_ENV_ACTION = "Supply a readable Mapping of environment names to bounded strings (256 entries, 131072 characters total)."


class HostAdapterError(ValueError):
    """Stable refusal, with no host output, path, credentials or input echoed."""

    def __init__(self, reason, next_action, *, exit_code=1):
        super().__init__(reason)
        self.refused = True
        self.reason = reason
        self.next_action = next_action
        self.exit_code = exit_code

    def as_dict(self):
        return {"refused": True, "reason": self.reason,
                "next_action": self.next_action, "exit_code": self.exit_code}


def copy_environment(value):
    """Snapshot a Mapping within limits; mapping-read failures are usage refusals.

    A custom Mapping is an input boundary. Bound both its declared length and
    observed iteration, and never forward its exception text to the caller.
    """
    if not isinstance(value, Mapping):
        raise HostAdapterError("invalid_host_environment", _ENV_ACTION, exit_code=2)
    try:
        if len(value) > 256:
            raise HostAdapterError("invalid_host_environment", _ENV_ACTION, exit_code=2)
        result, total = {}, 0
        for index, (key, text) in enumerate(value.items()):
            if (index >= 256 or type(key) is not str or len(key) > 256 or
                    not key or "=" in key or "\x00" in key or type(text) is not str or
                    len(text) > 32768 or "\x00" in text):
                raise HostAdapterError("invalid_host_environment", _ENV_ACTION, exit_code=2)
            total += len(key) + len(text)
            if total > 131072:
                raise HostAdapterError("invalid_host_environment", _ENV_ACTION, exit_code=2)
            result[key] = text
        return result
    except HostAdapterError:
        raise
    except Exception:
        # Accessing a caller-supplied Mapping can fail independently of its
        # shape. This is a documented refusal, with no fallback or retry.
        raise HostAdapterError("invalid_host_environment", _ENV_ACTION, exit_code=2) from None


@runtime_checkable
class HostAdapter(Protocol):
    """Pure candidate interface. No method starts a process or reads host files.

    Authentication returns a private child environment and settings, never a
    display payload. Transcript parts are relative locator data, not permission
    to open paths. Callers must use a trusted descriptor-rooted storage boundary.
    Candidate configuration and ownership evidence grant no launch authority.
    Constructors receive a scrub_environment callback returning a private
    bounded snapshot and a scrubbed child; adapters never import the service.
    """

    def describe(self): ...
    def authentication(self, mode, environment, *, session=None): ...
    def model_options(self, bindings, model_class, intent): ...
    def session_verdict(self, argv, session, *, argv_boundaries="proven"): ...
    def child_environment(self, environment, session, *, auth_mode=None): ...
    def transcript_parts(self, session): ...
    def require_launchable(self): ...
