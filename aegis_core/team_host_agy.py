"""Antigravity candidate adapter, with no filesystem, network or process I/O.

Threat model: model inputs and editable files are hostile; the owner UID and
the installed registry are trusted. Same-UID rewriting of owner state is outside
this contract. Candidate metadata never qualifies a host or enables any role.

Selector evidence: installed agy --help (2026-11-12): --conversation ID,
--continue/-c, --print/-p/--prompt and the value/flag catalog below. Authentication
matches the build's agy-team launcher: SSO strips both API keys; token explicitly
sets modelProvider=gemini and requires GEMINI_API_KEY. No auto-update suppression
or native child marker has been verified, so launch admission always refuses.
"""
from __future__ import annotations

import re

from aegis_core import model_select
from aegis_core.hosts import get
from aegis_core.team_host_adapter import HostAdapterError

__all__ = ["Adapter"]

_SESSION = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_AUTH_ACTION = "Choose explicit sso or token/api authentication; configure the selected mode without provider fallback."
_SESSION_ACTION = "Supply a canonical session UUID and proven complete argv atoms."
_MODEL_ACTION = "Select a supported level from this host's model registry; probe and qualify it before launch."
_VALUES = {"--conversation": "--conversation", "--model": "--model", "--effort": "--effort",
           "--output-format": "--output-format", "--input-format": "--input-format",
           "--mode": "--mode", "--print-timeout": "--print-timeout", "--settings": "--settings",
           "--agent": "--agent", "--log-file": "--log-file", "--json-schema": "--json-schema",
           "--add-dir": "--add-dir", "--print": "--print", "-p": "--print", "--prompt": "--print"}
_FLAGS = {"--sandbox", "--disable-slash-commands"}
_PROMPTS = {"--print"}


def _session(value):
    if type(value) is not str or len(value) != 36 or _SESSION.fullmatch(value) is None:
        raise HostAdapterError("invalid_host_session", _SESSION_ACTION, exit_code=2)
    return value


def _arguments(argv):
    if type(argv) not in (list, tuple) or not 1 <= len(argv) <= 128:
        return False
    total = 0
    for atom in argv:
        if type(atom) is not str or len(atom) > 32768 or not atom or "\x00" in atom:
            return False
        total += len(atom)
        if total > 131072:
            return False
    return True


def _selection(arguments, session):
    seen, selected, index = set(), None, 0
    while index < len(arguments):
        word, separator, value = arguments[index].partition("=")
        if word in _FLAGS and not separator:
            option = word
        elif word in _VALUES:
            option = _VALUES[word]
            if not separator:
                index += 1
                if index == len(arguments):
                    return "HOLD"
                value = arguments[index]
            # Help does not document attached dash-leading prompts. Refuse them
            # too; a split selector/continue atom must never become a value.
            if not value or value.startswith("-") or (option not in _PROMPTS and
                                                      any(c in value for c in "\r\n")):
                return "HOLD"
            if option == "--conversation":
                if len(value) != 36 or _SESSION.fullmatch(value) is None:
                    return "HOLD"
                selected = value
        else:
            # Continue, project switches, remote modes, unknown options and bare
            # operands cannot establish ownership of a named local conversation.
            return "HOLD"
        if option in seen and option != "--add-dir":
            return "HOLD"
        seen.add(option)
        index += 1
    if selected is None:
        return "NOT_OWNED" if seen else "HOLD"
    return "OWNED" if selected == session else "NOT_OWNED"


def _basename(program):
    name = program.replace("\\", "/").rsplit("/", 1)[-1]
    return name.lower() if name.lower().endswith(".exe") else name


def _host_arguments(argv):
    index = 0
    if _basename(argv[0]) in ("env", "env.exe"):
        index = 1
        while index < len(argv) and _ASSIGNMENT.match(argv[index]):
            index += 1
        # Match the strict parity grammar: env options and an absent program
        # are indeterminate, never proof that this is a different session.
        if index == len(argv) or argv[index].startswith("-"):
            return False
    if _basename(argv[index]) not in ("agy", "agy.exe"):
        return None
    return argv[index + 1:]


class Adapter:
    """Stateless candidate configuration; no admission, auth or isolation claims."""

    def __init__(self, *, scrub_environment):
        self._scrub_environment = scrub_environment

    def describe(self):
        return {"host": "antigravity", "binary": "agy", "family": "google",
                "auth_modes": ["sso", "token", "api"], "qualification": "pending",
                "auto_update": {"verified": False, "control": None},
                "native_session_marker": None,
                "session_markers": list(get("antigravity").session_markers),
                "transcript_location": "~/.gemini/antigravity/brain/{session}/transcript.jsonl",
                "transcript_evidence": "hook event contract; native admission probe pending",
                "billing_variables": list(get("antigravity").billing_variables)}

    def authentication(self, mode, environment, *, session=None):
        if type(mode) is not str or mode not in ("sso", "token", "api"):
            raise HostAdapterError("invalid_host_auth", _AUTH_ACTION, exit_code=2)
        if session is not None:
            _session(session)
        source, child = self._scrub_environment(environment)
        key = None
        if mode != "sso":
            key = source.get("GEMINI_API_KEY")
            if (type(key) is not str or not 1 <= len(key) <= 4096 or
                    any(character.isspace() for character in key)):
                raise HostAdapterError("host_auth_unavailable", _AUTH_ACTION)
        settings = {}
        if mode != "sso":
            child["GEMINI_API_KEY"] = key
            settings = {"modelProvider": "gemini"}
        if session is not None:
            child.update(AEGIS_TEAM_HOST="antigravity", AEGIS_TEAM_SESSION=session)
        return {"environment": child, "settings": settings}

    def model_options(self, bindings, model_class, intent):
        if (type(model_class) is not str or len(model_class) > 64 or
                type(intent) is not str or len(intent) > 32):
            raise HostAdapterError("host_model_unavailable", _MODEL_ACTION, exit_code=2)
        if type(bindings) is not dict:
            raise HostAdapterError("invalid_host_bindings", _MODEL_ACTION, exit_code=2)
        try:
            _, rows = model_select.validate_bindings(bindings)
        except model_select.ModelSelectionError:
            raise HostAdapterError("invalid_host_bindings", _MODEL_ACTION, exit_code=2) from None
        row = rows.get(("antigravity", model_class))
        level = row["levels"].get(intent) if row is not None else None
        if level is None:
            raise HostAdapterError("host_model_unavailable", _MODEL_ACTION, exit_code=2)
        if row["admission"][intent] == "rejected":
            raise HostAdapterError("host_model_unavailable", _MODEL_ACTION)
        model, effort = row["model"], level
        if row.get("effort_encoding", "flag") == "model_suffix":
            model, effort = model + "-" + level, None
        return {"model": model, "effort": effort, "admission": row["admission"][intent],
                "host_status": row.get("host_status", "selectable")}

    def session_verdict(self, argv, session, *, argv_boundaries="proven"):
        try:
            _session(session)
        except HostAdapterError:
            return "HOLD"
        if argv_boundaries != "proven" or not _arguments(argv):
            return "HOLD"
        arguments = _host_arguments(argv)
        if arguments is False:
            return "HOLD"
        if arguments is None:
            return "NOT_OWNED"
        return _selection(arguments, session)

    def child_environment(self, environment, session, *, auth_mode=None):
        _session(session)
        if auth_mode is not None:
            return self.authentication(auth_mode, environment, session=session)["environment"]
        _, child = self._scrub_environment(environment)
        child.update(AEGIS_TEAM_HOST="antigravity", AEGIS_TEAM_SESSION=session)
        return child

    def transcript_parts(self, session):
        # Locator data only. A future reader must open by descriptor from its
        # trusted home; no exists/stat/glob followed by a path reopen is safe.
        return (".gemini", "antigravity", "brain", _session(session), "transcript.jsonl")

    def require_launchable(self):
        raise HostAdapterError("host_runtime_unqualified",
                               "Verify no-auto-update and native session controls in an admission probe, "
                               "then qualify the host and promote each role before enabling launch.")
