"""Protected decision service over the fixed H/N1 route and strict data boundaries.

H owns invocation authentication and completion; N1 owns the canonical journal.
The pure validation/projection functions do not authenticate or commit anything.
"""
import re

from tools.hierarchy_host_authority import HostAuthorityError, HostSession


__all__ = ["validate_command", "project_commit_result", "CanonicalDecisionBackend", "DecisionService"]

_SLUG = re.compile(r"[a-z0-9][a-z0-9_-]{0,79}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_COMMAND_FIELDS = frozenset({"event_id", "request_id", "request_sha256", "decision", "reason"})
_RESULT_FIELDS = frozenset({"schema", "state", "effect", "code", "reason", "event_id",
                            "request_id", "request_sha256", "receipt", "native_qualified"})
_RECEIPT_FIELDS = frozenset({"event_id", "sequence", "event_sha256", "execution_enabled"})
_ERROR_REASONS = {
    "INVALID_DECISION_INPUT": "invalid decision command",
    "HOST_AUTHORITY_UNAVAILABLE": "protected host authority is unavailable",
    "UNAUTHORIZED_ROLE": "decision requires a current ROOT HostInvocation",
    "STALE_INVOCATION": "decision invocation is stale",
    "STALE_GENERATION_OR_CUSTODY": "current canonical generation or custody changed",
    "SOURCE_MISMATCH": "protected canonical source binding mismatch",
    "REQUEST_HASH_MISMATCH": "request sha256 mismatch",
    "UNKNOWN_REQUEST": "unknown request id",
    "BOUNDED_AUTHORITY_EXPIRED": "bounded authority expired",
    "REPLAY_CONFLICT": "event id conflicts with different decision payload",
    "DECISION_CONFLICT": "decision requires an authority request and a valid first approve/deny or approve-to-deny transition",
    "CAP_REACHED": "actor cumulative active cap reached",
    "CANONICAL_WRITER_BUSY": "mailbox writer is busy; inspect an abandoned lock before retrying",
    "PUBLICATION_UNKNOWN": "canonical decision publication is unresolved",
}
_SUCCESS = {
    "recorded": ("canonical_decision", "canonical decision recorded"),
    "recovered": ("none", "original canonical receipt recovered"),
}
_HOST_ERRORS = {
    "STALE_INVOCATION": "STALE_INVOCATION",
    "HOST_CALL_CONFLICT": "STALE_INVOCATION",
    "ROLE_OPERATION_FORBIDDEN": "UNAUTHORIZED_ROLE",
    "CANONICAL_CORRELATION_MISMATCH": "SOURCE_MISMATCH",
    "CANONICAL_API_UNAVAILABLE": "HOST_AUTHORITY_UNAVAILABLE",
    "UNSUPPORTED_HOST": "HOST_AUTHORITY_UNAVAILABLE",
    "UNPROTECTED_DEPLOYMENT": "HOST_AUTHORITY_UNAVAILABLE",
    "HOST_PROFILE_UNQUALIFIED": "HOST_AUTHORITY_UNAVAILABLE",
    "HOST_PROTOCOL_ERROR": "STALE_INVOCATION",
    "HOST_PROTOCOL_TIMEOUT": "STALE_INVOCATION",
    "PROVIDER_OUTCOME_UNKNOWN": "PUBLICATION_UNKNOWN",
}


def _plain_fields(value, fields):
    # Check keys before set comparisons, which could invoke subclass methods.
    return (type(value) is dict and all(type(key) is str for key in value)
            and value.keys() == fields)


def _slug(value):
    return type(value) is str and _SLUG.fullmatch(value) is not None


def _sha256(value):
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _valid_command(command):
    if not _plain_fields(command, _COMMAND_FIELDS):
        return False
    if any(type(value) is not str for value in command.values()):
        return False
    return (_slug(command["event_id"]) and _slug(command["request_id"])
            and _sha256(command["request_sha256"])
            and command["decision"] in ("approve", "deny")
            and 0 < len(command["reason"]) <= 1024 and "\0" not in command["reason"])


def validate_command(command):
    """Return an independent exact five-field copy, or reject inert input.

    Whitespace and Unicode reason text are preserved. No normalization,
    coercion, host lookup, canonical access or authority grant occurs.
    """
    if not _valid_command(command):
        raise ValueError("invalid decision command")
    return dict(command)


def _correlations(command):
    validators = {"event_id": _slug, "request_id": _slug, "request_sha256": _sha256}
    values = dict.fromkeys(validators)
    if type(command) is dict:
        # Iteration avoids comparing untrusted nonplain keys during lookup.
        for key, value in command.items():
            if type(key) is str and key in validators and validators[key](value):
                values[key] = value
    return values


def _matching_correlation(value, expected):
    return value is None if expected is None else type(value) is str and value == expected


def _valid_receipt(receipt, event_id):
    return (_plain_fields(receipt, _RECEIPT_FIELDS)
            and _slug(receipt["event_id"]) and receipt["event_id"] == event_id
            and type(receipt["sequence"]) is int and receipt["sequence"] > 0
            and _sha256(receipt["event_sha256"])
            and receipt["execution_enabled"] is False)


def project_commit_result(result, *, command):
    """Validate closed producer DATA and return its independent nine-field view.

    This function cannot establish that a producer ran or that a receipt is
    authoritative. Malformed, cross-command or contradictory data raises
    ValueError("invalid canonical decision result").
    """
    if not _plain_fields(result, _RESULT_FIELDS):
        raise ValueError("invalid canonical decision result")
    if any(type(result[key]) is not str for key in ("schema", "state", "effect", "reason")):
        raise ValueError("invalid canonical decision result")
    if result["code"] is not None and type(result["code"]) is not str:
        raise ValueError("invalid canonical decision result")
    if result["schema"] != "aegis.protected-decision-commit/v1" or result["native_qualified"] is not False:
        raise ValueError("invalid canonical decision result")
    for key, expected in _correlations(command).items():
        if not _matching_correlation(result[key], expected):
            raise ValueError("invalid canonical decision result")

    state, code = result["state"], result["code"]
    valid_command = _valid_command(command)
    if not valid_command and (state != "refused" or code != "INVALID_DECISION_INPUT"):
        raise ValueError("invalid canonical decision result")
    if valid_command and code == "INVALID_DECISION_INPUT":
        raise ValueError("invalid canonical decision result")

    if state in _SUCCESS:
        effect, reason = _SUCCESS[state]
        valid = (code is None and result["effect"] == effect and result["reason"] == reason
                 and _valid_receipt(result["receipt"], result["event_id"]))
    elif state in ("refused", "unknown"):
        expected_unknown = state == "unknown"
        valid = (code in _ERROR_REASONS and (code == "PUBLICATION_UNKNOWN") == expected_unknown
                 and result["effect"] == ("possible" if expected_unknown else "none")
                 and result["reason"] == _ERROR_REASONS[code] and result["receipt"] is None)
    else:
        valid = False
    if not valid:
        raise ValueError("invalid canonical decision result")

    projected = {key: value for key, value in result.items() if key != "event_id"}
    projected["schema"] = "aegis.decision-service-result/v1"
    if projected["receipt"] is not None:
        projected["receipt"] = dict(projected["receipt"])
    return projected


def _service_error(command, code):
    unknown = code == "PUBLICATION_UNKNOWN"
    result = {"schema": "aegis.protected-decision-commit/v1",
              "state": "unknown" if unknown else "refused",
              "effect": "possible" if unknown else "none",
              "code": code, "reason": _ERROR_REASONS[code],
              **_correlations(command), "receipt": None, "native_qualified": False}
    return project_commit_result(result, command=command)


class CanonicalDecisionBackend:
    """Bind the real current H session to its sole fixed decision dispatch port."""

    def __init__(self, host_session):
        if type(host_session) is not HostSession:
            raise TypeError("backend requires an owned HostSession")
        # Public current-owner validation; no root, writer or authority is retained.
        _ = host_session.owned_runtime
        self._session = host_session

    def commit(self, invocation, command):
        return self._session.dispatch_decision(invocation, command)


class DecisionService:
    """Validate inert input before fixed H/N1 dispatch, then project its result."""

    def __init__(self, backend):
        if type(backend) is not CanonicalDecisionBackend:
            raise TypeError("service requires a CanonicalDecisionBackend")
        self._backend = backend

    def handle(self, invocation, arguments):
        try:
            command = validate_command(arguments)
        except ValueError:
            return _service_error(arguments, "INVALID_DECISION_INPUT")
        try:
            result = self._backend.commit(invocation, command)
        except HostAuthorityError as exc:
            code = _HOST_ERRORS.get(exc.code)
            if code is None:
                raise
            # H wraps post-writer ambiguity as PROVIDER_OUTCOME_UNKNOWN. These
            # inert results cannot create H completion or clear an older UNKNOWN.
            return _service_error(command, code)
        return project_commit_result(result, command=command)
