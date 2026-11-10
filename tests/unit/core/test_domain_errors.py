"""Tests for standardized typed AegisError hierarchy (aegis_core.errors)."""
from __future__ import annotations


from aegis_core.errors import AegisError, AegisValidationError, LockTimeoutError


class TestDomainErrors:
    """Test suite for typed exception hierarchy and backwards compatibility."""

    def test_aegis_error_base(self):
        """All domain exceptions inherit from AegisError."""
        err = AegisError("Base error", code="ERR_BASE")
        assert str(err) == "Base error"
        assert err.code == "ERR_BASE"
        assert isinstance(err, Exception)

    def test_validation_error_is_value_error(self):
        """AegisValidationError inherits from ValueError for backward compatibility."""
        err = AegisValidationError("Invalid value", code="INVALID_VALUE")
        assert isinstance(err, AegisError)
        assert isinstance(err, ValueError)
        assert str(err) == "Invalid value"

    def test_lock_timeout_error(self):
        """LockTimeoutError inherits from TimeoutError."""
        err = LockTimeoutError("Could not acquire lock", path="/w/.aegis/state/lock")
        assert isinstance(err, AegisError)
        assert isinstance(err, TimeoutError)
        assert err.path == "/w/.aegis/state/lock"
