"""Driver errors shared by the v1 runner and packaged batch transport."""
from aegis_core.errors import AegisError


class ASTDriverError(AegisError):
    """Raised when an AST driver execution fails."""


class ASTDriverTimeoutError(ASTDriverError):
    """Raised when an AST driver exceeds its deadline."""


class NoDriverConfiguredError(ASTDriverError):
    """Raised when no driver is configured for an extension."""
