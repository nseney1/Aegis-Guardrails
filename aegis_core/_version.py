"""The Aegis version: written here and nowhere else (ADR 0005 D18).

pyproject.toml reads it as the dynamic version, and `aegis --version`, the MCP
serverInfo and every package's ``__version__`` import it.
"""
__version__ = "4.4.0"

__all__ = ["__version__"]
