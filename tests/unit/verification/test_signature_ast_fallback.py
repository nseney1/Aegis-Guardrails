"""Behavioral tests for BUG-077: ast.literal_eval crash on complex default expressions.

extract_signatures() in safety_verify.py must not crash when encountering
non-literal default argument values (e.g. Path.cwd(), function calls, module constants).
It must fall back to ast.unparse() to extract valid function signatures.
"""
from pathlib import Path
import pytest

from aegis_core.verification.adversarial_verify import extract_signatures


def test_extract_signatures_with_complex_defaults(tmp_path: Path):
    """extract_signatures should cleanly extract signatures with non-literal defaults."""
    code = '''
from pathlib import Path

DEFAULT_TIMEOUT = 30

def connect(timeout=DEFAULT_TIMEOUT, workdir=Path.cwd(), debug=False):
    """Connect to service with custom timeout and directory."""
    pass

def calculate(value, offset=10 * 2, mode=None):
    pass
'''
    test_file = tmp_path / "sample.py"
    test_file.write_text(code, encoding="utf-8")

    sigs = extract_signatures(str(test_file))
    assert len(sigs) == 2, f"Expected 2 signatures extracted, got {len(sigs)}"
    
    # Check connect signature reconstructed
    connect_sig = next((s for s in sigs if "def connect(" in s), None)
    assert connect_sig is not None, "Failed to extract connect() signature"
    assert "timeout=DEFAULT_TIMEOUT" in connect_sig
    assert "workdir=Path.cwd()" in connect_sig
    assert "debug=False" in connect_sig

    # Check calculate signature reconstructed
    calc_sig = next((s for s in sigs if "def calculate(" in s), None)
    assert calc_sig is not None, "Failed to extract calculate() signature"
    assert "offset=" in calc_sig
