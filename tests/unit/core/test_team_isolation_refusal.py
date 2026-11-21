"""The capability, mount, and verify APIs share one fixed refusal type."""
import ast
import importlib
from pathlib import Path

import pytest

from aegis_core import team_isolation_capability as capability, team_isolation_mounts as mounts
from aegis_core import team_isolation_verify as verify


def test_shared_refusal_preserves_the_code_string_and_legacy_imports():
    shared = importlib.import_module("aegis_core.team_isolation_refusal")
    assert capability.IsolationRefusal is mounts.IsolationRefusal is verify.IsolationRefusal is shared.IsolationRefusal
    assert capability.REFUSALS is mounts.REFUSALS is shared.REFUSALS
    for code in ("unknown_host", "unsafe_mount", "expected_record"):
        refusal = shared.IsolationRefusal(code)
        assert str(refusal) == refusal.code == refusal.reason == code
        assert refusal.exit_code == 1
        assert refusal.message == shared.REFUSALS[code]
        assert refusal.next_action == {"actor": "operator", "command": refusal.message}


@pytest.mark.parametrize("code", ["undefined_refusal", [], None], ids=["unregistered", "unhashable", "missing"])
def test_unknown_refusal_codes_have_one_fixed_response(code):
    refusal = capability.IsolationRefusal(code)
    assert str(refusal) == refusal.code == refusal.reason == "internal"
    assert refusal.exit_code == 1
    assert refusal.message == "Report an internal isolation check failure."
    assert refusal.next_action == {"actor": "operator", "command": refusal.message}


def test_list_literal_capability_result_codes(request):
    """Publish literal code sites as an advisory pytest report section."""
    path = Path(capability.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    sites = set()
    for node in ast.walk(tree):
        candidates = []
        if isinstance(node, ast.Dict):
            candidates.extend(value for key, value in zip(node.keys, node.values)
                              if isinstance(key, ast.Constant) and key.value == "code")
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
              and node.func.id == "_refusal"):
            candidates.extend(node.args[:1])
        sites.update((value.lineno, value.value) for value in candidates
                     if isinstance(value, ast.Constant) and type(value.value) is str)
    request.node.add_report_section("call", "literal result codes",
                                    "\n".join(f"{path.name}:{line} {code}" for line, code in sorted(sites)))
