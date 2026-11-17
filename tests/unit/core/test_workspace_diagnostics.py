"""Binding refusals have one bounded, literal and stateless display owner."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from aegis_core.guidance_projection import MAX_GUIDANCE_CHARS, MAX_GUIDANCE_ITEMS
from aegis_core.workspace.binding import WorkspaceBinding


def test_variants_never_depend_on_message_text():
    from aegis_core.workspace.diagnostics import project_binding

    for kind, suffix in (("not_a_directory", "which is not a directory"),
                         ("filesystem_root", "which is the filesystem root")):
        reason = "pin_missing" if kind == "not_a_directory" else "pin_denied"
        binding = WorkspaceBinding("error", reason=reason, kind=kind, message="untrusted wording")
        for _ in range(2):
            shown = project_binding(binding, workspace=r"C:\new\repo")
            assert shown["message"] == "AEGIS_WORKSPACE is set to C:\\new\\repo, " + suffix
            assert shown == project_binding(replace(binding, message="changed again"), workspace=r"C:\new\repo")


@pytest.mark.parametrize("details,expected", [
    (None, "guidance_projection_invalid_field"),
    ((3,), "guidance_projection_invalid_field"),
    ((("candidates", "wrong type"),), "guidance_projection_invalid_field"),
    ((("candidates", [3]),), "guidance_projection_invalid_field"),
    ((("unknown", "x"),), "guidance_projection_invalid_field"),
    ((("candidates", ["x"] * MAX_GUIDANCE_ITEMS),), "guidance_projection_limit"),
    ((("pin", "x" * (MAX_GUIDANCE_CHARS + 1)),), "guidance_projection_limit"),
])
@pytest.mark.parametrize("cli", [False, True])
def test_malformed_details_refuse_without_echo_or_exception(details, expected, cli):
    from aegis_core.workspace.diagnostics import project_binding

    binding = WorkspaceBinding("hold", reason="pin_conflicts_with_target", details=details)
    for _ in range(2):
        shown = project_binding(binding, cli=cli)
        assert shown["message"] == expected
        assert shown["details"] == {}


def test_parallel_projection_bounds_components_without_mutating_binding():
    from aegis_core.workspace.diagnostics import project_binding

    prefix = "C:\\new\\"
    paths = [prefix + "x" * 5000 + str(i) for i in range(240)]
    binding = WorkspaceBinding("hold", reason="ambiguous_host_roots", details=(("candidates", paths),))
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(project_binding, binding, cli=cli) for cli in (False, True) * 3]
        results = [future.result(timeout=10) for future in futures]
    assert binding.details == (("candidates", paths),)
    assert all(len(result["details"]["candidates"]) == 240 for result in results)
    assert all(len(value) == 1024 and value.startswith(prefix) and value.endswith("...")
               for result in results for value in result["details"]["candidates"])


@pytest.mark.parametrize("cli", [False, True])
def test_wrapper_limit_precedes_invalid_detail(cli):
    from aegis_core.workspace.diagnostics import project_binding

    binding = WorkspaceBinding("hold", reason="pin_conflicts_with_target",
                               details=(("unknown", "x"),) * (MAX_GUIDANCE_ITEMS + 1))
    assert project_binding(binding, cli=cli)["message"] == "guidance_projection_limit"


@pytest.mark.parametrize("kind", [[], 3, "x" * (MAX_GUIDANCE_CHARS + 1)], ids=["list", "number", "oversized"])
def test_malformed_variant_returns_documented_refusal(kind):
    from aegis_core.workspace.diagnostics import project_binding

    binding = WorkspaceBinding("error", reason="pin_denied", kind=kind)
    expected = "guidance_projection_limit" if isinstance(kind, str) else "guidance_projection_invalid_field"
    assert project_binding(binding)["message"] == expected


@pytest.mark.parametrize("field", ["reason", "status", "source", "confidence"])
@pytest.mark.parametrize("cli", [False, True])
def test_malformed_wrapper_field_cannot_reach_template_lookup(field, cli):
    from aegis_core.workspace.diagnostics import project_binding

    binding = replace(WorkspaceBinding("hold", reason="pin_missing"), **{field: []})
    shown = project_binding(binding, cli=cli)
    assert shown["message"] == "guidance_projection_invalid_field"
    assert shown["details"] == {}
