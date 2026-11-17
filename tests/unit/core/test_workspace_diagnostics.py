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


# Enumerate the public refusal variants: fixed causes and repairs must survive
# clipping in every template, including templates without a repair suffix.
@pytest.mark.parametrize("cli,reason,kind,details,workspace,fixed", [
    (True, "pin_conflicts_with_target", None, {"pin": "p", "target": "t"}, "w",
     ("--workspace ", " resolves to ", ", but AEGIS_WORKSPACE pins ", "; unset the pin or drop --workspace")),
    (True, "pin_conflicts_with_cwd", None, {"pin": "p", "cwd": "c", "cwd_root": "r"}, None,
     ("AEGIS_WORKSPACE pins ", ", but the current directory ", " is in ", "; unset the pin, or run aegis from the pinned project")),
    (False, "pin_conflicts_with_host_root", None, {"pin": "p", "host_roots": ["h", "j"]}, None,
     ("AEGIS_WORKSPACE pins ", ", but the host reports the session in ", "; fix the pin or open the pinned project")),
    (False, "pin_conflicts_with_registry", None, {"pin": "p", "registered_root": "r"}, None,
     ("AEGIS_WORKSPACE pins ", ", but the files belong to the registered workspace ")),
    (False, "host_root_conflicts_with_registry", None, {"host_root": "h", "registered_root": "r"}, None,
     ("the host reports the session in ", ", but the files belong to the registered workspace ")),
    (False, "host_root_conflicts_with_registry", None, {"registered_root": "r"}, None,
     ("the host reports the session outside any Aegis workspace, but the files belong to the registered workspace ",)),
    (False, "cwd_conflicts_with_registry", None, {"cwd_root": "c", "candidates": ["r", "s"]}, None,
     ("the server runs in the workspace ", ", but the files exist only in the registered workspace(s) ", "; pass absolute paths")),
    (True, "no_workspace", "pin_resolution", {"pin": "p"}, None,
     ("AEGIS_WORKSPACE ", " cannot be resolved")),
    (True, "no_workspace", "target_resolution", {"target": "t"}, None,
     ("--workspace ", " cannot be resolved")),
    (True, "no_workspace", "home_directory", {"target": "t"}, None,
     ("not an Aegis workspace (", " is the home directory; ~/.aegis is the user rule layer); run aegis init in a project")),
    (True, "no_workspace", "filesystem_root", {"target": "t"}, None,
     ("not an Aegis workspace (", " is the filesystem root); run aegis init in a project")),
    (False, "pin_missing", None, {"pin": "p"}, None,
     ("AEGIS_WORKSPACE is set to ", ", which cannot be resolved")),
    (False, "pin_missing", "not_a_directory", {"pin": "p"}, None,
     ("AEGIS_WORKSPACE is set to ", ", which is not a directory")),
    (False, "pin_not_a_workspace", None, {"pin": "p"}, None,
     ("AEGIS_WORKSPACE is set to ", ", which has no .aegis/ (run aegis init there)")),
    (False, "pin_denied", None, {"pin": "p"}, None,
     ("AEGIS_WORKSPACE is set to ", ", which is the home directory")),
    (False, "pin_denied", "filesystem_root", {"pin": "p"}, None,
     ("AEGIS_WORKSPACE is set to ", ", which is the filesystem root")),
])
def test_binding_frame_reserves_every_fixed_fragment(cli, reason, kind, details, workspace, fixed):
    from aegis_core.workspace.diagnostics import project_binding

    long = {key: [item * 5000 for item in value] if isinstance(value, list) else value * 5000
            for key, value in details.items()}
    binding = WorkspaceBinding("hold", reason=reason, kind=kind, details=tuple(long.items()))
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(project_binding, binding, workspace=workspace, cli=cli) for _ in range(6)]
        results = [future.result(timeout=10) for future in futures]
    assert all(result == results[0] for result in results)
    message = results[0]["message"]
    assert len(message) <= 1024
    assert all(fragment in message for fragment in fixed)
    assert "... [display-only]" in message
    assert binding.details == tuple(long.items())
    # A refused retry cannot poison the next valid projection.
    assert project_binding(replace(binding, details=None), cli=cli)["message"] == "guidance_projection_invalid_field"
    assert project_binding(binding, workspace=workspace, cli=cli) == results[0]


@pytest.mark.parametrize("extra", [-1, 0, 1])
def test_binding_frame_exact_boundary_preserves_fixed_text(extra):
    from aegis_core.workspace.diagnostics import project_binding

    prefix = "AEGIS_WORKSPACE is set to "
    suffix = ", which has no .aegis/ (run aegis init there)"
    pin = "x" * (1024 - len(prefix) - len(suffix) + extra)
    binding = WorkspaceBinding("error", reason="pin_not_a_workspace", details=(("pin", pin),))
    message = project_binding(binding)["message"]
    assert message.startswith(prefix) and message.endswith(suffix)
    assert len(message) <= 1024
    if extra <= 0:
        assert message == prefix + pin + suffix
    else:
        assert "... [display-only]" in message


def test_binding_frame_cannot_split_a_redaction_atom_or_redact_fixed_wording():
    from aegis_core.workspace.diagnostics import project_binding

    prefix = "AEGIS_WORKSPACE is set to "
    suffix = ", which has no .aegis/ (run aegis init there)"
    marker = "... [display-only]"
    budget = 1024 - len(prefix) - len(suffix) - len(marker)
    pin = "x" * (budget - 5) + " ghp_" + "S" * 30 + " " + "z" * 5000
    binding = WorkspaceBinding("error", reason="pin_not_a_workspace", details=(("pin", pin),))
    message = project_binding(binding)["message"]
    assert message == prefix + "x" * (budget - 5) + " " + marker + suffix
    # A projected identity must never consume fixed text in another redaction pass.
    assert project_binding(replace(binding, details=(("pin", "token="),)))["message"] == prefix + "token=" + suffix
    resolution = WorkspaceBinding("error", reason="no_workspace", kind="target_resolution",
                                  details=(("target", "token="),))
    assert project_binding(resolution, cli=True)["message"] == "--workspace token= cannot be resolved"
