"""External metadata shapes are refused through the public native-selection API."""
import json

import pytest

from aegis_core.verification.regression_identity import prepare_native_selection
from tests.unit.core import test_language_tests

project = test_language_tests.project


@pytest.mark.parametrize("language,keys,value", [
    ("go", (), None), ("go", ("Dir",), []), ("go", ("ImportPath",), []),
    ("go", ("TestGoFiles",), None), ("go", ("XTestGoFiles",), [7]),
    ("rust", (), None), ("rust", ("workspace_members",), [["pkg"]]),
    ("rust", ("packages",), {}), ("rust", ("packages", 0), None),
    ("rust", ("packages", 0, "id"), []),
    ("rust", ("packages", 0, "manifest_path"), 7),
    ("rust", ("packages", 0, "name"), []),
    ("rust", ("packages", 0, "targets"), None),
    ("rust", ("packages", 0, "targets", 0), []),
    ("rust", ("packages", 0, "targets", 0, "kind"), [7]),
    ("rust", ("packages", 0, "targets", 0, "name"), []),
    ("rust", ("packages", 0, "targets", 0, "src_path"), 7),
    ("rust", None, None),
])
@pytest.mark.parametrize("diagnostic", ["", "go: downloading example.invalid/unavailable v1.0.0"])
def test_native_metadata_validation_is_explicit_and_preserves_valid_ownership(project, language, keys, value, diagnostic):
    workspace, snapshot, tools = (project[key] for key in ("workspace", "snapshot", "tools"))
    (workspace / ".aegis").mkdir()
    (workspace / ".aegis/config.json").write_text('{"ast":{"packaged_drivers":["go"]}}')
    file = "pkg/a_test.go" if language == "go" else "tests/smoke.rs"
    (snapshot / file).write_text("package pkg\nfunc TestA() {}\n" if language == "go" else "#[test] fn works() {}\n")
    document = ({"Dir": str(snapshot / "pkg"), "ImportPath": "example/pkg", "TestGoFiles": ["a_test.go"]}
                if language == "go" else {"workspace_members": ["pkg"], "packages": [{
                    "id": "pkg", "name": "pkg", "manifest_path": str(snapshot / "Cargo.toml"),
                    "targets": [{"kind": ["test"], "name": "smoke", "src_path": str(snapshot / file)}]}]})
    if keys:
        parent = document
        for key in keys[:-1]:
            parent = parent[key]
        parent[keys[-1]] = value
    elif keys is not None:
        document = value
    project["scenario"].write_text(json.dumps(document))
    (tools / "runtime.py").write_text(
        "import json,pathlib,sys\ntool,args=sys.argv[1],sys.argv[2:]\n"
        "if tool=='rustup': print('stable-fixture (default)')\n"
        f"elif tool=='go' and args[0]=='env': print({str(tools / 'go-build')!r}+'\\n'+{str(tools / 'go-modules')!r})\n"
        f"else: print({diagnostic!r}, file=sys.stderr); print(pathlib.Path({str(project['scenario'])!r}).read_text())\n")
    selection = prepare_native_selection(workspace, snapshot, language, [file], scratch=project["scratch"] / "selection")
    assert (project["scratch"] / "selection/metadata/metadata-stderr.log").read_text() == diagnostic + "\n"
    if keys is None:
        assert selection.plan.available, selection.plan.detail
        assert selection.belongs(("pkg", "test", "smoke", "works"), file)
    else:
        assert not selection.plan.available and selection.owners == ()
        assert selection.plan.reason == "test_ids_unmapped"
        label = "Go package" if language == "go" else "Cargo"
        assert selection.plan.detail == f"test_ids_unmapped: invalid {label} metadata"


def test_failed_metadata_retains_bounded_stdout_and_stderr_diagnostics(project):
    diagnostic = "error: failed to download dependency " + "x" * 8192
    (project["tools"] / "runtime.py").write_text(
        "import sys\n"
        "if sys.argv[1]=='rustup': print('stable-fixture (default)')\n"
        f"else: print('{{}}'); print({diagnostic!r}, file=sys.stderr); raise SystemExit(1)\n")
    (project["snapshot"] / "tests/smoke.rs").write_text("#[test] fn works() {}\n")
    selection = prepare_native_selection(project["workspace"], project["snapshot"], "rust", ["tests/smoke.rs"],
                                         scratch=project["scratch"] / "selection")
    assert selection.plan.reason == "deps_unavailable" and not selection.owners
    assert "stdout: {}" in selection.plan.detail and "stderr: " + diagnostic[:100] in selection.plan.detail
    assert len(selection.plan.detail) < 4300
