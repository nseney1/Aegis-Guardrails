"""The installer and binding readers keep their distinct registry policies."""
from __future__ import annotations

import json

import pytest

from aegis_cli import install_hosts
from aegis_core.workspace import binding
from aegis_core.workspace.layout import UserLayout


@pytest.fixture
def registry_paths(tmp_path, monkeypatch):
    home = tmp_path.resolve() / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    root = tmp_path.resolve() / "repo"
    root.mkdir()
    return home, UserLayout(home).workspaces_file, root


@pytest.mark.parametrize(
    "document, strict_error, binding_problem, has_root",
    [
        pytest.param(
            lambda root: {"v": 1, "workspaces": [{"root": str(root), "extra": "kept"}], "extra": 7},
            None, None, True, id="valid-with-unknown-keys",
        ),
        pytest.param(lambda root: {"v": 1, "workspaces": []}, None, None, False, id="empty"),
        pytest.param(
            lambda root: {"v": 2, "workspaces": []},
            ": has schema version 2; this aegis reads version 1. Left unchanged.",
            ": unsupported registry version 2", False, id="v2",
        ),
        pytest.param(
            lambda root: {"v": 1, "workspaces": {}},
            ": 'workspaces' must be a list; left unchanged",
            ": 'workspaces' must be a list", False, id="workspaces-not-list",
        ),
        pytest.param(
            lambda root: {"v": 1, "workspaces": [{}]},
            ": every workspace needs a 'root' path; left unchanged",
            ": entry 0 has no absolute 'root'", False, id="missing-root",
        ),
        pytest.param(
            lambda root: {"v": 1, "workspaces": [{"root": "relative/repo"}]},
            None, ": entry 0 has no absolute 'root'", False, id="relative-root",
        ),
        pytest.param(
            lambda root: {"v": 1, "workspaces": [{"root": "\x00repo"}]},
            None, ": entry 0 has no absolute 'root'", False, id="relative-nul-root",
        ),
        pytest.param(
            lambda root: {"v": 1, "workspaces": [{"root": str(root)}, {"root": str(root)}]},
            None, None, True, id="duplicate-roots",
        ),
        pytest.param(
            lambda root: [1], ": must hold a JSON object; left unchanged",
            " must be a JSON object", False, id="non-object",
        ),
    ],
)
def test_registry_readers_preserve_their_document_policies(
    registry_paths, document, strict_error, binding_problem, has_root,
):
    home, path, root = registry_paths
    doc = document(root)
    raw = (json.dumps(doc) + "\n").encode("utf-8")
    path.parent.mkdir()
    path.write_bytes(raw)

    if strict_error is None:
        assert install_hosts.read_registry(home) == doc
    else:
        with pytest.raises(install_hosts.InstallError) as caught:
            install_hosts.read_registry(home)
        assert str(caught.value) == f"{path}{strict_error}"
    assert path.read_bytes() == raw

    result = binding.read_registry(path)
    assert result.roots == ((root,) if has_root else ())
    assert result.problems == (() if binding_problem is None else (f"{path}{binding_problem}",))
    assert path.read_bytes() == raw


def test_missing_registry_is_empty_without_creating_user_files(registry_paths):
    home, path, _ = registry_paths
    assert install_hosts.read_registry(home) == {"v": 1, "workspaces": []}
    assert binding.read_registry() == binding.Registry()
    assert not path.parent.exists()


@pytest.mark.parametrize(
    "raw, strict_error, binding_problem",
    [
        pytest.param(
            b"{bad",
            ": is not valid JSON (Expecting property name enclosed in double quotes at line 1 column 2); "
            "left unchanged. Comments and trailing commas are not supported: fix the file or move it "
            "aside, then re-run.",
            " is not valid JSON", id="corrupt-json",
        ),
        pytest.param(
            b"\xff", ": is not UTF-8 text (invalid start byte); left unchanged",
            " is not valid JSON", id="invalid-utf8",
        ),
        pytest.param(b"", None, " is not valid JSON", id="blank-file"),
        pytest.param(b"{}", None, ": unsupported registry version None", id="empty-object"),
    ],
)
def test_unusable_registry_bytes_are_reported_and_unchanged(
    registry_paths, raw, strict_error, binding_problem,
):
    home, path, _ = registry_paths
    path.parent.mkdir()
    path.write_bytes(raw)

    if strict_error is None:
        assert install_hosts.read_registry(home) == {"v": 1, "workspaces": []}
    else:
        with pytest.raises(install_hosts.InstallError) as caught:
            install_hosts.read_registry(home)
        assert str(caught.value) == f"{path}{strict_error}"
    assert path.read_bytes() == raw

    result = binding.read_registry(path)
    assert result.roots == ()
    assert result.problems == (f"{path}{binding_problem}",)
    assert path.read_bytes() == raw
