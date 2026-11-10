"""The independent tools/core validators must accept the same binding documents.

Only the tools reader boundary is replaced: source pin verification is covered by
the provisioning integration suite. Both real validation functions run below.
The core's host registry is passed as data, preserving its vendor independence.
"""
import copy
import importlib
import json
from pathlib import Path

import pytest

from aegis_core import model_select

REPO = Path(__file__).resolve().parents[2]


def fixture_case(case):
    data = json.loads((REPO / "tools/hierarchy_templates/model-bindings.json").read_text())
    row = data["hosts"][0]
    if case == "valid":
        pass
    elif case == "punctuation-model":
        row["model"] = ".-model"
    elif case == "band-policy-data":
        data["roles"][0]["band"] = {"floor": "deep", "default": "deep", "ceiling": "max"}
    elif case == "schema":
        data["schema"] = "unknown"
    elif case == "extra-key":
        data["unexpected"] = True
    elif case == "duplicate-role":
        data["roles"].append(copy.deepcopy(data["roles"][0]))
    elif case == "missing-role":
        data["roles"].pop()
    elif case == "band-order":
        data["roles"][0]["band"]["floor"] = "max"
    elif case == "role-class":
        data["roles"][0]["model_class"] = "scout"
    elif case == "duplicate-host-class":
        data["hosts"].append(copy.deepcopy(row))
    elif case == "duplicate-host-model":
        data["hosts"][1]["model"] = row["model"]
    elif case == "unknown-host":
        row["host"] = "other-host"
    elif case == "missing-coding":
        data["hosts"].pop(0)
    elif case == "missing-entire-host":
        data["hosts"] = [r for r in data["hosts"] if r["host"] != "codex-cli"]
    elif case == "bad-model-token":
        row["model"] = "bad model"
    elif case == "level-alias":
        row["levels"]["ultra"] = "ultra"
    elif case == "duplicate-native-level":
        row["levels"]["max"] = row["levels"]["deep"]
    elif case == "admission-shape":
        del row["admission"]["deep"]
    elif case == "admission-state":
        row["admission"]["deep"] = "unknown"
    elif case in ("missing-default", "missing-ceiling"):
        intent = "deep" if case == "missing-default" else "max"
        del row["levels"][intent]
        del row["admission"][intent]
    elif case in ("rejected-default", "rejected-ceiling"):
        row["admission"]["deep" if case == "rejected-default" else "max"] = "rejected"
    return data


@pytest.mark.parametrize("case", ["valid", "punctuation-model", "band-policy-data", "schema", "extra-key",
    "duplicate-role", "missing-role", "band-order", "role-class", "duplicate-host-class", "duplicate-host-model",
    "unknown-host", "missing-coding", "missing-entire-host", "bad-model-token", "level-alias",
    "duplicate-native-level", "admission-shape", "admission-state", "missing-default", "missing-ceiling",
    "rejected-default", "rejected-ceiling"])
def test_core_and_mr1_binding_validation_agree(case, tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(REPO / "tools"))
    provision = importlib.import_module("hierarchy_provision")
    data = fixture_case(case)
    path = tmp_path / "model-bindings.json"
    path.write_text(json.dumps(data))
    monkeypatch.setattr(provision, "read_pinned_bindings", lambda setup, base: (path, path.read_bytes()))
    try:
        provision.load_model_bindings({}, tmp_path)
    except ValueError:
        tools_accepts = False
    else:
        tools_accepts = True
    try:
        model_select.validate_bindings(data, host_kinds=provision.hierarchy_hosts.TEAM_HOSTS)
    except model_select.ModelSelectionError as exc:
        assert str(exc) == "invalid_bindings"
        core_accepts = False
    else:
        core_accepts = True
    assert core_accepts == tools_accepts
    assert tools_accepts == (case in ("valid", "punctuation-model", "band-policy-data"))
    policy = {"team_id": "parity", "team_family": "first", "manager_family": "second",
              "target_shares": {"first": 0.7, "second": 0.3}, "family_order": ["first", "second"],
              "family_hosts": {"first": ["codex-cli"], "second": ["claude-code"]}, "flexible_tasks": ["T9"],
              "review_families": {"T4": {"primary": "first"}, "T5": {"primary": "second"},
                                  "T6": {"primary": "first", "whole": "second"},
                                  "T8": {"primary": "opposite", "second": "author"}}}
    try:
        model_select.select_model(data, policy, "T9", "implementer", [], subject="parity",
                                  host_kinds=provision.hierarchy_hosts.TEAM_HOSTS)
    except model_select.ModelSelectionError as exc:
        assert str(exc) == "invalid_bindings"
        selection_accepts = False
    else:
        selection_accepts = True
    assert selection_accepts == tools_accepts


def test_large_valid_registry_has_mr1_parity(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(REPO / "tools"))
    provision = importlib.import_module("hierarchy_provision")
    data = fixture_case("valid")
    registry = tuple("host-%d" % i for i in range(8))
    templates = [row for row in data["hosts"] if row["host"] == "codex-cli"]
    data["hosts"] = [dict(copy.deepcopy(row), host=host) for host in registry for row in templates]
    assert len(data["hosts"]) == 32
    path = tmp_path / "large-model-bindings.json"
    path.write_text(json.dumps(data))
    monkeypatch.setattr(provision.hierarchy_hosts, "TEAM_HOSTS", registry)
    monkeypatch.setattr(provision, "read_pinned_bindings", lambda setup, base: (path, path.read_bytes()))
    expected_roles, expected_hosts, _, _ = provision.load_model_bindings({}, tmp_path)
    assert model_select.validate_bindings(data, host_kinds=registry) == (expected_roles, expected_hosts)
