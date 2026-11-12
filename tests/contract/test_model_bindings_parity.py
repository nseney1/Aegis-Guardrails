"""The independent tools/core validators agree on shared binding-schema rules.

Provision also requires admitted band endpoints; selector enforcement is filed
separately as MR-1c-SEL.

Only the tools reader boundary is replaced: source pin verification is covered by
the provisioning integration suite. Both real validation functions run below.
The core's host registry is passed as data, preserving its vendor independence.
"""
import copy
from concurrent.futures import ThreadPoolExecutor
import importlib
import json
from pathlib import Path

import pytest

from aegis_core import model_select

REPO = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
@pytest.mark.parametrize("intent", ["standard", "deep", "max"])
@pytest.mark.parametrize("state", ["admitted", "unprobed", "rejected"])
@pytest.mark.parametrize("planned", [False, True])
def test_mr1c_load_requires_admitted_band_endpoints(tmp_path, monkeypatch, host, intent, state, planned):
    import tools.hierarchy_provision as provision
    data = fixture_case("valid")
    coding = next(row for row in data["hosts"] if (row["host"], row["class"]) == (host, "coding"))
    coding["admission"][intent] = state
    if planned:
        for row in data["hosts"]:
            if row["host"] == host:
                row["host_status"] = "planned"
    path = tmp_path / "bindings.json"
    raw = json.dumps(data).encode()
    path.write_bytes(raw)
    monkeypatch.setattr("tools.hierarchy_provision.read_pinned_bindings",
                        lambda setup, base: (path, path.read_bytes()))

    def load(_):
        try:
            _, rows, digest, _ = provision.load_model_bindings({}, tmp_path)
        except ValueError as exc:
            return str(exc)
        return "loaded", rows[host, "coding"]["admission"][intent], digest

    with ThreadPoolExecutor(max_workers=3) as workers:
        answers = list(workers.map(load, range(6)))
    assert all(answer == answers[0] for answer in answers)
    assert load(None) == answers[0]
    assert path.read_bytes() == raw
    if planned or state == "admitted":
        assert answers[0][:2] == ("loaded", state)
        if planned:
            with pytest.raises(ValueError, match="^host is planned; Teams support is not qualified$"):
                provision.require_selectable_host(provision.load_model_bindings({}, tmp_path), host)
    else:
        assert answers[0] == ("invalid model bindings %s: band default and ceiling levels must be admitted; "
                              "probe the level or repair model-bindings.json" % path)
        coding["admission"][intent] = "admitted"
        path.write_text(json.dumps(data))
        assert load(None)[:2] == ("loaded", "admitted")


def test_mr1c_registry_admits_only_probed_supported_coding_levels():
    data = fixture_case("valid")
    for row in data["hosts"]:
        for intent, level in row["levels"].items():
            expected = ("admitted" if row["host"] in ("claude-code", "codex-cli") and
                        row["class"] == "coding" and level is not None else "unprobed")
            assert row["admission"][intent] == expected


@pytest.mark.parametrize("host", ["claude-code", "codex-cli"])
@pytest.mark.parametrize("state", ["admitted", "rejected", "unprobed", "null"])
def test_mr1c_planned_admission_is_repeatable_and_does_not_mutate_inputs(host, state):
    import tools.hierarchy_provision as provision
    data = fixture_case("valid")
    roles = {row["kind"]: row for row in data["roles"]}
    row = next(row for row in data["hosts"] if (row["host"], row["class"]) == (host, "coding"))
    row["admission"]["extended"] = "admitted" if state == "null" else state
    if state == "null":
        row["levels"]["extended"] = None
    bindings = (roles, {(host, "coding"): row}, "0" * 64, REPO / "bindings.json")
    options = {"model": row["model"], "effort": "xhigh"}
    before = copy.deepcopy((bindings, options))

    def resolve(_):
        try:
            return provision.planned_model_settings(bindings, host, "implementer", options, None)
        except ValueError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=3) as workers:
        answers = list(workers.map(resolve, range(6)))
    assert all(answer == answers[0] for answer in answers)
    assert resolve(None) == answers[0]
    assert (bindings, options) == before
    if state == "admitted":
        assert answers[0][1]["admission"] == "admitted"
    elif state == "null":
        assert answers[0] == ("implementer effort xhigh has no supported intent; supported intents: "
                              "light, standard, deep, max; choose a supported effort")
    else:
        assert answers[0] == ("%s intent extended (effort xhigh) is not admitted for %s; "
                              "choose an admitted supported level" % (row["model"], host))


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
        row["levels"]["beyond"] = "ultra"
    elif case == "duplicate-native-level":
        row["levels"]["max"] = row["levels"]["deep"]
    elif case == "admission-shape":
        del row["admission"]["deep"]
    elif case == "admission-state":
        row["admission"]["deep"] = "unknown"
    elif case == "null-levels":
        row["levels"]["extended"] = None
    elif case in ("null-default", "null-ceiling"):
        row["levels"]["deep" if case == "null-default" else "max"] = None
    elif case == "optional-fields":
        row.update(effort_encoding="flag", served_aliases=["usage-only"], host_status="selectable")
    elif case == "unknown-encoding":
        row["effort_encoding"] = "shell"
    elif case == "unknown-status":
        row["host_status"] = "ready"
    elif case == "mixed-status":
        row["host_status"] = "planned"
    elif case == "bad-aliases":
        row["served_aliases"] = "usage-only"
    elif case == "duplicate-aliases":
        row["served_aliases"] = ["usage-only", "usage-only"]
    elif case == "bad-alias-token":
        row["served_aliases"] = ["token=private\nvalue"]
    elif case == "long-effective-model":
        row.update(model="a" * 128, effort_encoding="model_suffix")
    elif case == "too-many-aliases":
        row["served_aliases"] = ["served-%d" % i for i in range(257)]
    elif case == "unhashable-status":
        row["host_status"] = {"token": "private"}
    elif case == "unhashable-level":
        row["levels"]["ultra"] = ["private"]
    elif case == "unhashable-alias":
        row["served_aliases"] = [["private"]]
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
    "rejected-default", "rejected-ceiling", "null-levels", "optional-fields", "unknown-encoding",
    "unknown-status", "mixed-status", "bad-aliases", "duplicate-aliases", "bad-alias-token",
    "long-effective-model", "too-many-aliases", "unhashable-status", "unhashable-level",
    "unhashable-alias", "null-default", "null-ceiling"])
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
    assert tools_accepts == (case in ("valid", "punctuation-model", "band-policy-data",
                                     "null-levels", "optional-fields"))
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


def test_mr4_registry_records_capabilities_without_admitting_hosts():
    data = fixture_case("valid")
    rows = {(row["host"], row["class"]): row for row in data["hosts"]}
    for model_class, model in (("frontier", "gemini-4-carbon"),
                               ("scout", "gemini-4-argon"),
                               ("mechanical", "gemini-3.8-flash")):
        row = rows["antigravity", model_class]
        assert row["model"] == model
        assert row["effort_encoding"] == "model_suffix"
        assert row["host_status"] == "planned"
        assert row["levels"] == {"light": "low", "standard": "medium", "deep": "high",
                                 "extended": None, "max": None, "ultra": None}
        assert set(row["admission"].values()) == {"unprobed"}
    grok = rows["grok", "coding"]
    assert grok["model"] == "grok-4.7"
    assert grok["host_status"] == "planned"
    assert grok["served_aliases"] == ["grok-4.7-build"]
    assert grok["levels"] == {"light": "low", "standard": "medium", "deep": "high",
                              "extended": "xhigh", "max": None, "ultra": None}
    assert set(grok["admission"].values()) == {"unprobed"}
    for row in data["hosts"]:
        assert list(row["levels"]) == ["light", "standard", "deep", "extended", "max", "ultra"]
        assert row["levels"]["ultra"] is None
        assert row["admission"]["ultra"] == "unprobed"


def test_mr4_optional_capabilities_have_validator_parity(tmp_path, monkeypatch):
    import tools.hierarchy_provision as provision
    data = fixture_case("valid")
    planned = copy.deepcopy(data["hosts"][0])
    planned.update(host="future-host", host_status="planned", effort_encoding="model_suffix",
                   served_aliases=["served-model"])
    planned["levels"].update(extended=None, max=None)
    data["hosts"].append(planned)
    path = tmp_path / "bindings.json"
    raw = json.dumps(data).encode()
    monkeypatch.setattr("tools.hierarchy_provision.read_pinned_bindings", lambda setup, base: (path, raw))
    roles, hosts, _, _ = provision.load_model_bindings({}, tmp_path)
    assert model_select.validate_bindings(data, host_kinds=provision.hierarchy_hosts.TEAM_HOSTS) == (roles, hosts)


def test_mr4_provision_renders_suffix_after_capability_admission():
    import tools.hierarchy_provision as provision
    data = fixture_case("valid")
    roles = {row["kind"]: row for row in data["roles"]}
    # Exercise rendering independently of the provisional registry classes/host plan.
    row = copy.deepcopy(data["hosts"][0])
    row.update(host="antigravity", model="gemini-4-carbon", effort_encoding="model_suffix")
    row["admission"]["deep"] = "admitted"
    bindings = (roles, {("antigravity", "coding"): row}, "0" * 64, REPO / "bindings.json")
    options, record = provision.planned_model_settings(
        bindings, "antigravity", "implementer", {"effort": "high"}, None)
    assert options["model"] == record["model"] == "gemini-4-carbon-high"


@pytest.mark.parametrize("model", [None, "gemini-4-carbon", "gemini-4-carbon-high"])
def test_mr4_provision_suffix_retries_and_refusals(model):
    import tools.hierarchy_provision as provision
    data = fixture_case("valid")
    roles = {row["kind"]: row for row in data["roles"]}
    row = copy.deepcopy(data["hosts"][0])
    row.update(host="antigravity", model="gemini-4-carbon", effort_encoding="model_suffix")
    row["levels"].update(extended=None, max=None)
    bindings = (roles, {("antigravity", "coding"): row}, "0" * 64, REPO / "bindings.json")
    options = {"model": model, "effort": "high"}
    before = copy.deepcopy((bindings, options))
    first = provision.planned_model_settings(bindings, "antigravity", "implementer", options, None)
    assert first[0]["model"] == first[1]["model"] == "gemini-4-carbon-high"
    assert first == provision.planned_model_settings(bindings, "antigravity", "implementer", *first)
    assert (bindings, options) == before
    with pytest.raises(ValueError, match="^implementer effort xhigh has no supported intent; "
                             "supported intents: light, standard, deep; choose a supported effort$"):
        provision.planned_model_settings(bindings, "antigravity", "implementer", {"effort": "xhigh"}, None)
    row["host_status"] = "planned"
    for _ in range(2):
        with pytest.raises(ValueError, match="host is planned; Teams support is not qualified"):
            provision.planned_model_settings(bindings, "antigravity", "implementer", options, None)


def test_mr4_served_alias_is_not_a_provision_model():
    import tools.hierarchy_provision as provision
    data = fixture_case("valid")
    roles = {row["kind"]: row for row in data["roles"]}
    row = copy.deepcopy(data["hosts"][0])
    row["served_aliases"] = ["usage-only"]
    bindings = (roles, {("claude-code", "coding"): row}, "0" * 64, REPO / "bindings.json")
    with pytest.raises(ValueError, match="^request model usage-only is not bound for host claude-code;"):
        provision.planned_model_settings(bindings, "claude-code", "implementer",
                                         {"model": "usage-only", "effort": "high"}, None)


@pytest.mark.parametrize("collision", ["suffix-flag", "suffix-base", "alias-base", "alias-suffix"])
@pytest.mark.parametrize("state", ["unprobed", "admitted", "rejected"])
@pytest.mark.parametrize("reverse", [False, True])
def test_mr4_2h_rendered_identity_collisions_refuse_in_both_validators(tmp_path, monkeypatch,
                                                                    collision, state, reverse):
    import tools.hierarchy_provision as provision
    data = fixture_case("valid")
    coding = next(r for r in data["hosts"] if (r["host"], r["class"]) == ("claude-code", "coding"))
    other = next(r for r in data["hosts"] if (r["host"], r["class"]) == ("claude-code", "frontier"))
    coding.update(model="m", effort_encoding="model_suffix")
    other["admission"]["deep"] = state
    if collision in ("suffix-flag", "suffix-base"):
        other["model"] = "m-high"
        if collision == "suffix-base":
            other["effort_encoding"] = "model_suffix"
    elif collision == "alias-base":
        coding["served_aliases"] = [other["model"]]
    else:
        other["served_aliases"] = ["m-high"]
    if reverse:
        data["hosts"].reverse()
    path = tmp_path / "bindings.json"
    raw = json.dumps(data).encode()
    monkeypatch.setattr("tools.hierarchy_provision.read_pinned_bindings", lambda setup, base: (path, raw))
    for _ in range(2):
        with pytest.raises(model_select.ModelSelectionError, match="^invalid_bindings$"):
            model_select.validate_bindings(data, host_kinds=provision.hierarchy_hosts.TEAM_HOSTS)
        with pytest.raises(ValueError, match="ambiguous effective model identity; repair model-bindings.json$"):
            provision.load_model_bindings({}, tmp_path)


@pytest.mark.parametrize("reverse", [False, True])
def test_mr4_2h_provision_never_chooses_an_ambiguous_first_match(reverse):
    import tools.hierarchy_provision as provision
    data = fixture_case("valid")
    roles = {r["kind"]: r for r in data["roles"]}
    coding, other = copy.deepcopy(data["hosts"][:2])
    coding.update(model="m", effort_encoding="model_suffix")
    other["model"] = "m-high"
    rows = [coding, other]
    if reverse:
        rows.reverse()
    bindings = (roles, {(r["host"], r["class"]): r for r in rows}, "0" * 64, REPO / "bindings.json")
    with pytest.raises(ValueError, match="^ambiguous model binding$"):
        provision.planned_model_settings(bindings, "claude-code", "implementer",
                                         {"model": "m-high", "effort": "high"}, None)


def test_mr4_2h_native_ultra_is_not_advertised_or_accepted(tmp_path, monkeypatch):
    import tools.hierarchy_provision as provision
    data = fixture_case("valid")
    assert all(row["levels"]["ultra"] is None for row in data["hosts"])
    row = next(r for r in data["hosts"] if (r["host"], r["class"]) == ("codex-cli", "coding"))
    row["levels"]["extended"] = "ultra"
    path = tmp_path / "bindings.json"
    raw = json.dumps(data).encode()
    monkeypatch.setattr("tools.hierarchy_provision.read_pinned_bindings", lambda setup, base: (path, raw))
    with pytest.raises(model_select.ModelSelectionError, match="^invalid_bindings$"):
        model_select.validate_bindings(data, host_kinds=provision.hierarchy_hosts.TEAM_HOSTS)
    with pytest.raises(ValueError, match="unknown native level 'ultra'; repair model-bindings.json$"):
        provision.load_model_bindings({}, tmp_path)
