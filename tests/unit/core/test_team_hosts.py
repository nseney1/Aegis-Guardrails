"""Capacity advice through the profile and adapter service surface."""
from collections import Counter, deque
from copy import deepcopy
from dataclasses import replace
import json
import importlib
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from aegis_core import hosts as registry, team_host_agy, team_hosts as hosts, team_profile as profile
from tools import hierarchy_hosts


RESET = "2026-11-16T22:00:00Z"
KINDS = ("writer", "review", "extra-review", "doc", "research")


def test_candidate_contract_reexports_preserve_public_imports():
    contract = importlib.import_module("aegis_core.team_host_adapter")
    assert hosts.HostAdapterError is contract.HostAdapterError
    assert hosts.HostAdapter is contract.HostAdapter
    assert isinstance(hosts.host_adapter("antigravity"), contract.HostAdapter)


def test_candidate_import_has_no_service_dependency():
    result = subprocess.run(
        [sys.executable, "-c", "import sys; import aegis_core.team_host_agy; "
         "print('aegis_core.team_hosts' in sys.modules)"],
        cwd=Path(__file__).resolve().parents[3], capture_output=True, text=True, timeout=10, check=True)
    assert result.stdout == "False\n"
    assert result.stderr == ""


def test_candidate_adapter_lookup_uses_only_registry_configuration(monkeypatch):
    candidate = hosts.host_adapter("antigravity")
    imported = []
    registry = SimpleNamespace(resolve=lambda name: "other-kind",
                               get=lambda name: SimpleNamespace(team_adapter="example.adapter"))

    def load(module):
        imported.append(module)
        return SimpleNamespace(Adapter=lambda **kwargs: candidate)

    monkeypatch.setattr(hosts, "host_registry", registry)
    monkeypatch.setattr(hosts, "import_module", load)
    assert hosts.host_adapter("configured-alias") is candidate
    assert imported == ["example.adapter"]


@pytest.mark.parametrize("failure", [ImportError, AttributeError])
def test_candidate_adapter_import_failure_refuses_without_fallback(monkeypatch, failure):
    def unavailable(module):
        raise failure("untrusted diagnostic TOKEN=private")

    monkeypatch.setattr(hosts, "import_module", unavailable)
    with pytest.raises(hosts.HostAdapterError, match="^host_adapter_unavailable$"):
        hosts.host_adapter("antigravity")


def test_incomplete_candidate_interface_refuses(monkeypatch):
    monkeypatch.setattr(hosts, "import_module", lambda name: SimpleNamespace(Adapter=lambda **kwargs: object()))
    with pytest.raises(hosts.HostAdapterError, match="^host_adapter_unavailable$"):
        hosts.host_adapter("antigravity")


def test_generic_scrub_uses_every_registry_row_and_prefix(monkeypatch):
    rows = [*registry.all_hosts(), replace(registry.get("windsurf"), id="future-host",
        billing_variables=("FUTURE_KEY",), session_markers=("FUTURE_SESSION",),
        session_marker_prefixes=("FUTURE_CHILD_",))]
    monkeypatch.setattr(hosts, "host_registry", SimpleNamespace(all_hosts=lambda: tuple(rows)))
    source = {"PATH": "bin", "future_key": "private", "Future_Session": "foreign", "future_child_id": "foreign"}
    snapshot, child = hosts.scrub_child_environment(source)
    assert child == {"PATH": "bin"}
    assert snapshot == source and snapshot is not source


def _tools_environment_projection(rows):
    expected = {}
    for spec in rows:
        expected[spec.id] = {
            "billing_variables": spec.billing_variables,
            "session_variable": {"name": spec.session_variable, "verified_for_mcp": False},
            "session_markers": {
                "names": tuple(name for name in spec.session_markers
                               if name not in registry.TEAM_SESSION_MARKERS
                               and not name.startswith(spec.session_marker_prefixes)),
                "prefixes": spec.session_marker_prefixes}}
    # The native legacy kind is a surface alias of the core Codex plane.
    expected["codex"] = expected[registry.resolve("codex")]
    return expected


def _assert_tools_environment_projection(rows, catalog):
    def encoded(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")

    if encoded(catalog) != encoded(_tools_environment_projection(rows)):
        raise AssertionError("host environment catalog drift")


def test_tools_environment_catalog_is_exact_core_projection():
    _assert_tools_environment_projection(registry.all_hosts(), hierarchy_hosts.HOST_ENVIRONMENT)
    for kind in hierarchy_hosts.HOST_KINDS:
        row = hierarchy_hosts.entry(kind)
        observed = {key: row[key] for key in ("billing_variables", "session_variable", "session_markers")}
        assert json.dumps(observed, sort_keys=True) == json.dumps(hierarchy_hosts.HOST_ENVIRONMENT[kind], sort_keys=True)


@pytest.mark.parametrize("side", ("core", "tools", "both"))
def test_projection_guard_detects_future_hosts_in_either_catalog(side):
    rows = registry.all_hosts()
    catalog = deepcopy(hierarchy_hosts.HOST_ENVIRONMENT)
    if side in ("core", "both"):
        rows += (replace(registry.get("windsurf"), id="future-host", billing_variables=("FUTURE_KEY",),
                         session_variable="FUTURE_SESSION", session_markers=("FUTURE_SESSION",),
                         session_marker_prefixes=("FUTURE_CHILD_",)),)
    if side in ("tools", "both"):
        catalog["future-host"] = {
            "billing_variables": ("FUTURE_KEY",),
            "session_variable": {"name": "FUTURE_SESSION", "verified_for_mcp": False},
            "session_markers": {"names": ("FUTURE_SESSION",), "prefixes": ("FUTURE_CHILD_",)}}
    if side == "both":
        _assert_tools_environment_projection(rows, catalog)
    else:
        with pytest.raises(AssertionError, match="^host environment catalog drift$"):
            _assert_tools_environment_projection(rows, catalog)


@pytest.mark.parametrize("field", ("billing_variables", "session_variable", "session_markers", "session_marker_prefixes"))
@pytest.mark.parametrize("direction", ("missing", "extra"))
def test_projection_guard_detects_name_drift(field, direction):
    catalog = deepcopy(hierarchy_hosts.HOST_ENVIRONMENT)
    row = catalog["codex-cli"]
    if field == "billing_variables":
        row[field] = row[field][1:] if direction == "missing" else (*row[field], "FUTURE_KEY")
    elif field == "session_variable":
        row[field]["name"] = "" if direction == "missing" else "FUTURE_SESSION"
    elif field == "session_markers":
        names = row[field]["names"]
        row[field]["names"] = names[1:] if direction == "missing" else (*names, "FUTURE_MARKER")
    else:
        markers = catalog["claude-code"]["session_markers"]
        prefixes = markers["prefixes"]
        markers["prefixes"] = prefixes[1:] if direction == "missing" else (*prefixes, "FUTURE_CHILD_")
    with pytest.raises(AssertionError, match="^host environment catalog drift$"):
        _assert_tools_environment_projection(registry.all_hosts(), catalog)


def test_tools_only_registry_import_has_no_core_dependency():
    script = """import importlib.util, json, sys
sys.path.insert(0, sys.argv[1])
assert importlib.util.find_spec('aegis_core') is None
import hierarchy_hosts
assert importlib.util.find_spec('aegis_core') is None
assert 'aegis_core' not in sys.modules
print(json.dumps(hierarchy_hosts.describe()))
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", script,
                             str(Path(__file__).resolve().parents[3] / "tools")],
                            capture_output=True, text=True, timeout=10)
    assert (result.returncode, result.stderr) == (0, "")
    assert result.stdout == json.dumps(hierarchy_hosts.describe()) + "\n"


@pytest.mark.parametrize("direction", ("core-to-tools", "tools-to-core"))
@pytest.mark.parametrize("future", (False, True))
def test_registry_scrub_covers_legacy_host_environment_catalog(monkeypatch, direction, future):
    rows = registry.all_hosts()
    catalog = deepcopy(hierarchy_hosts.HOST_ENVIRONMENT)
    if future:
        rows += (replace(registry.get("windsurf"), id="future-host",
                         billing_variables=("FUTURE_KEY",), session_variable="FUTURE_SESSION",
                         session_markers=("FUTURE_SESSION",),
                         session_marker_prefixes=("FUTURE_CHILD_",)),)
        catalog["future-host"] = {
            "billing_variables": ["FUTURE_KEY"],
            "session_variable": {"name": "FUTURE_SESSION", "verified_for_mcp": False},
            "session_markers": {"names": ["FUTURE_SESSION"], "prefixes": ["FUTURE_CHILD_"]}}
    monkeypatch.setattr(hosts, "host_registry", SimpleNamespace(all_hosts=lambda: rows))
    monkeypatch.setattr(hierarchy_hosts, "HOST_ENVIRONMENT", catalog)
    monkeypatch.setattr(hierarchy_hosts, "os", SimpleNamespace(name="posix"))
    source = {"PATH": "bin"}
    if direction == "tools-to-core":
        for row in catalog.values():
            source.update({key.lower(): "foreign" for key in row["billing_variables"]})
            source.update({key.lower(): "foreign" for key in row["session_markers"]["names"]})
            if row["session_variable"]["name"]:
                source[row["session_variable"]["name"].lower()] = "foreign"
            source.update({prefix.lower() + "child": "foreign" for prefix in row["session_markers"]["prefixes"]})
        assert hosts.scrub_child_environment(source)[1] == {"PATH": "bin"}
    else:
        for row in rows:
            source.update({key: "foreign" for key in row.billing_variables})
            if row.session_variable:
                source[row.session_variable] = "foreign"
            source.update({key: "foreign" for key in row.session_markers
                           if key not in ("AEGIS_TEAM_HOST", "AEGIS_TEAM_SESSION")})
            source.update({prefix + "CHILD": "foreign" for prefix in row.session_marker_prefixes})
        assert hierarchy_hosts.child_environment(source, "no-host") == {"PATH": "bin"}


@pytest.mark.parametrize("kind", ("claude-code", "codex-cli", "codex"))
@pytest.mark.parametrize("platform", ("posix", "nt"))
@pytest.mark.parametrize("purpose", ("no-host", "host-cli"))
def test_legacy_environment_projection_preserves_policy(monkeypatch, kind, platform, purpose):
    from types import MappingProxyType

    monkeypatch.setattr(hierarchy_hosts, "os", SimpleNamespace(name=platform))
    billing, markers = {
        "claude-code": (("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
                         "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"),
                        ("CLAUDE_CODE_SESSION_ID", "CLAUDECODE", "CLAUDE_PID", "CLAUDE_EFFORT",
                         "CLAUDE_CODE_FUTURE_MARKER")),
        "codex-cli": (("OPENAI_API_KEY", "CODEX_API_KEY"),
                      ("CODEX_APPLY_PATCH_PRESERVE_LINE_ENDINGS", "CODEX_CI", "CODEX_SANDBOX_NETWORK_DISABLED",
                       "CODEX_SESSION_ID", "CODEX_THREAD_ID", "CODEX_TOOL_CALL_ID", "CODEX_VERSION")),
        "codex": (("OPENAI_API_KEY", "CODEX_API_KEY"),
                  ("CODEX_APPLY_PATCH_PRESERVE_LINE_ENDINGS", "CODEX_CI", "CODEX_SANDBOX_NETWORK_DISABLED",
                   "CODEX_SESSION_ID", "CODEX_THREAD_ID", "CODEX_TOOL_CALL_ID", "CODEX_VERSION")),
    }[kind]
    kept = {"PATH": "bin", "AEGIS_TEAM_HOST": "retained", "AEGIS_TEAM_SESSION": "retained",
            "TEAMS_GEMINI_MODE": "retained", "TEAMS_GEMINI_KEY_FILE": "retained"}
    source = {**kept, **{name: "modelled-value" for name in (*billing, *markers,
                                                           "GEMINI_API_KEY", "GOOGLE_API_KEY")}}
    source.update({name.lower(): value for name, value in list(source.items())})
    expected = dict(kept)
    expected.update({name.lower(): value for name, value in kept.items()})
    if platform == "posix":
        expected.update({name: value for name, value in source.items() if name.islower()})
    if purpose == "host-cli":
        allowed = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN") if kind == "claude-code" else billing
        expected.update({name: source[name] for name in (*allowed, "GEMINI_API_KEY", "GOOGLE_API_KEY")})
        if platform == "nt":
            expected.update({name.lower(): value for name, value in list(expected.items())})
    before = dict(source)
    for _ in range(2):
        child = hierarchy_hosts.child_environment(MappingProxyType(source), purpose)
        assert child == expected
        child["CALLER_CHANGE"] = "private"
        assert source == before
    assert hosts.scrub_child_environment(source)[1] == {"PATH": "bin", "path": "bin"}
    assert hierarchy_hosts.HOST_KINDS == ("claude-code", "codex-cli", "codex")


@pytest.mark.parametrize("platform", ("posix", "nt"))
def test_catalog_scrub_retries_and_concurrent_purposes_are_private(monkeypatch, platform):
    from concurrent.futures import ThreadPoolExecutor
    from types import MappingProxyType

    monkeypatch.setattr(hierarchy_hosts, "os", SimpleNamespace(name=platform))
    catalog = deepcopy(hierarchy_hosts.HOST_ENVIRONMENT)
    catalog["future-host"] = {
        "billing_variables": ("FUTURE_KEY",),
        "session_variable": {"name": "FUTURE_SESSION", "verified_for_mcp": False},
        "session_markers": {"names": ("FUTURE_SESSION",), "prefixes": ("FUTURE_CHILD_",)}}
    monkeypatch.setattr(hierarchy_hosts, "HOST_ENVIRONMENT", catalog)
    source = MappingProxyType({"PATH": "bin", "GEMINI_API_KEY": "modelled-value",
                               "GOOGLE_API_KEY": "modelled-value", "FUTURE_KEY": "modelled-value",
                               "FUTURE_SESSION": "foreign", "FUTURE_CHILD_ID": "foreign"})

    def observe(index):
        purpose = "host-cli" if index % 2 else "no-host"
        result = hierarchy_hosts.child_environment(source, purpose)
        expected = {"PATH": "bin"}
        if purpose == "host-cli":
            expected.update({name: source[name] for name in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "FUTURE_KEY")})
        assert result == expected
        result["CALLER_CHANGE"] = "private"
        assert "CALLER_CHANGE" not in source
        return result

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(observe, range(12)))
    assert observe(0) == results[0]
    assert observe(1) == results[1]


def test_candidate_description_projects_registry_markers(monkeypatch):
    row = replace(registry.get("antigravity"), session_markers=("FUTURE_SESSION",))
    monkeypatch.setattr(team_host_agy, "get", lambda kind: row)
    adapter = hosts.host_adapter("antigravity")
    first = adapter.describe()
    assert first["session_markers"] == ["FUTURE_SESSION"]
    first["session_markers"].append("CALLER_CHANGE")
    assert adapter.describe()["session_markers"] == ["FUTURE_SESSION"]


@pytest.mark.parametrize("cycle_size", (2, 4, 8))
def test_all_restarted_plans_have_bounded_validation_work(monkeypatch, cycle_size):
    writers = [f"w{i:02d}" for i in range(cycle_size)]
    reviewers = [f"r{i:02d}" for i in range(cycle_size)]
    document = {"version": 1, "preset": "ci-only", "model_settings": {
        "hosts": {**{name: {"kind": "codex-cli"} for name in writers},
                  **{name: {"kind": "claude-code"} for name in reviewers}},
        "roles": {"writer": {"hosts": [writers[0]]},
                  "reviewer.correctness": {"hosts": [reviewers[0]]}},
        "capacity": {**{name: {"fallback": {"writer": [writers[(i + 1) % cycle_size]]}}
                        for i, name in enumerate(writers)},
                     **{name: {"fallback": {"review": [reviewers[(i + 1) % cycle_size]]}}
                        for i, name in enumerate(reviewers)}}},
        "policy": {"review": {"require_cross_family": True, "lenses": [
            {"name": f"lens-{i:02d}", "host_pref": [reviewers[0]], "voting": True}
            for i in range(16)]}}}
    assert len(json.dumps(document).encode("utf-8")) <= profile.MAX_BYTES
    counts = Counter()
    plan_calls = Counter()
    original_plan = profile.plan
    kinds = ["writer", "reviewer.correctness", *[f"lens-{i:02d}" for i in range(16)]]
    expected_plans = {(kind, None) for kind in kinds}
    expected_plans.update((kind, host) for kind in kinds
                          for host in (writers if kind == "writer" else reviewers))
    expected_plans.update(("doc", host) for host in [*writers, *reviewers])
    limit = 8 * (len(kinds) + 1) * (2 * cycle_size)

    class Family(str):
        def __eq__(self, other):
            counts["family_comparisons"] += 1
            assert counts["family_comparisons"] <= limit, dict(counts)
            return str.__eq__(self, other)

        def __ne__(self, other):
            return not self == other

        def __hash__(self):
            counts["family_memberships"] += 1
            return str.__hash__(self)

    class HostFacts(dict):
        def __getitem__(self, key):
            if key == "family":
                counts["family_lookups"] += 1
            return super().__getitem__(key)

    registry = deepcopy(profile.PRESET_DATA)
    for kind, host in registry["hosts"].items():
        host["family"] = Family(host["family"])
        registry["hosts"][kind] = HostFacts(host)
    monkeypatch.setattr(profile, "PRESET_DATA", registry)

    def counted_plan(document, kind, *, start_host=None):
        plan_calls[kind, start_host] += 1
        return original_plan(document, kind, start_host=start_host)

    monkeypatch.setattr(profile, "plan", counted_plan)

    def assert_work():
        assert plan_calls == Counter({key: 1 for key in expected_plans})
        assert counts["family_lookups"] == 2 * cycle_size
        assert counts["family_comparisons"] + counts["family_memberships"] <= limit
        print("validation work:", cycle_size, sum(plan_calls.values()), dict(counts))

    result = profile.resolve(repo=document)
    assert_work()
    # The consumer must revalidate with a fresh memo, never trust a prior load.
    plan_calls.clear()
    counts.clear()
    hosts.HostCapacity(result)
    assert_work()


def dense_review_profile(host_count=16, chain_size=8, lens_count=16, edge_hosts=8):
    names = [f"h{i:02d}" for i in range(host_count)]
    return {"version": 1, "preset": "ci-only", "model_settings": {
        "hosts": {name: {"kind": "codex-cli"} for name in names},
        "roles": {kind: {"hosts": names[:1]} for kind in ("writer", "reviewer.correctness")},
        "capacity": {name: {"fallback": {"review": [names[(i + offset) % host_count]
                     for offset in range(1, chain_size + 1)]}} for i, name in enumerate(names[:edge_hosts])}},
        "policy": {"review": {"require_cross_family": False, "lenses": [
            {"name": f"audit{i:02d}", "host_pref": names[:1], "voting": True}
            for i in range(lens_count)]}}}


@pytest.mark.parametrize("violation,path", [
    ("hosts", "model_settings.hosts"),
    ("chain", "model_settings.capacity.h00.fallback.review"),
    ("lenses", "policy.review.lenses"),
    ("extra-lens", "policy.review.lenses"),
    ("edges", "model_settings.capacity"),
    ("role-binding", "model_settings.roles.writer.hosts"),
    ("lens-binding", "policy.review.lenses.0.host_pref"),
    ("reviewer-profile", "model_settings.hosts"),
])
@pytest.mark.parametrize("surface", ("resolve", "consumer"))
def test_routing_limits_refuse_before_planning(monkeypatch, violation, path, surface):
    document = dense_review_profile()
    settings = document["model_settings"]
    if violation == "hosts":
        settings["hosts"]["overflow"] = {"kind": "codex-cli"}
    elif violation == "chain":
        settings["capacity"] = {"h00": {"fallback": {"review": ["h00"] * 9}}}
    elif violation == "lenses":
        document["policy"]["review"]["lenses"].append({"name": "overflow", "host_pref": ["h00"]})
    elif violation == "extra-lens":
        settings["roles"]["lens.extra"] = {"hosts": ["h00"], "optional": True}
    elif violation == "edges":
        settings["capacity"]["h15"] = {"fallback": {"writer": ["h00"]}}
    elif violation == "role-binding":
        settings["roles"]["writer"]["hosts"] = ["h00"] * 17
    elif violation == "lens-binding":
        document["policy"]["review"]["lenses"][0]["host_pref"] = ["h00"] * 17
    else:
        document = dense_review_profile(64, 40, 64, 64)
    if surface == "consumer":
        resolved = profile.resolve(preset="ci-only")
        resolved["profile"]["model_settings"].update(document["model_settings"])
        resolved["profile"]["policy"]["review"].update(document["policy"]["review"])

    def forbidden(*args, **kwargs):
        pytest.fail("traversal started before refusing an oversized routing graph")

    monkeypatch.setattr(profile, "plan", forbidden)
    with pytest.raises(profile.ProfileError, match="limit exceeded") as refused:
        if surface == "resolve":
            profile.resolve(repo=document)
        else:
            hosts.HostCapacity(resolved)
    assert refused.value.exit_code == 1 and refused.value.layer == "repo"
    assert refused.value.file == "/".join(profile.REPO_PATH) and refused.value.path == path


def test_dense_routing_counts_edges_and_queue_operations(monkeypatch):
    document = dense_review_profile(lens_count=15)
    settings = document["model_settings"]
    names = list(settings["hosts"])
    roles = profile.JSON_SCHEMA["properties"]["model_settings"]["properties"]["roles"]["properties"]
    settings["roles"] = {kind: {"hosts": names} for kind in roles}
    kinds = [*roles, *[lens["name"] for lens in document["policy"]["review"]["lenses"]]]
    counts, plans = Counter(), Counter()
    original_plan = profile.plan

    class CountedDeque(deque):
        def __init__(self, roots):
            super().__init__(roots)
            counts["traversals"] += 1
            counts["pushes"] += len(self)

        def popleft(self):
            counts["pops"] += 1
            return super().popleft()

        def extendleft(self, entries):
            for entry in entries:
                counts["edges"] += 1
                counts["pushes"] += 1
                super().appendleft(entry)

    def counted_plan(document, kind, *, start_host=None):
        plans[kind, start_host] += 1
        return original_plan(document, kind, start_host=start_host)

    monkeypatch.setattr(profile, "deque", CountedDeque)
    monkeypatch.setattr(profile, "plan", counted_plan)

    def assert_work():
        expected = {(kind, start) for kind in kinds for start in [None, *names]}
        expected.update(("doc", name) for name in names)
        assert plans == Counter({key: 1 for key in expected})
        assert counts["traversals"] > 0, "planner did not use the instrumented deque"
        # Each plan has at most two walks, each visiting every declared edge
        # once and seeding at most hosts + one terminal queue entries.
        max_jobs = len(roles) + profile.MAX_LENSES + 1
        traversals = 2 * max_jobs * (profile.MAX_HOSTS + 1)
        edge_bound = traversals * profile.MAX_FALLBACK_EDGES
        queue_bound = 2 * traversals * (profile.MAX_HOSTS + 1 + profile.MAX_FALLBACK_EDGES)
        assert 0 < counts["edges"] <= edge_bound
        assert counts["pushes"] == counts["pops"]
        assert counts["pushes"] + counts["pops"] <= queue_bound
        assert counts["traversals"] == 2 * len(expected) - len(kinds)
        print("dense routing work:", dict(counts), "edge bound:", edge_bound, "queue bound:", queue_bound)

    result = profile.resolve(repo=document)
    assert_work()
    counts.clear()
    plans.clear()
    hosts.HostCapacity(result)
    assert_work()


def resolved(kind="doc", chain=None, *, source="subscription-window", pinned=False):
    settings = {
        "hosts": {"other": {"kind": "claude-code"}},
        "capacity": {"primary": {"usage_source": source,
                                  "thresholds": {"hold_pct": 95, "route_pct": 85, "flex_route_pct": 70},
                                  "fallback": {kind: [] if chain is None else chain}},
                     "other": {"usage_source": source}},
    }
    if pinned:
        settings["roles"] = {"research": {"pinned_family": True}}
    if kind in ("extra-review", "lens.extra"):
        settings.setdefault("roles", {})["lens.extra"] = {"hosts": ["primary"], "optional": True}
    return profile.resolve(repo={"model_settings": settings})


def adapter(primary=96, other=10):
    return hosts.FakeUsageAdapter({
        "primary": {"window": {"used_pct": primary, "resets_at": RESET}},
        "other": {"window": {"used_pct": other, "resets_at": RESET}},
    })


@pytest.mark.parametrize("preset", ("pair", "mixed"))
@pytest.mark.parametrize("terminal", ("hold", "skip"))
def test_arg0942_terminal_does_not_disable_a_separately_bound_host(preset, terminal):
    result = profile.resolve(repo={"version": 1, "preset": preset, "model_settings": {
        "capacity": {"primary": {"usage_source": "credits", "fallback": {"research": [terminal]}},
                     "review": {"usage_source": "credits"}}}})
    service = hosts.HostCapacity(result, adapter=hosts.FakeUsageAdapter({
        "primary": {"credits_left": 0}, "review": {"credits_left": 1}}))
    assert service.check("primary", "research")["decision"] == terminal
    assert service.check("review", "research")["decision"] == "go"
    review = next(row for row in service.status() if row["host"] == "review")
    assert next(row for row in review["decisions"] if row["kind"] == "research")["decision"] == "go"


def test_arg0942_hidden_bound_host_keeps_later_binding_destinations():
    result = profile.resolve(repo={"model_settings": {
        "hosts": {"other": {"kind": "claude-code"}, "last": {"kind": "codex-cli"}},
        "roles": {"research": {"hosts": ["primary", "other", "last"]}},
        "capacity": {"primary": {"usage_source": "credits", "fallback": {"research": ["hold"]}},
                     "other": {"usage_source": "credits"}, "last": {"usage_source": "credits"}}}})
    service = hosts.HostCapacity(result, adapter=hosts.FakeUsageAdapter({
        "primary": {"credits_left": 0}, "other": {"credits_left": 0}, "last": {"credits_left": 1}}))
    assert service.check("other", "research")["decision"] == "fallback:last"


def test_arg0942_pinned_fallback_host_is_still_unbound():
    result = profile.resolve(repo={"preset": "pair", "model_settings": {
        "roles": {"research": {"hosts": ["primary"], "pinned_family": True}},
        "capacity": {"primary": {"fallback": {"research": ["review"]}}}}})
    with pytest.raises(profile.ProfileError, match="host is not bound to this job") as refused:
        hosts.HostCapacity(result).check("review", "research")
    assert refused.value.exit_code == 1 and refused.value.layer == "repo"
    assert refused.value.path == "model_settings.roles.research.hosts"


@pytest.mark.parametrize("preset", ("pair", "mixed"))
@pytest.mark.parametrize("role,other_kind,tail,message", [
    ("reviewer.correctness", "claude-code", "skip", "skip is allowed only for non-voting jobs"),
    ("reviewer.correctness", "claude-code", "primary", "cross-family review route reaches the writer family"),
    ("reviewer.security", "codex-cli", "review", "pinned lens fallback changes family"),
])
def test_arg0942_hidden_bound_host_exposes_policy_with_correct_attribution(preset, role, other_kind, tail, message):
    first = "primary" if role == "reviewer.security" else "review"
    with pytest.raises(profile.ProfileError, match=message) as refused:
        profile.resolve(repo={"preset": preset, "model_settings": {
            "hosts": {"other": {"kind": other_kind}},
            "roles": {role: {"hosts": [first, "other"]}},
            "capacity": {first: {"fallback": {"review": ["hold"]}},
                         "other": {"fallback": {"review": [tail]}}}}})
    assert refused.value.exit_code == 1 and refused.value.layer == "repo"
    assert refused.value.path == "model_settings.capacity.other.fallback.review"


@pytest.mark.parametrize("terminal", ("hold", "skip"))
@pytest.mark.parametrize("kind", (*profile.CAPACITY_KINDS, "audit-vote", "audit-flex"))
def test_unvalidated_host_map_cannot_shadow_a_terminal(terminal, kind):
    if kind.startswith("audit-"):
        raw = profile.resolve(repo={"policy": {"review": {"lenses": [
            {"name": kind, "host_pref": ["primary"], "voting": kind == "audit-vote"}]}}})["profile"]
        key = "review"
    else:
        raw = resolved(kind)["profile"]
        key = kind
    settings = raw["model_settings"]
    settings["hosts"][terminal] = {"kind": "claude-code"}
    settings["capacity"].setdefault("primary", {}).setdefault("fallback", {})[key] = [terminal]
    route = profile.plan(raw, kind, start_host="primary")
    assert route["entries"] == [{"host": "primary", "path": route["path"]},
                                 {"terminal": terminal, "path": "model_settings.capacity.primary.fallback." + key}]


@pytest.mark.parametrize("terminal,code", (("hold", 3), ("skip", 5)))
def test_terminal_precedes_host_lookup_after_consumer_validation(terminal, code):
    snapshot = resolved(source="credits")
    reader = hosts.FakeUsageAdapter({"primary": {"credits_left": 0}, terminal: {"credits_left": 1}})
    service = hosts.HostCapacity(snapshot, adapter=reader)
    settings = snapshot["profile"]["model_settings"]
    settings["hosts"][terminal] = {"kind": "claude-code"}
    settings["capacity"][terminal] = {"usage_source": "credits"}
    settings["capacity"]["primary"]["fallback"]["doc"] = [terminal]
    result = service.check("primary", "doc")
    assert result["decision"] == terminal and result["exit_code"] == code
    assert [name for name, _ in reader.calls] == ["primary"]


@pytest.mark.parametrize("terminal", ("hold", "skip"))
@pytest.mark.parametrize("binding", ("role", "lens"))
def test_unvalidated_binding_cannot_treat_a_terminal_as_a_host(terminal, binding):
    raw = profile.resolve(repo={"policy": {"review": {"lenses": [
        {"name": "audit", "host_pref": ["primary"], "voting": False}]}}})["profile"]
    raw["model_settings"]["hosts"][terminal] = {"kind": "claude-code"}
    if binding == "role":
        raw["model_settings"]["roles"]["research"]["hosts"] = [terminal]
        kind, path = "research", "model_settings.roles.research.hosts"
    else:
        raw["policy"]["review"]["lenses"][0]["host_pref"] = [terminal]
        kind, path = "audit", "policy.review.lenses"
    assert profile.plan(raw, kind)["entries"] == [{"terminal": terminal, "path": path}]


@pytest.mark.parametrize("kind", (*[kind for kind in profile.CAPACITY_KINDS if kind != "doc"], "audit-vote", "audit-flex"))
@pytest.mark.parametrize("start", ("primary", "other", "last"))
@pytest.mark.parametrize("backward", (False, True))
def test_arg1138_restart_uses_its_own_declared_binding_position(kind, start, backward):
    canonical = {"review": "reviewer.correctness", "extra-review": "lens.extra"}.get(kind, kind)
    lens = kind.startswith("audit-")
    key = "review" if lens else kind
    binding = ["primary", "other", "last"]
    document = {"preset": "ci-only", "model_settings": {
        "hosts": {name: {"kind": "codex-cli"} for name in binding},
        "roles": {} if lens else {canonical: {"hosts": binding}},
        "capacity": {"primary": {"fallback": {key: ["last"]}},
                     "last": {"fallback": {key: ["other"]}} if backward else {}}}}
    if lens:
        document["policy"] = {"review": {"lenses": [
            {"name": kind, "host_pref": binding, "voting": kind == "audit-vote"}]}}
    raw = profile.resolve(repo=document)["profile"]
    expected = {"primary": ["primary", "last", "other"], "other": ["other", "last"],
                "last": ["last", "other"] if backward else ["last"]}
    assert [entry["host"] for entry in profile.plan(raw, kind, start_host=start)["entries"]] == expected[start]


@pytest.mark.parametrize("backward", (False, True))
def test_arg1138_fallback_only_start_uses_only_its_explicit_routes(backward):
    names = ("primary", "other", "last", "extra")
    settings = {"hosts": {name: {"kind": "codex-cli"} for name in names},
                "roles": {"writer": {"hosts": list(names[:3])}},
                "capacity": {name: {"usage_source": "credits"} for name in names}}
    settings["capacity"]["primary"]["fallback"] = {"writer": ["last"]}
    settings["capacity"]["last"]["fallback"] = {"writer": ["extra"]}
    if backward:
        settings["capacity"]["extra"]["fallback"] = {"writer": ["other"]}
    reader = hosts.FakeUsageAdapter({name: {"credits_left": int(name == "other")} for name in names})
    result = hosts.HostCapacity(profile.resolve(preset="ci-only", repo={"model_settings": settings}),
                                adapter=reader).check("extra", "writer")
    assert result["decision"] == ("fallback:other" if backward else "hold")
    assert result["exit_code"] == (4 if backward else 3)
    assert [name for name, _ in reader.calls] == (["extra", "other"] if backward else ["extra"])


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("used,chain,other,expected", [
    (10, [], 10, "go"), (96, [], 10, "hold"),
    (96, ["other"], 10, "fallback:other"), (96, ["other"], 100, "hold"),
    (96, ["hold", "other"], 10, "hold"),
])
def test_decision_paths_per_kind(kind, used, chain, other, expected):
    service = hosts.HostCapacity(resolved(kind, chain), adapter=adapter(used, other))
    result = service.check("primary", kind)
    assert result["decision"] == expected
    assert result["reason"] and result["next_action"]
    if expected == "hold":
        assert RESET in result["next_action"]


@pytest.mark.parametrize("kind", ("doc", "research", "extra-review"))
def test_nonvoting_skip(kind):
    result = hosts.HostCapacity(resolved(kind, ["skip"]), adapter=adapter()).check("primary", kind)
    assert result["decision"] == "skip" and result["exit_code"] == 5


@pytest.mark.parametrize("kind", ("writer", "review"))
def test_voting_or_writer_skip_is_policy_refusal(kind):
    with pytest.raises(profile.ProfileError, match="skip"):
        resolved(kind, ["skip"])


def test_flexible_jobs_route_before_lane_votes():
    service = hosts.HostCapacity(resolved(), adapter=adapter(75))
    assert service.check("primary", "review")["decision"] == "go"
    assert service.check("primary", "doc")["decision"] == "hold"


@pytest.mark.parametrize("kind", ("research", "reviewer.security", "security-audit"))
def test_pinned_lens_holds_without_trying_fallback(kind):
    doc = {"model_settings": {"hosts": {"other": {"kind": "claude-code"}},
                              "capacity": {"primary": {"usage_source": "subscription-window",
                                                       "fallback": {"research": ["other"], "doc": ["other"]}}},
                              "roles": {"research": {"pinned_family": True},
                                        "reviewer.security": {"pinned_family": True}}},
           "policy": {"review": {"lenses": [{"name": "security-audit", "host_pref": ["primary"],
                                               "pinned_family": True, "voting": False}]}}}
    fake = adapter()
    result = hosts.HostCapacity(profile.resolve(repo=doc), adapter=fake).check("primary", kind)
    assert result["decision"] == "hold" and "pinned" in result["reason"]
    assert [name for name, _ in fake.calls] == ["primary"]


def test_role_chain_and_fallback_chain_are_both_followed_in_order():
    doc = resolved("research", ["other"])
    doc["profile"]["model_settings"]["roles"]["research"]["hosts"] = ["primary", "other"]
    fake = adapter()
    service = hosts.HostCapacity(doc, adapter=fake)
    assert service.check("primary", "research")["decision"] == "fallback:other"
    assert [name for name, _ in fake.calls] == ["primary", "other"]


def test_adapter_failure_is_unknown_for_that_host_only():
    fake = hosts.FakeUsageAdapter({"primary": RuntimeError("token=private\ntraceback"),
                                   "other": {"window": {"used_pct": 100, "resets_at": RESET}}})
    service = hosts.HostCapacity(resolved(), adapter=fake)
    first = service.check("primary", "doc")
    assert first["decision"] == "go" and "unknown" in first["reason"]
    assert "private" not in str(first)
    assert service.check("other", "doc")["decision"] == "hold"


@pytest.mark.parametrize("value", [None, [], {"window": {}},
    {"window": {"used_pct": float("nan"), "resets_at": RESET}},
    {"window": {"used_pct": True, "resets_at": RESET}},
    {"window": {"used_pct": 101, "resets_at": RESET}},
    {"window": {"used_pct": 90, "resets_at": "x" * 5000}},
    {"window": {"used_pct": 90, "resets_at": RESET + "\nforged"}},
])
def test_malformed_adapter_snapshot_is_unknown(value):
    result = hosts.HostCapacity(resolved(), adapter=hosts.FakeUsageAdapter({"primary": value})).check("primary", "doc")
    assert result["decision"] == "go" and "unknown" in result["reason"]


@pytest.mark.parametrize("credits,decision", [(5, "go"), (0, "hold")])
def test_credits_are_per_host(credits, decision):
    fake = hosts.FakeUsageAdapter({"primary": {"credits_left": credits, "tokens": 40, "runs": 2},
                                   "other": {"credits_left": 20}})
    service = hosts.HostCapacity(resolved(source="credits"), adapter=fake)
    assert service.check("primary", "doc")["decision"] == decision
    rows = service.usage()
    assert rows[0]["usage"] == {"credits_left": credits, "tokens": 40, "runs": 2}
    assert rows[1]["usage"] == {"credits_left": 20}


def test_none_source_never_calls_adapter_and_solo_never_invents_host():
    fake = hosts.FakeUsageAdapter({})
    service = hosts.HostCapacity(profile.resolve(), adapter=fake)
    assert service.check("primary", "doc")["decision"] == "go"
    assert fake.calls == []
    doc = profile.resolve(repo={"model_settings": {"capacity": {"primary": {"usage_source": "subscription-window"}}}})
    assert hosts.HostCapacity(doc, adapter=adapter()).check("primary", "doc")["decision"] == "hold"


def test_unconfigured_readers_are_explicit_extension_points():
    service = hosts.HostCapacity(resolved())
    row = service.usage()[0]
    assert row["usage_source"] == "subscription-window" and row["usage_status"] == "unknown"
    assert "adapter" in row["reason"] and row["next_action"]


@pytest.mark.parametrize("kind", ("writer", "review", "extra-review", "doc", "research"))
def test_cycles_exhaust_without_recursion(kind):
    doc = resolved(kind, ["other"])
    doc["profile"]["model_settings"]["capacity"]["other"]["fallback"] = {kind: ["primary"]}
    assert hosts.HostCapacity(doc, adapter=adapter(100, 100)).check("primary", kind)["decision"] == "hold"


@pytest.mark.parametrize("thresholds", [{"hold_pct": 50, "route_pct": 80},
    {"route_pct": 50, "flex_route_pct": 80}])
def test_inconsistent_thresholds_are_closed_profile_refusals(thresholds):
    with pytest.raises(profile.ProfileError, match="threshold"):
        profile.resolve(repo={"model_settings": {"capacity": {"primary": {"thresholds": thresholds}}}})


def test_review_fallback_policy_still_refuses_family_changes():
    with pytest.raises(profile.ProfileError, match="pinned"):
        profile.resolve(preset="pair", repo={"model_settings": {
            "capacity": {"primary": {"fallback": {"reviewer.security": ["review"]}}}}})


def test_adapter_unknown_never_relaxes_role_binding():
    with pytest.raises(profile.ProfileError, match="bound"):
        hosts.HostCapacity(profile.resolve(preset="pair"), adapter=hosts.FakeUsageAdapter({})).check("review", "reviewer.security")


def test_input_profile_is_not_mutated():
    doc = resolved()
    before = deepcopy(doc)
    hosts.HostCapacity(doc, adapter=adapter()).status()
    assert doc == before


def test_writer_fallback_cannot_reach_correctness_family():
    with pytest.raises(profile.ProfileError, match="cross-family"):
        profile.resolve(preset="pair", repo={"model_settings": {
            "capacity": {"primary": {"fallback": {"writer": ["review"]}}}}})


def test_disabled_extra_lens_refuses_even_when_usage_is_unknown():
    with pytest.raises(profile.ProfileError, match="disabled"):
        hosts.HostCapacity(profile.resolve(preset="mixed")).check("primary", "extra-review")


def test_custom_lens_cannot_override_a_builtin_job_kind():
    with pytest.raises(profile.ProfileError, match="reserved"):
        profile.resolve(repo={"policy": {"review": {"lenses": [
            {"name": "writer", "host_pref": ["primary"], "voting": False}]}}})


@pytest.mark.parametrize("kind", ("lens.extra", "extra-review", "reviewer.correctness", "reviewer.security"))
def test_all_review_route_aliases_preserve_family_policy(kind):
    with pytest.raises(profile.ProfileError, match="pinned|cross-family"):
        profile.resolve(preset="pair", repo={"model_settings": {
            "roles": {"lens.extra": {"hosts": ["primary"], "pinned_family": True, "optional": True}},
            "capacity": {"primary" if kind in ("lens.extra", "extra-review", "reviewer.security") else "review": {
                "fallback": {kind: ["review" if kind != "reviewer.correctness" else "primary"]}}}}})


@pytest.mark.parametrize("alias,route", [("review", "reviewer.correctness"), ("extra-review", "lens.extra")])
def test_job_alias_uses_the_declared_role_fallback(alias, route):
    service = hosts.HostCapacity(resolved(route, ["other"]), adapter=adapter())
    assert service.check("primary", alias)["decision"] == "fallback:other"


@pytest.mark.parametrize("failure", (TimeoutError(), OSError(), ValueError()))
def test_usage_boundary_failures_remain_unknown(failure):
    result = hosts.HostCapacity(resolved(), adapter=hosts.FakeUsageAdapter({"primary": failure})).check("primary", "doc")
    assert result["decision"] == "go" and "unknown" in result["reason"]


@pytest.mark.parametrize("source,snapshot", [("credits", {"credits_left": -1}),
    ("credits", {"credits_left": True}), ("credits", {"credits_left": float("inf")}),
    ("subscription-window", {"window": {"used_pct": 10, "resets_at": RESET}, "tokens": -1}),
    ("subscription-window", {"window": {"used_pct": 10, "resets_at": RESET}, "runs": True})])
def test_bad_credits_and_counters_never_become_advice(source, snapshot):
    result = hosts.HostCapacity(resolved(source=source), adapter=hosts.FakeUsageAdapter({"primary": snapshot})).check("primary", "doc")
    assert result["decision"] == "go" and "unknown" in result["reason"]


@pytest.mark.parametrize("layer", ("flags",))
@pytest.mark.parametrize("role", ("writer", "research", "reviewer.correctness", "reviewer.security", "lens.extra"))
@pytest.mark.parametrize("field,value", [("pinned_family", False), ("pinned_family", True), ("optional", False)])
def test_argon_role_policy_fields_are_repository_only(layer, role, field, value):
    with pytest.raises(profile.ProfileError, match="repository-only") as refused:
        profile.resolve(**{layer: {"model_settings": {"roles": {role: {field: value}}}}})
    assert refused.value.layer == layer and refused.value.file


@pytest.mark.parametrize("role", ("writer", "research"))
@pytest.mark.parametrize("field,value", [("pinned_family", False), ("pinned_family", True), ("optional", False)])
@pytest.mark.parametrize("preset", ("solo", "ci-only"))
def test_user_role_policy_is_ignored_with_reason(role, field, value, preset):
    baseline = profile.resolve(preset=preset)
    result = profile.resolve(preset=preset, user={"model_settings": {"roles": {role: {field: value}}}})
    assert result["profile"] == baseline["profile"]
    record = result["values"]["user.model_settings.roles." + role + "." + field]
    assert record["status"] == "ignored" and record["reason"] == "repository-only"
    assert record["applied_paths"] == []


@pytest.mark.parametrize("repo_thresholds,user_thresholds", [({"route_pct": 85}, {"hold_pct": 70}),
    ({"hold_pct": 80}, {"route_pct": 90}), ({"flex_route_pct": 80}, {"route_pct": 70})])
def test_argon_incompatible_user_thresholds_are_ignored(repo_thresholds, user_thresholds):
    result = profile.resolve(repo={"model_settings": {"capacity": {"primary": {"thresholds": repo_thresholds}}}},
                             user={"model_settings": {"capacity": {"codex-cli": {"thresholds": user_thresholds}}}})
    assert result["profile"]["model_settings"]["capacity"]["primary"]["thresholds"] == repo_thresholds
    for field in user_thresholds:
        record = result["values"]["user.model_settings.capacity.codex-cli.thresholds." + field]
        assert record["status"] == "ignored" and "threshold" in record["reason"]
        assert record["applied_paths"] == []


@pytest.mark.parametrize("fields", [[("hold_pct", 70), ("route_pct", 60)], [("route_pct", 60), ("hold_pct", 70)]])
def test_argon_valid_user_threshold_group_is_order_independent(fields):
    result = profile.resolve(repo={"model_settings": {"capacity": {"primary": {"thresholds": {"route_pct": 85}}}}},
                             user={"model_settings": {"capacity": {"codex-cli": {"thresholds": dict(fields)}}}})
    assert result["profile"]["model_settings"]["capacity"]["primary"]["thresholds"] == dict(fields)
