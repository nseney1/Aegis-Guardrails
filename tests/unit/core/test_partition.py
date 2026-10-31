"""The AST partition report (v4.2 #5): which edges cross between planned lanes.

Lanes are planned as globs (``--split A=a/** --split B=b/**``). The report builds the
def, call and import sets of every lane file with the Python driver (and the Rust driver
when it is enabled), resolves the names through each file's imports, and reports the
edges that cross a lane boundary plus the signatures of the functions on the boundary,
which the lanes must not change while they run in parallel. It is a report: it changes
nothing, and it is exact only for what static name resolution through imports can see.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from typing import Dict

import pytest

from aegis_cli.formatters.text import render_partition
from aegis_core import events, partition
from aegis_core._version import __version__
from tests.helpers_checkmodes import commit, init_repo, write

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

TS = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")

SVC = '''"""Lane B's service."""
from typing import Optional


def work(x, y=0):
    return x + y


async def fetch(url: str, *, retries: int = 3) -> Optional[bytes]:
    return None


def helper(n: int) -> int:
    return n * 2


class Client(object):
    def __init__(self, url: str, timeout: float = 1.0):
        self.url = url


class Plain:
    pass


def _private():
    return 0
'''
API = '''from b import svc
from b.svc import helper, Client, Plain


def run():
    client = Client("u")
    return svc.work(1) + helper(2) + len(str(Plain()))
'''


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = init_repo(tmp_path / "project", rules=False)
    write(root, "a/__init__.py", "")
    write(root, "a/api.py", API)
    write(root, "a/local.py", "def local():\n    return 1\n")
    write(root, "b/__init__.py", "")
    write(root, "b/svc.py", SVC)
    write(root, "b/inner.py", "from b.svc import work\n\n\ndef inner():\n    return work(1)\n")
    write(root, "c/other.py", "from b import svc\n\n\ndef other():\n    return svc.work(2)\n")  # in no lane
    commit(root, "base")
    return root


def _splits(**lanes: str) -> Dict[str, tuple]:
    return partition.parse_splits([f"{name}={globs}" for name, globs in lanes.items()])


AB = {"A": "a/**", "B": "b/**"}


def _edges(report, kind=None):
    rows = report.as_dict()["edges"]
    return [(e["kind"], e["from"], e["line"], e["to"], e["symbol"]) for e in rows if kind in (None, e["kind"])]


def _tree(root: Path) -> Dict[str, str]:
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file() and ".git" not in p.relative_to(root).parts}


# ── --split ──────────────────────────────────────────────────────────────────

def test_splits_become_named_glob_tuples_in_order():
    parsed = partition.parse_splits(["A=a/**, x/*.py", "B=b", "C=z/**,z/**"])
    assert list(parsed) == ["A", "B", "C"]
    assert parsed == {"A": ("a/**", "x/*.py"), "B": ("b",), "C": ("z/**",)}


def test_globs_are_normalized_like_rule_paths():
    assert partition.parse_splits(["A=./a/**", "B=\\b\\**"]) == {"A": ("a/**",), "B": ("b/**",)}


@pytest.mark.parametrize("values, message", [
    ([], "--partition needs at least 2 --split NAME=GLOB[,GLOB...]"),
    (["A=a"], "--partition needs at least 2 --split NAME=GLOB[,GLOB...]"),
    (["A=a", "A=b"], "--split: lane A is given twice"),
    (["A=a", "B"], "--split: 'B' is not NAME=GLOB[,GLOB...]"),
    (["A=a", "=b"], "--split: '=b' is not NAME=GLOB[,GLOB...]"),
    (["A=a", "B="], "--split: lane B has no glob"),
    (["A=a", "B=b,"], "--split: lane B has an empty glob"),
    (["A=a", "B=../b"], "--split: lane B: glob '../b' climbs out of the workspace with '..'"),
    (["A=a", "B=b\x01"], "--split: lane B has a glob with a control character"),
    (["A=a", "x y=b"], "--split: lane name 'x y' must match [A-Za-z0-9][A-Za-z0-9._-]*"),
])
def test_a_bad_split_is_a_usage_error_with_its_reason(values, message):
    with pytest.raises(partition.PartitionUsage) as info:
        partition.parse_splits(values)
    assert str(info.value) == message


# ── Lanes and files ──────────────────────────────────────────────────────────

def test_each_lane_owns_the_files_its_globs_match_and_the_rest_belong_to_none(repo: Path):
    data = partition.check(repo, _splits(**AB), record=False).as_dict()
    lanes = {row["name"]: row for row in data["lanes"]}
    assert lanes["A"]["files"] == 3 and lanes["B"]["files"] == 3  # __init__, plus api/local and svc/inner
    assert lanes["A"]["globs"] == ["a/**"]
    assert data["overlap"] == [] and data["scope"]["unassigned"] == 1  # c/other.py


def test_a_glob_without_a_slash_matches_at_any_depth_as_a_rule_path_does(repo: Path):
    write(repo, "deep/er/svc.py", "x = 1\n")
    data = partition.check(repo, _splits(A="a/**", B="svc.py"), record=False).as_dict()
    assert {row["name"]: row["files"] for row in data["lanes"]}["B"] == 2  # b/svc.py and deep/er/svc.py


def test_a_file_in_two_lanes_is_an_overlap_and_takes_no_part_in_the_edges(repo: Path):
    report = partition.check(repo, _splits(A="a/**", B="b/**,a/api.py"), record=False)
    data = report.as_dict()
    assert data["overlap"] == [{"path": "a/api.py", "lanes": ["A", "B"]}]
    assert _edges(report) == []  # a/api.py was the only crossing file
    assert "overlap" in "\n".join(render_partition(report.as_dict())) and "a/api.py (A, B)" in "\n".join(render_partition(report.as_dict()))


# ── Edges ────────────────────────────────────────────────────────────────────

def test_import_edges_name_the_file_and_the_symbol(repo: Path):
    report = partition.check(repo, _splits(**AB), record=False)
    assert _edges(report, "import") == [
        ("import", "a/api.py", 1, "b/svc.py", None),        # from b import svc: a module
        ("import", "a/api.py", 2, "b/svc.py", "Client"),
        ("import", "a/api.py", 2, "b/svc.py", "Plain"),
        ("import", "a/api.py", 2, "b/svc.py", "helper"),
    ]


def test_call_edges_resolve_through_the_imports(repo: Path):
    report = partition.check(repo, _splits(**AB), record=False)
    assert _edges(report, "call") == [
        ("call", "a/api.py", 6, "b/svc.py", "Client"),     # an imported class
        ("call", "a/api.py", 7, "b/svc.py", "Plain"),
        ("call", "a/api.py", 7, "b/svc.py", "helper"),     # an imported function
        ("call", "a/api.py", 7, "b/svc.py", "work"),       # a function of an imported module
    ]


def test_every_edge_names_its_lanes_and_the_def_it_lands_on(repo: Path):
    rows = partition.check(repo, _splits(**AB), record=False).as_dict()["edges"]
    call = next(e for e in rows if e["kind"] == "call" and e["symbol"] == "work")
    assert (call["from_lane"], call["to_lane"], call["target"]) == ("A", "B", "svc.work")
    assert call["def_line"] == 5
    imp = next(e for e in rows if e["kind"] == "import" and e["symbol"] == "helper")
    assert imp["def_line"] == 13 and imp["target"] == "b.svc"


def test_edges_inside_one_lane_and_from_unassigned_files_are_not_reported(repo: Path):
    report = partition.check(repo, _splits(**AB), record=False)
    assert all(e[1] == "a/api.py" for e in _edges(report))  # not b/inner.py (same lane), not c/other.py (no lane)


def test_edges_in_both_directions_are_both_reported(repo: Path):
    write(repo, "b/back.py", "from a.local import local\n\n\ndef back():\n    return local()\n")
    data = partition.check(repo, _splits(**AB), record=False).as_dict()
    pairs = {(e["from_lane"], e["to_lane"]) for e in data["edges"]}
    assert pairs == {("A", "B"), ("B", "A")}


def test_lanes_with_no_call_between_them_have_no_edges(repo: Path):
    write(repo, "d/solo.py", "def solo():\n    return 1\n")
    report = partition.check(repo, _splits(A="a/**", D="d/**"), record=False)
    assert _edges(report) == []
    assert report.as_dict()["frozen_signatures"] == []
    assert "cross-lane edges: none" in "\n".join(render_partition(report.as_dict()))


def test_an_aliased_module_import_is_followed(repo: Path):
    write(repo, "a/aliased.py", "import b.svc as s\n\n\ndef go():\n    return s.work(1)\n")
    report = partition.check(repo, _splits(**AB), record=False)
    assert ("call", "a/aliased.py", 5, "b/svc.py", "work") in _edges(report)
    assert ("import", "a/aliased.py", 1, "b/svc.py", None) in _edges(report)


def test_a_plain_dotted_import_is_followed(repo: Path):
    write(repo, "a/dotted.py", "import b.svc\n\n\ndef go():\n    return b.svc.work(1)\n")
    assert ("call", "a/dotted.py", 5, "b/svc.py", "work") in _edges(partition.check(repo, _splits(**AB), record=False))


def test_modules_are_found_from_a_source_root_above_the_importing_file(tmp_path: Path):
    root = init_repo(tmp_path / "src-layout", rules=False)
    write(root, "src/pkg_a/x.py", "from pkg_b.y import make\n\n\ndef x():\n    return make()\n")
    write(root, "src/pkg_b/y.py", "def make():\n    return 1\n")
    commit(root, "base")
    report = partition.check(root, _splits(A="src/pkg_a/**", B="src/pkg_b/**"), record=False)
    assert _edges(report) == [
        ("import", "src/pkg_a/x.py", 1, "src/pkg_b/y.py", "make"),
        ("call", "src/pkg_a/x.py", 5, "src/pkg_b/y.py", "make"),
    ]


def test_a_name_that_is_not_imported_is_not_guessed(repo: Path):
    write(repo, "a/guess.py", "def go(obj):\n    return obj.work(1) + work(2)\n")  # no import of work
    assert not any(e[1] == "a/guess.py" for e in _edges(partition.check(repo, _splits(**AB), record=False)))


def test_a_module_that_is_not_in_the_workspace_makes_no_edge(repo: Path):
    write(repo, "a/std.py", "import json\nfrom os import path\n\n\ndef go():\n    return json.dumps(path.sep)\n")
    assert not any(e[1] == "a/std.py" for e in _edges(partition.check(repo, _splits(**AB), record=False)))



# ── Module resolution (R-cli-44: pinned across the revert into partition.py) ─

def test_the_nearest_module_shadows_one_higher_up(tmp_path: Path):
    root = init_repo(tmp_path / "shadow", rules=False)
    write(root, "pkg/app.py", "from util import helper\n\n\ndef go():\n    return helper()\n")
    write(root, "pkg/util.py", "def helper():\n    return 1\n")
    write(root, "util.py", "def helper():\n    return 2\n")
    commit(root, "base")
    # The root util.py is in no lane (a slash-free glob would match pkg/util.py too): an edge
    # exists only if the import resolved to pkg/util.py.
    report = partition.check(root, _splits(A="pkg/app.py", B="pkg/util.py"), record=False)
    assert _edges(report, "import") == [("import", "pkg/app.py", 1, "pkg/util.py", "helper")]


def test_an_importer_at_the_workspace_root_finds_a_package(tmp_path: Path):
    root = init_repo(tmp_path / "rooted", rules=False)
    write(root, "app.py", "from lib import f\n\n\ndef go():\n    return f()\n")
    write(root, "lib/__init__.py", "def f():\n    return 1\n")
    commit(root, "base")
    report = partition.check(root, _splits(A="app.py", B="lib/**"), record=False)
    assert _edges(report) == [
        ("import", "app.py", 1, "lib/__init__.py", "f"),
        ("call", "app.py", 5, "lib/__init__.py", "f"),
    ]


def test_a_rust_module_directory_resolves_through_mod_rs(tmp_path: Path):
    root = init_repo(tmp_path / "rustmod", rules=False)
    write(root, "src/a.rs", "use crate::b::work;\n\npub fn run() -> i32 {\n    work(2)\n}\n")
    write(root, "src/b/mod.rs", "pub fn work(x: i32) -> i32 { x }\n")
    write(root, ".aegis/config.json", json.dumps({"v": 1, "ast": {"packaged_drivers": ["rs"]}}))
    commit(root, "base")
    edges = _edges(partition.check(root, _splits(A="src/a.rs", B="src/b/**"), record=False))
    assert ("import", "src/a.rs", 1, "src/b/mod.rs", "work") in edges
    assert ("call", "src/a.rs", 4, "src/b/mod.rs", "work") in edges


def test_an_import_that_resolves_to_no_file_makes_no_edge(tmp_path: Path):
    root = init_repo(tmp_path / "unresolved", rules=False)
    write(root, "a/x.py", "from missing.mod import f\nimport gone\n\n\ndef go():\n    return f() + gone.g()\n")
    write(root, "b/y.py", "def f():\n    return 1\n")
    commit(root, "base")
    assert _edges(partition.check(root, _splits(A="a/**", B="b/**"), record=False)) == []

# ── FROZEN_SIGNATURES ────────────────────────────────────────────────────────

def _frozen(report):
    return {row["symbol"]: row for row in report.as_dict()["frozen_signatures"]}


def test_boundary_functions_and_classes_are_frozen_with_their_signatures(repo: Path):
    frozen = _frozen(partition.check(repo, _splits(**AB), record=False))
    assert sorted(frozen) == ["Client", "Plain", "helper", "work"]
    assert frozen["work"]["signature"] == "def work(x, y=0)"
    assert frozen["helper"]["signature"] == "def helper(n: int) -> int"
    assert frozen["Client"]["signature"] == "class Client(object); __init__(self, url: str, timeout: float = 1.0)"
    assert frozen["Plain"]["signature"] == "class Plain"
    assert (frozen["work"]["path"], frozen["work"]["line"], frozen["work"]["lane"]) == ("b/svc.py", 5, "B")


def test_a_frozen_symbol_lists_who_uses_it(repo: Path):
    frozen = _frozen(partition.check(repo, _splits(**AB), record=False))
    assert frozen["work"]["used_by"] == [{"lane": "A", "path": "a/api.py", "line": 7}]
    assert frozen["helper"]["used_by"] == [{"lane": "A", "path": "a/api.py", "line": 2},
                                           {"lane": "A", "path": "a/api.py", "line": 7}]


def test_only_the_symbols_that_cross_a_boundary_are_frozen(repo: Path):
    frozen = _frozen(partition.check(repo, _splits(**AB), record=False))
    assert "fetch" not in frozen and "_private" not in frozen  # defined in B, never reached from A


def test_an_async_function_keeps_its_keyword_only_arguments(repo: Path):
    write(repo, "a/net.py", "from b.svc import fetch\n\n\ndef go():\n    return fetch('u')\n")
    frozen = _frozen(partition.check(repo, _splits(**AB), record=False))
    assert frozen["fetch"]["signature"] == "async def fetch(url: str, *, retries: int = 3) -> Optional[bytes]"


def test_the_text_block_is_delimited_and_names_each_symbol(repo: Path):
    lines = render_partition(partition.check(repo, _splits(**AB), record=False).as_dict())
    start, end = lines.index("[FROZEN_SIGNATURES]"), lines.index("[/FROZEN_SIGNATURES]")
    block = lines[start + 1:end]
    assert any("def work(x, y=0)" in line and "b/svc.py::work" in line for line in block)
    assert any("lane B" in line and "used by A" in line for line in block)


def test_no_block_markers_are_printed_without_boundary_symbols(repo: Path):
    lines = render_partition(partition.check(repo, _splits(A="a/**", D="d/**"), record=False).as_dict())
    assert "[FROZEN_SIGNATURES]" in lines and lines[lines.index("[FROZEN_SIGNATURES]") + 1] == "(none)"


# ── What cannot be analyzed ──────────────────────────────────────────────────

def test_a_file_that_cannot_be_parsed_is_listed_and_the_rest_goes_on(repo: Path):
    write(repo, "a/broken.py", "def (:\n")
    data = partition.check(repo, _splits(**AB), record=False).as_dict()
    broken = [row for row in data["not_analyzed"] if row["path"] == "a/broken.py"]
    assert len(broken) == 1 and "cannot be parsed" in broken[0]["reason"]
    assert data["edges"]  # a/api.py still reported


def test_a_lane_file_with_no_driver_is_listed_with_the_reason(repo: Path):
    write(repo, "a/notes.md", "# notes\n")
    write(repo, "b/main.go", "package main\n")
    rows = {row["path"]: row["reason"] for row in partition.check(repo, _splits(**AB), record=False).as_dict()["not_analyzed"]}
    assert rows["a/notes.md"] == "no partition support for .md files"
    assert rows["b/main.go"] == "no partition support for .go files"


def test_python_files_and_sizes_are_counted(repo: Path):
    data = partition.check(repo, _splits(**AB), record=False).as_dict()
    assert data["scope"]["files_analyzed"] == 6 and data["scope"]["languages"] == {"python": 6}


# ── Rust, when its driver is enabled ─────────────────────────────────────────

RUST_A = "use crate::b::work;\nuse crate::b::Config;\n\npub fn run() -> i32 {\n    Config::new();\n    work(2)\n}\n"
RUST_B = "pub fn work(x: i32) -> i32 { x }\npub struct Config { pub n: i32 }\nimpl Config { pub fn new() -> Self { Config { n: 1 } } }\n"


def _rust(tmp_path: Path, enabled: bool) -> Path:
    root = init_repo(tmp_path / "rust", rules=False)
    write(root, "src/a.rs", RUST_A)
    write(root, "src/b.rs", RUST_B)
    if enabled:
        write(root, ".aegis/config.json", json.dumps({"v": 1, "ast": {"packaged_drivers": ["rs"]}}))
    commit(root, "base")
    return root


def test_rust_files_are_analyzed_when_the_driver_is_enabled(tmp_path: Path):
    root = _rust(tmp_path, enabled=True)
    report = partition.check(root, _splits(A="src/a.rs", B="src/b.rs"), record=False)
    assert report.as_dict()["scope"]["languages"] == {"rust": 2}
    edges = _edges(report)
    assert ("import", "src/a.rs", 1, "src/b.rs", "work") in edges
    assert ("call", "src/a.rs", 6, "src/b.rs", "work") in edges
    assert ("call", "src/a.rs", 5, "src/b.rs", "Config") in edges
    frozen = _frozen(report)
    assert frozen["work"]["signature"] == "pub fn work(x: i32) -> i32"
    assert frozen["Config"]["signature"] == "pub struct Config"


def test_rust_files_are_analyzed_without_an_opt_in(tmp_path: Path):
    root = _rust(tmp_path, enabled=False)
    data = partition.check(root, _splits(A="src/a.rs", B="src/b.rs"), record=False).as_dict()
    assert data["edges"] and data["scope"]["files_analyzed"] == 2
    assert data["not_analyzed"] == []
    assert data["scope"]["languages"] == {"rust": 2}


# ── The event, the documents, side effects ───────────────────────────────────

def test_a_partition_check_event_records_the_prediction(repo: Path):
    report = partition.check(repo, _splits(**AB))
    (row,) = events.read(repo, "partition_check").rows
    assert row["result"] == "edges"
    detail = row["detail"]
    assert detail["lanes"] == {"A": ["a/**"], "B": ["b/**"]}
    assert (detail["edges"], detail["frozen"], detail["overlap"], detail["files"]) == (8, 4, 0, 6)
    assert detail["predicted"][0] == {"from_lane": "A", "to_lane": "B", "kind": "import", "from": "a/api.py",
                                      "to": "b/svc.py", "symbol": None}
    assert detail["truncated"] is False and report.warnings == ()


def test_a_clean_partition_is_recorded_as_clear(repo: Path):
    write(repo, "d/solo.py", "def solo():\n    return 1\n")
    partition.check(repo, _splits(A="a/**", D="d/**"))
    assert events.read(repo, "partition_check").rows[-1]["result"] == "clear"


def test_the_prediction_in_the_event_is_capped(repo: Path):
    imports = "".join(f"from b.svc import work as w{i}\n" for i in range(partition.MAX_PREDICTED + 20))
    write(repo, "a/many.py", imports)
    partition.check(repo, _splits(**AB))
    detail = events.read(repo, "partition_check").rows[-1]["detail"]
    assert len(detail["predicted"]) == partition.MAX_PREDICTED and detail["truncated"] is True
    assert detail["edges"] > partition.MAX_PREDICTED


def test_an_event_that_cannot_be_written_is_a_warning_not_a_failure(repo: Path, monkeypatch):
    def refuse(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(events, "append", refuse)
    report = partition.check(repo, _splits(**AB))
    assert report.warnings == ("event not recorded: disk full",)
    assert report.as_dict()["warnings"] == ["event not recorded: disk full"]


def test_nothing_but_the_event_log_changes(repo: Path):
    before = _tree(repo)
    partition.check(repo, _splits(**AB))
    assert _tree(repo) == before


def test_the_report_is_deterministic(repo: Path):
    first = partition.check(repo, _splits(**AB), record=False, now=0).as_dict()
    second = partition.check(repo, _splits(**AB), record=False, now=0).as_dict()
    assert first == second and json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_the_json_carries_the_envelope(repo: Path):
    data = partition.check(repo, _splits(**AB), record=False, now=0).as_dict()
    assert data["source"] == "aegis check --partition" and data["aegis_version"] == __version__
    assert data["checked_at"] == "1970-01-01T00:00:00Z"
    assert TS.match(partition.check(repo, _splits(**AB), record=False).as_dict()["checked_at"])
    assert data["scope"]["workspace"] == str(repo) and data["scope"]["lanes"] == ["A", "B"]
    assert data["limits"] and all(isinstance(item, str) for item in data["limits"])
    json.dumps(data)


def test_outside_git_the_files_are_walked(tmp_path: Path):
    root = tmp_path / "plain"
    write(root, "a/x.py", "from b.y import make\n\n\ndef x():\n    return make()\n")
    write(root, "b/y.py", "def make():\n    return 1\n")
    write(root, ".aegis/config.json", '{"v": 1}')
    report = partition.check(root, _splits(A="a/**", B="b/**"), record=False)
    assert _edges(report, "call") == [("call", "a/x.py", 5, "b/y.py", "make")]
    assert report.as_dict()["scope"]["listing"] == "walk"


def test_text_report_header_counts_lanes_files_and_edges(repo: Path):
    text = "\n".join(render_partition(partition.check(repo, _splits(**AB), record=False).as_dict()))
    assert "aegis check --partition: 2 lanes, 6 file(s) analyzed (6 python)" in text
    assert "cross-lane edges: 8" in text and "A -> B: 8" in text
    assert "call    a/api.py:7 -> b/svc.py::work  (svc.work)" in text
    assert "import  a/api.py:2 -> b/svc.py::helper  (b.svc)" in text
    assert "static name resolution" in text
