"""forbid_ast hardening (review H2, H3).

H2: import aliasing must not change a forbid_ast verdict. ``import subprocess as sp;
sp.run()`` is judged exactly like ``import subprocess; subprocess.run()``.

H3: forbid_ast fails closed. Python sources are read the way CPython reads them
(UTF-8 BOM, PEP 263 coding cookie), and a file in scope of a forbid_ast rule that
still cannot be parsed yields a failing ``forbid_ast: cannot verify`` finding
instead of being skipped.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import time

import pytest

from aegis_core.ast.drivers.python import parse_python_ast
from aegis_core.ast.policy import evaluate_forbid_ast, extract_normalized_ast
from aegis_core.ast.runner import ASTDriverError
from aegis_core.ast.schema import CallSiteNode, ImportNode, NormalizedAST
from aegis_core.verification.pipeline import DeterministicVerifier
from aegis_core.verification.runner import gate_verdict


def _violations(code: str, spec: dict) -> list[str]:
    return evaluate_forbid_ast(extract_normalized_ast("mod.py", code=code), spec)


# Canonical patterns only: every pattern names a real module, symbol or dotted API,
# never a local alias.
CANONICAL_SPEC = {
    "imports": [
        "subprocess", "subprocess.run", "os.path", "pickle", "run", "path",
        "xml.etree", "datetime.datetime", "pytest",
    ],
    "calls": [
        "subprocess.run", "subprocess.Popen", "run", "os.system", "system", "os.path.join",
        "join", "pickle.loads", "loads", "eval", "exec", "datetime.now",
        "datetime.datetime.now", "xml.etree.ElementTree.parse",
    ],
    "decorators": [
        "pytest.mark.xfail", "mark.xfail", "xfail", "functools.lru_cache", "lru_cache",
        "dataclass", "dataclasses.dataclass",
    ],
}


# ── H2: alias forms ≡ plain forms ─────────────────────────────────────────────

ALIAS_EQUIVALENCE = [
    pytest.param(
        "import subprocess\nsubprocess.run(['ls'])\n",
        "import subprocess as sp\nsp.run(['ls'])\n",
        "Forbidden call 'subprocess.run' matched rule forbid_ast.calls",
        id="import-module-as",
    ),
    pytest.param(
        "from subprocess import run\nrun(['ls'])\n",
        "from subprocess import run as r\nr(['ls'])\n",
        "Forbidden call 'subprocess.run' matched rule forbid_ast.calls",
        id="from-import-symbol-as",
    ),
    pytest.param(
        "import os.path\nos.path.join('a', 'b')\n",
        "import os.path as osp\nosp.join('a', 'b')\n",
        "Forbidden call 'os.path.join' matched rule forbid_ast.calls",
        id="import-dotted-module-as",
    ),
    pytest.param(
        "from os import path\npath.join('a', 'b')\n",
        "from os import path as p\np.join('a', 'b')\n",
        "Forbidden call 'os.path.join' matched rule forbid_ast.calls",
        id="from-import-submodule-as",
    ),
    pytest.param(
        "import os\nos.system('ls')\n",
        "import os as operating_system\noperating_system.system('ls')\n",
        "Forbidden call 'os.system' matched rule forbid_ast.calls",
        id="import-as-long-alias",
    ),
    pytest.param(
        "from pickle import loads\nloads(b'')\n",
        "from pickle import loads as decode\ndecode(b'')\n",
        "Forbidden call 'pickle.loads' matched rule forbid_ast.calls",
        id="from-import-as-unrelated-name",
    ),
    pytest.param(
        "import xml.etree.ElementTree\nxml.etree.ElementTree.parse('f')\n",
        "import xml.etree.ElementTree as ET\nET.parse('f')\n",
        "Forbidden call 'xml.etree.ElementTree.parse' matched rule forbid_ast.calls",
        id="import-deep-module-as",
    ),
    pytest.param(
        "from os import path, system\nsystem('ls')\npath.join('a')\n",
        "from os import path as p, system\nsystem('ls')\np.join('a')\n",
        "Forbidden import 'path' matched rule forbid_ast.imports",
        id="mixed-aliased-and-plain-names",
    ),
    pytest.param(
        "from . import sibling\nsibling.run()\n",
        "from . import sibling as s\ns.run()\n",
        "Forbidden call 'run' matched rule forbid_ast.calls",
        id="relative-import-as",
    ),
    pytest.param(
        "def f():\n    import subprocess\n    subprocess.run([])\n",
        "def f():\n    import subprocess as sp\n    sp.run([])\n",
        "Forbidden call 'subprocess.run' matched rule forbid_ast.calls",
        id="function-scoped-import-as",
    ),
    pytest.param(
        "import pytest\n@pytest.mark.xfail\ndef test_a():\n    pass\n",
        "import pytest as pt\n@pt.mark.xfail\ndef test_a():\n    pass\n",
        "Forbidden decorator 'pytest.mark.xfail' matched rule forbid_ast.decorators",
        id="decorator-module-as",
    ),
    pytest.param(
        "from functools import lru_cache\n@lru_cache(maxsize=1)\ndef f():\n    return 1\n",
        "from functools import lru_cache as memo\n@memo(maxsize=1)\ndef f():\n    return 1\n",
        "Forbidden decorator 'functools.lru_cache' matched rule forbid_ast.decorators",
        id="decorator-symbol-as",
    ),
]


class TestAliasBypassClosed:
    @pytest.mark.parametrize("plain, aliased, expected", ALIAS_EQUIVALENCE)
    def test_alias_form_yields_exactly_the_plain_form_violations(self, plain, aliased, expected):
        plain_violations = _violations(plain, CANONICAL_SPEC)
        assert expected in plain_violations
        assert _violations(aliased, CANONICAL_SPEC) == plain_violations

    @pytest.mark.parametrize(
        "code, expected",
        [
            ("import subprocess as sp\nsp.run()\n", ["Forbidden call 'subprocess.run' matched rule forbid_ast.calls"]),
            (
                "from subprocess import run as r\nr()\n",
                [
                    "Forbidden import 'subprocess.run' matched rule forbid_ast.imports",
                    "Forbidden call 'subprocess.run' matched rule forbid_ast.calls",
                ],
            ),
            (
                "import os.path as osp\nosp.join()\n",
                [
                    "Forbidden import 'os.path' matched rule forbid_ast.imports",
                    "Forbidden call 'os.path.join' matched rule forbid_ast.calls",
                ],
            ),
            (
                "from os import path as p\np.join()\n",
                [
                    "Forbidden import 'os.path' matched rule forbid_ast.imports",
                    "Forbidden call 'os.path.join' matched rule forbid_ast.calls",
                ],
            ),
        ],
        ids=["sp.run", "r", "osp.join", "p.join"],
    )
    def test_review_reproductions_report_the_forbidden_api(self, code, expected):
        spec = {"calls": ["subprocess.run", "os.path.join"], "imports": ["subprocess.run", "os.path"]}
        assert _violations(code, spec) == expected

    def test_alias_convention_call_patterns_still_match(self):
        """Patterns written against a conventional alias keep matching the literal call text."""
        code = "import numpy as np\nnp.load('weights.npy')\n"
        assert _violations(code, {"calls": ["np.load", "numpy.load"]}) == [
            "Forbidden call 'np.load' matched rule forbid_ast.calls",
            "Forbidden call 'numpy.load' matched rule forbid_ast.calls",
        ]

    def test_alias_survives_json_round_trip_for_external_drivers(self):
        """External drivers hand back NormalizedAST JSON; the alias binding must survive it."""
        original = parse_python_ast("import subprocess as sp\nsp.run([])\n", file_path="mod.py")
        restored = NormalizedAST.from_json(original.to_json())
        assert evaluate_forbid_ast(restored, {"calls": ["subprocess.run"]}) == [
            "Forbidden call 'subprocess.run' matched rule forbid_ast.calls"
        ]

    def test_alias_bound_by_mapping_import_node(self):
        norm_ast = NormalizedAST(
            file_path="mod.ts",
            language="typescript",
            imports=[{"source": "child_process", "imported_symbols": ["run"], "aliases": [["run", "execSync"]]}],
            calls=["run"],
        )
        assert evaluate_forbid_ast(norm_ast, {"calls": ["child_process.execSync"], "imports": ["execSync"]}) == [
            "Forbidden import 'execSync' matched rule forbid_ast.imports",
            "Forbidden call 'child_process.execSync' matched rule forbid_ast.calls",
        ]


# ── H2 guard: plain forms are byte-identical to the pre-fix engine ────────────

# Golden outputs recorded on base add1dbf (before this change) with CANONICAL_SPEC.
PLAIN_FORM_GOLDEN = [
    ("import subprocess\nsubprocess.run(['ls'])\n", ["Forbidden import 'subprocess' matched rule forbid_ast.imports", "Forbidden call 'subprocess.run' matched rule forbid_ast.calls", "Forbidden call 'run' matched rule forbid_ast.calls"]),
    ("import subprocess\nsubprocess.Popen(['ls'])\n", ["Forbidden import 'subprocess' matched rule forbid_ast.imports", "Forbidden call 'subprocess.Popen' matched rule forbid_ast.calls"]),
    ("from subprocess import run\nrun(['ls'])\n", ["Forbidden import 'subprocess' matched rule forbid_ast.imports", "Forbidden import 'subprocess.run' matched rule forbid_ast.imports", "Forbidden import 'run' matched rule forbid_ast.imports", "Forbidden call 'subprocess.run' matched rule forbid_ast.calls", "Forbidden call 'run' matched rule forbid_ast.calls"]),
    ("from subprocess import run, Popen\nPopen(['ls'])\n", ["Forbidden import 'subprocess' matched rule forbid_ast.imports", "Forbidden import 'subprocess.run' matched rule forbid_ast.imports", "Forbidden import 'run' matched rule forbid_ast.imports", "Forbidden call 'subprocess.Popen' matched rule forbid_ast.calls"]),
    ("import os\nos.system('ls')\n", ["Forbidden call 'os.system' matched rule forbid_ast.calls", "Forbidden call 'system' matched rule forbid_ast.calls"]),
    ("import os.path\nos.path.join('a', 'b')\n", ["Forbidden import 'os.path' matched rule forbid_ast.imports", "Forbidden call 'os.path.join' matched rule forbid_ast.calls", "Forbidden call 'join' matched rule forbid_ast.calls"]),
    ("from os import path\npath.join('a', 'b')\n", ["Forbidden import 'os.path' matched rule forbid_ast.imports", "Forbidden import 'path' matched rule forbid_ast.imports", "Forbidden call 'os.path.join' matched rule forbid_ast.calls", "Forbidden call 'join' matched rule forbid_ast.calls"]),
    ("from os import system\nsystem('ls')\n", ["Forbidden call 'os.system' matched rule forbid_ast.calls", "Forbidden call 'system' matched rule forbid_ast.calls"]),
    ("import pickle\npickle.loads(b'')\n", ["Forbidden import 'pickle' matched rule forbid_ast.imports", "Forbidden call 'pickle.loads' matched rule forbid_ast.calls", "Forbidden call 'loads' matched rule forbid_ast.calls"]),
    ("from pickle import loads\nloads(b'')\n", ["Forbidden import 'pickle' matched rule forbid_ast.imports", "Forbidden call 'pickle.loads' matched rule forbid_ast.calls", "Forbidden call 'loads' matched rule forbid_ast.calls"]),
    ("eval('1')\n", ["Forbidden call 'eval' matched rule forbid_ast.calls"]),
    ("exec('x = 1')\n", ["Forbidden call 'exec' matched rule forbid_ast.calls"]),
    ("import builtins\nbuiltins.eval('1')\n", ["Forbidden call 'eval' matched rule forbid_ast.calls"]),
    ("from . import sibling\nsibling.run()\n", ["Forbidden call 'run' matched rule forbid_ast.calls"]),
    ("from .pkg import helper\nhelper()\n", []),
    ("from datetime import datetime\ndatetime.now()\n", ["Forbidden import 'datetime.datetime' matched rule forbid_ast.imports", "Forbidden call 'datetime.now' matched rule forbid_ast.calls"]),
    ("import pytest\n@pytest.mark.xfail\ndef test_a():\n    pass\n", ["Forbidden import 'pytest' matched rule forbid_ast.imports", "Forbidden decorator 'pytest.mark.xfail' matched rule forbid_ast.decorators", "Forbidden decorator 'mark.xfail' matched rule forbid_ast.decorators", "Forbidden decorator 'xfail' matched rule forbid_ast.decorators"]),
    ("from pytest import mark\n@mark.xfail\ndef test_a():\n    pass\n", ["Forbidden import 'pytest' matched rule forbid_ast.imports", "Forbidden decorator 'mark.xfail' matched rule forbid_ast.decorators", "Forbidden decorator 'xfail' matched rule forbid_ast.decorators"]),
    ("from functools import lru_cache\n@lru_cache(maxsize=1)\ndef f():\n    return 1\n", ["Forbidden decorator 'functools.lru_cache' matched rule forbid_ast.decorators", "Forbidden decorator 'lru_cache' matched rule forbid_ast.decorators"]),
    ("from dataclasses import dataclass\n@dataclass\nclass A:\n    x: int = 0\n", ["Forbidden decorator 'dataclass' matched rule forbid_ast.decorators", "Forbidden decorator 'dataclasses.dataclass' matched rule forbid_ast.decorators"]),
    ("import json\njson.loads('{}')\n", ["Forbidden call 'loads' matched rule forbid_ast.calls"]),
    ("from os import *\nsystem('ls')\n", ["Forbidden call 'system' matched rule forbid_ast.calls"]),
    ("import xml.etree.ElementTree\nxml.etree.ElementTree.parse('f')\n", ["Forbidden import 'xml.etree' matched rule forbid_ast.imports", "Forbidden call 'xml.etree.ElementTree.parse' matched rule forbid_ast.calls"]),
    ("def run():\n    pass\nrun()\n", ["Forbidden call 'run' matched rule forbid_ast.calls"]),
    ("class A:\n    def m(self):\n        self.run()\n", ["Forbidden call 'run' matched rule forbid_ast.calls"]),
]

HANDBUILT_GOLDEN = [
    (
        NormalizedAST(file_path="m.py", imports=[{"module": "pickle", "imported_names": ["loads"]}], calls=["loads"]),
        ["Forbidden import 'pickle' matched rule forbid_ast.imports", "Forbidden call 'pickle.loads' matched rule forbid_ast.calls", "Forbidden call 'loads' matched rule forbid_ast.calls"],
    ),
    (
        NormalizedAST(file_path="m.py", imports=["subprocess.run"], calls=["run", "subprocess.run"]),
        ["Forbidden import 'subprocess' matched rule forbid_ast.imports", "Forbidden import 'subprocess.run' matched rule forbid_ast.imports", "Forbidden import 'run' matched rule forbid_ast.imports", "Forbidden call 'subprocess.run' matched rule forbid_ast.calls", "Forbidden call 'run' matched rule forbid_ast.calls"],
    ),
    (
        NormalizedAST(
            file_path="m.py",
            imports=[ImportNode(source="os", imported_symbols=("path", "system"))],
            call_sites=[CallSiteNode(target="path.join"), CallSiteNode(target="system")],
        ),
        ["Forbidden import 'os.path' matched rule forbid_ast.imports", "Forbidden import 'path' matched rule forbid_ast.imports", "Forbidden call 'os.system' matched rule forbid_ast.calls", "Forbidden call 'system' matched rule forbid_ast.calls", "Forbidden call 'os.path.join' matched rule forbid_ast.calls", "Forbidden call 'join' matched rule forbid_ast.calls"],
    ),
    (
        NormalizedAST(file_path="m.py", imports=[ImportNode(source="", imported_symbols=("run",))], calls=["run"]),
        ["Forbidden import 'run' matched rule forbid_ast.imports", "Forbidden call 'run' matched rule forbid_ast.calls"],
    ),
]


class TestPlainFormsUnchanged:
    @pytest.mark.parametrize("code, expected", PLAIN_FORM_GOLDEN)
    def test_plain_form_violations_match_pre_fix_golden(self, code, expected):
        assert _violations(code, CANONICAL_SPEC) == expected

    @pytest.mark.parametrize("norm_ast, expected", HANDBUILT_GOLDEN)
    def test_handbuilt_ast_violations_match_pre_fix_golden(self, norm_ast, expected):
        assert evaluate_forbid_ast(norm_ast, CANONICAL_SPEC) == expected

    @pytest.mark.parametrize("code", [c for c, _ in PLAIN_FORM_GOLDEN])
    def test_plain_form_serialization_carries_no_alias_key(self, code):
        assert '"aliases"' not in parse_python_ast(code, file_path="mod.py").to_json()


# ── H3 (documented limit): dynamic imports ────────────────────────────────────

class TestDynamicImports:
    @pytest.mark.parametrize(
        "code",
        ["__import__('subprocess')\n", "import importlib\nimportlib.import_module('subprocess')\n"],
        ids=["__import__", "importlib.import_module"],
    )
    def test_literal_dynamic_import_is_reported_as_import(self, code):
        assert _violations(code, {"imports": ["subprocess"]}) == [
            "Forbidden import 'subprocess' matched rule forbid_ast.imports"
        ]

    def test_non_literal_dynamic_import_is_a_documented_blind_spot(self):
        """A syntactic check cannot resolve a computed module name (see evaluate_forbid_ast)."""
        code = "name = 'sub' + 'process'\n__import__(name)\n"
        assert _violations(code, {"imports": ["subprocess"]}) == []


# ── H3: encoding-aware reads and fail-closed extraction ───────────────────────

_RULE = (
    "---\n"
    "id: no-subprocess-run\n"
    "type: invariant\n"
    "enforcement: gate\n"
    "hypothesis: Production code never shells out or unpickles.\n"
    "target_paths:\n"
    "  - src/*\n"
    "forbid_ast:\n"
    "  calls:\n"
    "    - subprocess.run\n"
    "  imports:\n"
    "    - pickle\n"
    "---\n"
    "# No subprocess.run\n"
)


_LATIN1_SOURCE = "# -*- coding: latin-1 -*-\nimport pickle\nGREETING = 'café'\n".encode("latin-1")


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    rules_dir = tmp_path / ".aegis" / "rules" / "invariants"
    rules_dir.mkdir(parents=True)
    (rules_dir / "no-subprocess-run.md").write_text(_RULE, encoding="utf-8")
    (tmp_path / "src").mkdir()
    return tmp_path


def _forbid_results(ws: Path, *files: str):
    evidence = DeterministicVerifier(fast_mode=True).verify(changed_files=list(files), workspace=ws)
    return evidence, [e for e in evidence if e.tool == "forbid_ast:no-subprocess-run"]


class TestEncodingAwareParsing:
    def test_utf8_bom_file_is_parsed_and_violation_reported(self, ws: Path):
        (ws / "src" / "bom.py").write_bytes(b"\xef\xbb\xbfimport subprocess\nsubprocess.run(['ls'])\n")
        evidence, results = _forbid_results(ws, "src/bom.py")
        assert [(r.target, r.verdict, r.detail) for r in results] == [
            ("src/bom.py", False, "Forbidden call 'subprocess.run' matched rule forbid_ast.calls")
        ]
        assert gate_verdict(evidence) is False

    def test_latin1_cookie_source_is_parsed(self, tmp_path: Path):
        legacy = tmp_path / "legacy.py"
        legacy.write_bytes(_LATIN1_SOURCE)
        assert evaluate_forbid_ast(extract_normalized_ast(legacy), {"imports": ["pickle"]}) == [
            "Forbidden import 'pickle' matched rule forbid_ast.imports"
        ]

    def test_latin1_cookie_file_is_parsed_and_violation_reported(self, ws: Path):
        # __init__.py: call_graph and import_guard skip package initialisers, so this
        # exercises forbid_ast alone (the full Layer 1 path is TestLayer1LegacyEncoding).
        (ws / "src" / "__init__.py").write_bytes(_LATIN1_SOURCE)
        _, results = _forbid_results(ws, "src/__init__.py")
        assert [(r.target, r.verdict, r.detail) for r in results] == [
            ("src/__init__.py", False, "Forbidden import 'pickle' matched rule forbid_ast.imports")
        ]

    def test_clean_bom_file_passes_without_unverifiable_finding(self, ws: Path):
        (ws / "src" / "clean.py").write_bytes(b"\xef\xbb\xbfimport json\njson.loads('{}')\n")
        evidence, results = _forbid_results(ws, "src/clean.py")
        assert results == []

    def test_long_single_line_file_is_parsed(self, ws: Path):
        """A one-line source longer than NAME_MAX must not be mistaken for a path."""
        args = ", ".join(repr(str(i)) for i in range(80))
        (ws / "src" / "oneliner.py").write_text(f"import subprocess; subprocess.run([{args}])", encoding="utf-8")
        _, results = _forbid_results(ws, "src/oneliner.py")
        assert [(r.verdict, r.detail) for r in results] == [
            (False, "Forbidden call 'subprocess.run' matched rule forbid_ast.calls")
        ]


class TestSourceIdentity:
    def test_one_line_source_naming_an_existing_file_is_not_swapped_for_it(self, ws: Path, monkeypatch):
        """The checked file's own text is parsed, never a decoy file whose name equals that text."""
        line = "import subprocess; subprocess.run(['ls'])"
        (ws / "src" / "evil.py").write_text(line, encoding="utf-8")
        (ws / line).write_text("x = 1\n", encoding="utf-8")
        monkeypatch.chdir(ws)
        _, results = _forbid_results(ws, "src/evil.py")
        assert [(r.verdict, r.detail) for r in results] == [
            (False, "Forbidden call 'subprocess.run' matched rule forbid_ast.calls")
        ]


class TestFailClosed:
    def test_syntax_error_file_yields_failing_unverifiable_finding(self, ws: Path):
        (ws / "src" / "broken.py").write_text("import subprocess\nsubprocess.run(\n", encoding="utf-8")
        (ws / "src" / "ok.py").write_text("import json\n", encoding="utf-8")
        evidence, results = _forbid_results(ws, "src/broken.py", "src/ok.py")
        assert len(results) == 1
        assert results[0].target == "src/broken.py"
        assert results[0].verdict is False
        assert results[0].detail.startswith("forbid_ast: cannot verify src/broken.py: SyntaxError: ")
        assert gate_verdict(evidence) is False

    def test_undecodable_file_yields_failing_unverifiable_finding(self, ws: Path):
        # __init__.py for the same reason as the latin-1 Layer 1 test above.
        (ws / "src" / "__init__.py").write_bytes(b"import json\n\nX = '\xff\xfe'\n")
        _, results = _forbid_results(ws, "src/__init__.py")
        assert len(results) == 1
        assert results[0].verdict is False
        assert results[0].detail.startswith("forbid_ast: cannot verify src/__init__.py: UnicodeDecodeError: ")

    def test_invalid_coding_cookie_yields_failing_unverifiable_finding(self, ws: Path):
        (ws / "src" / "cookie.py").write_bytes(b"# -*- coding: no-such-codec -*-\nimport json\n")
        _, results = _forbid_results(ws, "src/cookie.py")
        assert len(results) == 1
        assert results[0].verdict is False
        assert results[0].detail.startswith("forbid_ast: cannot verify src/cookie.py: SyntaxError: ")

    def test_file_type_without_ast_driver_is_not_in_scope(self, ws: Path):
        (ws / "src" / "notes.md").write_text("# subprocess.run is banned\n", encoding="utf-8")
        _, results = _forbid_results(ws, "src/notes.md")
        assert results == []

    def test_unparseable_file_outside_rule_scope_is_ignored(self, ws: Path):
        (ws / "lib").mkdir()
        (ws / "lib" / "broken.py").write_text("def (:\n", encoding="utf-8")
        _, results = _forbid_results(ws, "lib/broken.py")
        assert results == []


class TestExtractionContract:
    def test_syntax_error_raises_extraction_error(self, tmp_path: Path):
        from aegis_core.ast.policy import ASTExtractionError

        bad = tmp_path / "bad.py"
        bad.write_text("def (:\n", encoding="utf-8")
        with pytest.raises(ASTExtractionError) as excinfo:
            extract_normalized_ast(bad)
        assert excinfo.value.path == str(bad)
        assert excinfo.value.reason.startswith("SyntaxError: ")
        assert str(excinfo.value) == f"cannot verify {bad}: {excinfo.value.reason}"

    def test_code_string_syntax_error_raises_extraction_error(self):
        from aegis_core.ast.policy import ASTExtractionError

        with pytest.raises(ASTExtractionError, match=r"^cannot verify planned\.py: SyntaxError: "):
            extract_normalized_ast("planned.py", code="x = (\n")

    def test_external_driver_failure_raises_extraction_error(self, tmp_path: Path):
        from aegis_core.ast.policy import ASTExtractionError

        class _Registry:
            def resolve_driver(self, ext, workspace_root=None):
                return "fake-driver"

        class _FailingRunner:
            registry = _Registry()

            def parse_file(self, path, workspace_root=None):
                raise ASTDriverError("AST driver 'fake-driver' failed with exit code 3: boom")

        target = tmp_path / "mod.zz"
        target.write_text("whatever", encoding="utf-8")
        with pytest.raises(ASTExtractionError) as excinfo:
            extract_normalized_ast(target, workspace_root=tmp_path, ast_runner=_FailingRunner())
        assert excinfo.value.reason == "ASTDriverError: AST driver 'fake-driver' failed with exit code 3: boom"

    def test_extension_without_driver_returns_none(self, tmp_path: Path):
        target = tmp_path / "notes.md"
        target.write_text("# notes\n", encoding="utf-8")
        assert extract_normalized_ast(target, workspace_root=tmp_path) is None


# ── Review round 2, finding 1: a later binding of the same name must not hide one ──

class TestRebindingDoesNotHideAlias:
    """Import maps are file-global and every binding of a name counts.

    A name bound by more than one import (in one statement, a later statement or another
    function) is judged against every API it may refer to, so reusing a bound name can
    only add violations, never remove one.
    """

    @pytest.mark.parametrize(
        "code",
        [
            "import subprocess as sp\nsp.run(['ls'])\nimport json as sp\n",
            "def f():\n    import subprocess as sp\n    sp.run(['ls'])\n\ndef g():\n    import json as sp\n    return sp\n",
            "from subprocess import run as r\nr(['ls'])\nfrom mylib import other as r\n",
            "from subprocess import run\nrun(['ls'])\nfrom mylib import run\n",
            "import json as sp\nimport subprocess as sp\nsp.run(['ls'])\n",
        ],
        ids=["alias-rebound-later", "alias-rebound-in-other-function", "from-alias-rebound", "from-import-rebound", "alias-bound-earlier"],
    )
    def test_shadowing_binding_does_not_hide_forbidden_call(self, code):
        assert _violations(code, {"calls": ["subprocess.run"]}) == [
            "Forbidden call 'subprocess.run' matched rule forbid_ast.calls"
        ]

    def test_duplicate_bound_name_in_one_statement_keeps_every_original(self):
        code = "from subprocess import run as x, Popen as x\nx(['ls'])\n"
        spec = {"imports": ["subprocess.run", "subprocess.Popen"], "calls": ["subprocess.run", "subprocess.Popen"]}
        assert _violations(code, spec) == [
            "Forbidden import 'subprocess.run' matched rule forbid_ast.imports",
            "Forbidden import 'subprocess.Popen' matched rule forbid_ast.imports",
            "Forbidden call 'subprocess.run' matched rule forbid_ast.calls",
            "Forbidden call 'subprocess.Popen' matched rule forbid_ast.calls",
        ]

    def test_name_bound_both_plain_and_aliased_in_one_statement_keeps_plain_binding(self):
        """``from m import a as b, b`` binds ``b`` twice; the plain ``b`` must not be lost."""
        code = "from subprocess import Popen as run, run\nrun(['ls'])\n"
        assert _violations(code, {"imports": ["subprocess.run"], "calls": ["subprocess.run"]}) == [
            "Forbidden import 'subprocess.run' matched rule forbid_ast.imports",
            "Forbidden call 'subprocess.run' matched rule forbid_ast.calls",
        ]

    def test_rebound_decorator_alias_still_matches(self):
        code = "import functools as ft\n@ft.lru_cache\ndef f():\n    pass\nimport json as ft\n"
        assert _violations(code, {"decorators": ["functools.lru_cache"]}) == [
            "Forbidden decorator 'functools.lru_cache' matched rule forbid_ast.decorators"
        ]

# ── R-checks-9: builtin shadowing follows Python's lexical scoping ──

_BUILTIN_EVAL = {"calls": [{"name": "eval", "builtin": True}]}
_EVAL_FLAGGED = ["Forbidden call 'eval' matched rule forbid_ast.calls"]


class TestBuiltinShadowFollowsPythonScoping:
    """A name shadows the builtin only where Python's own lookup finds that binding first: the
    call's scope, then enclosing function and module scopes. A class body is seen only by code
    directly in it; a lambda or comprehension does not see it."""

    @pytest.mark.parametrize("code", [
        "def helper():\n    def eval(x):\n        return x\n    return eval(1)\n\neval(input())\n",
        "async def helper():\n    async def eval(x):\n        return x\n\neval(input())\n",
        "def helper():\n    class eval:\n        pass\n\neval(input())\n",
        "def helper():\n    from mylib import eval\n\neval(input())\n",
        "def helper():\n    import mylib as eval\n\neval(input())\n",
        "def a():\n    def eval(x):\n        return x\n\ndef b():\n    return eval(input())\n",
        "class A:\n    class eval:\n        pass\n\neval(input())\n",
        "def f(a=eval(input())):\n    def eval(x):\n        return x\n",
        "class A:\n    def m(self):\n        def eval(x):\n            return x\n\neval(input())\n",
        "def h():\n    from builtins import eval\n\ndef g():\n    return eval(input())\n",
    ], ids=["def", "async-def", "class", "from-import", "import-as", "sibling", "class-body", "default", "in-method",
            "builtins-import"])
    def test_a_binding_in_another_scope_does_not_hide_the_call(self, code):
        assert _violations(code, _BUILTIN_EVAL) == _EVAL_FLAGGED

    @pytest.mark.parametrize("code", [
        "class A:\n    def eval(self, x):\n        return x\n\n    def m(self):\n        return eval(input())\n",
        "class A:\n    def eval(self, x):\n        return x\n\n    xs = [eval(i) for i in data]\n",
        "class A:\n    def eval(self, x):\n        return x\n\n    f = lambda: eval(input())\n",
    ], ids=["sibling-method", "comprehension", "lambda"])
    def test_a_class_body_binding_is_not_seen_by_nested_code(self, code):
        assert _violations(code, _BUILTIN_EVAL) == _EVAL_FLAGGED

    @pytest.mark.parametrize("code", [
        "def eval(x):\n    return x\n\neval(1)\n",
        "from mylib import eval\n\neval(1)\n",
        "import mylib as eval\n\neval(1)\n",
        "def h():\n    def eval(x):\n        return x\n    return eval(1)\n",
        "def h():\n    def eval(x):\n        return x\n\n    def g():\n        return eval(1)\n\n    return g\n",
        "def eval(x):\n    return x\n\ndef g():\n    return eval(1)\n",
        "class A:\n    def eval(self, x):\n        return x\n\n    y = eval(1)\n",
    ], ids=["module-def", "module-from-import", "module-import-as", "same-function", "enclosing-function",
            "module-def-from-function", "class-body-direct"])
    def test_a_binding_visible_at_the_call_shadows_the_builtin(self, code):
        assert _violations(code, _BUILTIN_EVAL) == []

    def test_exec_is_resolved_the_same_way(self):
        code = "def helper():\n    def exec(x):\n        return x\n\nexec(input())\n"
        assert _violations(code, {"calls": [{"name": "exec", "builtin": True}]}) == [
            "Forbidden call 'exec' matched rule forbid_ast.calls"]

    def test_the_structured_evaluator_reports_the_module_level_line_only(self):
        from aegis_core.ast.policy import evaluate_forbid_ast_structured

        code = "def helper():\n    def eval(x):\n        return x\n    return eval(1)\n\neval(input())\n"
        found = evaluate_forbid_ast_structured(extract_normalized_ast("mod.py", code=code), _BUILTIN_EVAL, rule_id="r")
        assert [(hit["line"], hit["unknown"]) for hit in found] == [(6, False)]

    def test_the_driver_resolves_bare_names_only(self):
        norm = extract_normalized_ast("mod.py", code="import os\ndef f():\n    pass\nf()\ng()\nos.getcwd()\n")
        assert [(c.target, c.shadowed) for c in norm.call_sites] == [("f", True), ("g", False), ("os.getcwd", None)]
        assert NormalizedAST.from_json(norm.to_json()) == norm

    def test_shadowed_round_trips_is_omitted_when_none_and_a_non_bool_loads_as_none(self):
        for value in (True, False):
            site = CallSiteNode(target="eval", line=3, shadowed=value)
            assert site.to_dict()["shadowed"] is value
            assert CallSiteNode.from_dict(site.to_dict()) == site
        assert "shadowed" not in CallSiteNode(target="eval", line=3).to_dict()
        assert CallSiteNode.from_dict({"target": "eval", "line": 3}).shadowed is None
        assert CallSiteNode.from_dict({"target": "eval", "shadowed": "yes"}).shadowed is None
        assert CallSiteNode.from_dict({"target": "eval", "shadowed": 1}).shadowed is None

    def test_a_site_without_a_driver_verdict_keeps_the_file_wide_test(self):
        from aegis_core.ast.schema import DefinitionNode

        defs = (DefinitionNode(name="eval", kind="function"),)
        free = NormalizedAST(file_path="m.py", definitions=defs, call_sites=(CallSiteNode("eval", 4, shadowed=False),))
        bound = NormalizedAST(file_path="m.py", call_sites=(CallSiteNode("eval", 4, shadowed=True),))
        legacy = NormalizedAST(file_path="m.py", definitions=defs, call_sites=(CallSiteNode("eval", 4),))
        assert evaluate_forbid_ast(free, _BUILTIN_EVAL) == _EVAL_FLAGGED
        assert evaluate_forbid_ast(bound, _BUILTIN_EVAL) == []
        assert evaluate_forbid_ast(legacy, _BUILTIN_EVAL) == []


# ── Review round 2, finding 2: encoding detection must split lines like CPython ──

# CPython treats \r and \r\n as line breaks when it looks for a PEP 263 cookie in the first
# two lines, so the utf-7 cookie on line 4 below is ignored and the payload runs as UTF-8.
# Splitting on \n only would honour it and decode `+ACM-` into `#`, hiding the call.
CR_COOKIE_ATTACKS = [
    pytest.param(
        b"#\r\r\r# coding: utf-7\rACM = 5; b = (1) +ACM-1; import subprocess; subprocess.run(['echo','X'])\r",
        id="cr-only",
    ),
    pytest.param(
        b"#\r\r\r# coding: utf-7\nACM = 5; b = (1) +ACM-1; import subprocess; subprocess.run(['echo','X'])\n",
        id="mixed-cr-lf",
    ),
    pytest.param(
        b"#\r\n\r\n\r\n# coding: utf-7\r\nACM = 5; b = (1) +ACM-1; import subprocess; subprocess.run(['echo','X'])\r\n",
        id="crlf",
    ),
]

_SUBPROCESS_SPEC = {"calls": ["subprocess.run"], "imports": ["subprocess"]}
_SUBPROCESS_VIOLATIONS = [
    "Forbidden import 'subprocess' matched rule forbid_ast.imports",
    "Forbidden call 'subprocess.run' matched rule forbid_ast.calls",
]


def _cpython_bytes_violations(raw: bytes, spec: dict) -> list[str]:
    """Violations for the AST CPython itself builds from the raw bytes (its own decoder)."""
    import ast as _ast

    _ast.parse(raw)  # CPython accepts the file
    return evaluate_forbid_ast(parse_python_ast(_ast.unparse(_ast.parse(raw)), file_path="cpython.py"), spec)


class TestLineEndingsInCookieDetection:
    @pytest.mark.parametrize("raw", CR_COOKIE_ATTACKS)
    def test_cookie_beyond_line_two_is_ignored_like_cpython(self, tmp_path: Path, raw: bytes):
        target = tmp_path / "payload.py"
        target.write_bytes(raw)
        assert _cpython_bytes_violations(raw, _SUBPROCESS_SPEC) == _SUBPROCESS_VIOLATIONS
        assert evaluate_forbid_ast(extract_normalized_ast(target), _SUBPROCESS_SPEC) == _SUBPROCESS_VIOLATIONS

    @pytest.mark.parametrize("raw", CR_COOKIE_ATTACKS)
    def test_layer1_blocks_cr_cookie_payload(self, ws: Path, raw: bytes):
        (ws / "src" / "payload.py").write_bytes(raw)
        evidence, results = _forbid_results(ws, "src/payload.py")
        assert [(r.target, r.verdict, r.detail) for r in results] == [
            ("src/payload.py", False, "Forbidden call 'subprocess.run' matched rule forbid_ast.calls")
        ]
        assert gate_verdict(evidence) is False

    @pytest.mark.parametrize(
        "raw",
        [
            b"# -*- coding: latin-1 -*-\rimport pickle\rS = '\xe9'\r",
            b"#!/usr/bin/env python\r# -*- coding: latin-1 -*-\rimport pickle\rS = '\xe9'\r",
            b"# -*- coding: latin-1 -*-\r\nimport pickle\r\nS = '\xe9'\r\n",
        ],
        ids=["cr-line1", "cr-line2", "crlf-line1"],
    )
    def test_cookie_on_first_two_cr_lines_is_honoured(self, tmp_path: Path, raw: bytes):
        from aegis_core.ast.drivers.python import read_python_source

        target = tmp_path / "legacy.py"
        target.write_bytes(raw)
        assert "S = 'é'" in read_python_source(target)
        assert evaluate_forbid_ast(extract_normalized_ast(target), {"imports": ["pickle"]}) == [
            "Forbidden import 'pickle' matched rule forbid_ast.imports"
        ]


class TestDecoderDependentEncodingsFailClosed:
    """A codec that can decode ASCII bytes into something else makes the code's meaning
    depend on which decoder reads it, so forbid_ast refuses to judge such a file."""

    @pytest.mark.parametrize("codec", ["utf-7", "hz", "iso2022_jp", "unicode_escape", "utf-16", "cp037", "idna"])
    def test_non_ascii_transparent_cookie_raises_extraction_error(self, tmp_path: Path, codec: str):
        from aegis_core.ast.policy import ASTExtractionError

        target = tmp_path / "odd.py"
        target.write_bytes(f"# coding: {codec}\nimport json\n".encode("ascii"))
        with pytest.raises(ASTExtractionError) as excinfo:
            extract_normalized_ast(target)
        assert excinfo.value.reason == f"UnicodeError: source encoding {codec!r} does not decode ASCII to itself"

    def test_utf7_line1_payload_is_unverifiable_in_layer1(self, ws: Path):
        (ws / "src" / "u7.py").write_bytes(b"# coding: utf-7\n# +AAo-import os; os.system('echo X')\n")
        evidence, results = _forbid_results(ws, "src/u7.py")
        assert [(r.verdict, r.detail) for r in results] == [
            (False, "forbid_ast: cannot verify src/u7.py: UnicodeError: source encoding 'utf-7' does not decode ASCII to itself")
        ]
        assert gate_verdict(evidence) is False

    @pytest.mark.parametrize(
        "codec, text",
        [
            ("cp1252", "café €"),
            ("iso-8859-15", "café €"),
            ("koi8-r", "привет"),
            ("shift_jis", "日本語"),
            ("euc-jp", "日本語"),
            ("gbk", "中文"),
            ("big5", "中文"),
            ("euc-kr", "한국어"),
            ("mac-roman", "café"),
        ],
    )
    def test_ascii_transparent_legacy_codecs_are_parsed(self, tmp_path: Path, codec: str, text: str):
        target = tmp_path / "legacy.py"
        target.write_bytes(f"# -*- coding: {codec} -*-\nimport pickle\nS = '{text}'\n".encode(codec))
        assert evaluate_forbid_ast(extract_normalized_ast(target), {"imports": ["pickle"]}) == [
            "Forbidden import 'pickle' matched rule forbid_ast.imports"
        ]


# ── Review round 2, finding 3: dynamic imports through aliases and chains ─────

class TestDynamicImportResolution:
    @pytest.mark.parametrize(
        "code",
        [
            "import importlib as il\nil.import_module('subprocess')\n",
            "from importlib import import_module\nimport_module('subprocess')\n",
            "from importlib import import_module as im\nim('subprocess')\n",
            "import builtins\nbuiltins.__import__('subprocess')\n",
            "from builtins import __import__ as imp\nimp('subprocess')\n",
            "import importlib\nimportlib.__import__('subprocess')\n",
            "__import__(name='subprocess')\n",
            "import importlib\nimportlib.import_module(name='subprocess')\n",
            "def f():\n    return import_module('subprocess')\nfrom importlib import import_module\n",
            "__import__('importlib').import_module('subprocess')\n",
        ],
        ids=[
            "importlib-alias", "from-importlib-import_module", "import_module-alias", "builtins.__import__",
            "from-builtins-__import__-alias", "importlib.__import__", "__import__-name-kw",
            "import_module-name-kw", "import-after-use", "chained-importer",
        ],
    )
    def test_dynamic_import_spelling_is_reported_as_import(self, code):
        assert _violations(code, {"imports": ["subprocess"]}) == [
            "Forbidden import 'subprocess' matched rule forbid_ast.imports"
        ]

    @pytest.mark.parametrize(
        "code, call",
        [
            ("__import__('os').system('ls')\n", "os.system"),
            ("import importlib\nimportlib.import_module('subprocess').run(['ls'])\n", "subprocess.run"),
            ("import importlib as il\nil.import_module('subprocess').run(['ls'])\n", "subprocess.run"),
            ("__import__('os').path.join('a', 'b')\n", "os.path.join"),
            ("__import__('os.path').path.join('a', 'b')\n", "os.path.join"),
            ("__import__('os.path', fromlist=['join']).join('a', 'b')\n", "os.path.join"),
            ("import importlib\nimportlib.import_module('os.path').join('a', 'b')\n", "os.path.join"),
            ("__import__(name='os').system('ls')\n", "os.system"),
        ],
        ids=[
            "__import__-attr", "import_module-attr", "import_module-alias-attr", "__import__-deep-attr",
            "__import__-dotted-returns-top-package", "__import__-fromlist-returns-submodule",
            "import_module-dotted", "__import__-name-kw-attr",
        ],
    )
    def test_call_on_dynamically_imported_module_matches_calls_rule(self, code, call):
        assert _violations(code, {"calls": [call]}) == [f"Forbidden call '{call}' matched rule forbid_ast.calls"]

    @pytest.mark.parametrize(
        "code",
        [
            "from mylib import import_module\nimport_module('subprocess')\n",
            "def import_module(name):\n    return name\nimport_module('subprocess')\n",
            "loader.import_module('subprocess')\n",
        ],
        ids=["foreign-import_module", "local-import_module", "method-named-import_module"],
    )
    def test_unrelated_function_named_import_module_is_not_an_import(self, code):
        assert _violations(code, {"imports": ["subprocess"]}) == []

    @pytest.mark.parametrize(
        "code",
        [
            "i = __import__\ni('subprocess')\n",
            "__import__(f'sub{1}process')\n",
            "import importlib\ngetattr(importlib, 'import_module')('subprocess')\n",
        ],
        ids=["rebound-by-assignment", "computed-name", "getattr"],
    )
    def test_documented_blind_spots_stay_out_of_scope(self, code):
        """Rebinding by assignment, computed names and getattr are listed as out of scope
        in evaluate_forbid_ast's docstring; a syntactic check cannot see through them."""
        assert _violations(code, {"imports": ["subprocess"]}) == []
        doc = evaluate_forbid_ast.__doc__
        for phrase in ("computed module names", "getattr", "rebinding"):
            assert phrase in doc


# ── Review round 3, finding 1 (out of lane scope): Layer 1 aborts on latin-1 ───

class TestLayer1LegacyEncoding:
    def test_latin1_module_reaches_forbid_ast_through_layer1(self, ws: Path):
        (ws / "src" / "legacy.py").write_bytes(_LATIN1_SOURCE + b"import subprocess\nsubprocess.run(['ls'])\n")
        _, results = _forbid_results(ws, "src/legacy.py")
        assert [(r.verdict, r.detail) for r in results] == [
            (
                False,
                "Forbidden import 'pickle' matched rule forbid_ast.imports; "
                "Forbidden call 'subprocess.run' matched rule forbid_ast.calls",
            )
        ]


# ── Review round 3, finding 2: binding fan-out must stay linear ───────────────

def _generated(*blocks: list[str]) -> str:
    return "\n".join(line for block in blocks for line in block) + "\n"


# Timing asserts complexity, never a runner's speed (R-cli-10): t(2N) / t(N), each the best of 3,
# is about 2 when linear and about 4 when quadratic. The ceiling only tells a hang from a slow run.
_HANG_CEILING_S = 60.0


def _best_of(runs: int, fn, clock=time.perf_counter) -> float:
    best = float("inf")
    for _ in range(runs):
        start = clock()
        fn()
        took = clock() - start
        assert took < _HANG_CEILING_S, f"one run took {took:.0f}s: a hang, not a slow runner"
        best = min(best, took)
    return best


def _doubling_ratio(run, n: int, clock=time.perf_counter) -> float:
    return _best_of(3, lambda: run(2 * n), clock) / max(_best_of(3, lambda: run(n), clock), 1e-9)


class TestTheScalingCheck:
    @pytest.mark.timing
    def test_a_quadratic_evaluator_fails_the_ratio(self, monkeypatch):
        import aegis_core.ast.policy as policy

        real = policy._eval_call_entry

        def quadratic(raw_call, sites, *rest):
            sum(1 for _ in sites for _ in sites)
            return real(raw_call, sites, *rest)

        monkeypatch.setattr(policy, "_eval_call_entry", quadratic)
        trees = {n: extract_normalized_ast("mod.py", code="f()\n" * (800 * n)) for n in (1, 2)}
        ratio = _doubling_ratio(lambda n: evaluate_forbid_ast(trees[n], {"calls": ["g"]}), 1)
        assert ratio >= 3, f"a quadratic stand-in doubled to only {ratio:.1f}x"

    def test_a_hang_hits_the_ceiling(self):
        clock = iter([0.0, _HANG_CEILING_S + 1]).__next__
        with pytest.raises(AssertionError, match="a hang"):
            _best_of(1, lambda: None, clock)


FAN_OUT_SHAPES = [
    pytest.param(
        [f"from m{i} import x{i} as n" for i in range(1500)], ["n()"] * 15000,
        id="one-name-bound-1500x-called-15000x",
    ),
    pytest.param(
        [f"import m{i} as n" for i in range(2000)], [f"n.a{j}()" for j in range(20000)],
        id="one-name-bound-2000x-20000-distinct-attributes",
    ),
    pytest.param(
        [f"import m{i}.sub as n" for i in range(1000)] + [f"from p{i} import m{i}" for i in range(1000)],
        [f"n.a{j}()" for j in range(10000)],
        id="dotted-originals-requalified",
    ),
    pytest.param(
        [f"import m{i} as n" for i in range(2000)],
        [f"@n.d{j}\ndef f{j}():\n    pass" for j in range(5000)],
        id="decorators-on-a-name-bound-2000x",
    ),
]


class TestBindingFanOutStaysLinear:
    """A name bound N times and referenced M times costs about N + M, not N * M."""

    @pytest.mark.timing
    @pytest.mark.parametrize("bindings, uses", FAN_OUT_SHAPES)
    def test_generated_file_cost_scales_linearly(self, bindings, uses):
        spec = {"calls": ["subprocess.run", "os.system"], "decorators": ["functools.lru_cache"]}

        def run(half_steps: int) -> None:  # 1: half of each block, 2: all of it
            code = _generated(bindings[: len(bindings) * half_steps // 2], ["import subprocess as n"],
                              uses[: len(uses) * half_steps // 2], ["n.run(['ls'])"])
            assert _violations(code, spec) == ["Forbidden call 'subprocess.run' matched rule forbid_ast.calls"]

        ratio = _doubling_ratio(run, 1)
        assert ratio < 3, f"doubling the bindings and uses multiplied the cost by {ratio:.1f}"


# Reference semantics, written out longhand: a reference ``head + rest`` (the head ends at
# the first "." or "::") is spelled as written and with each alias original in place of the
# head; each spelling is also qualified through the import map (an exact key, else its part
# before the first "."); a pattern matches a spelling it equals or is a dot-suffix of.
def _reference_split(ref: str) -> tuple[str, str]:
    cuts = [i for i in (ref.find("."), ref.find("::")) if i != -1]
    cut = min(cuts) if cuts else len(ref)
    return ref[:cut], ref[cut:]


def _reference_spellings(ref: str, quals: dict, aliases: dict, *, calls: bool) -> list[str]:
    head, rest = _reference_split(ref)
    out = []
    for spelled in [ref, *(orig + rest for orig in aliases.get(head, []))]:
        out.append(spelled)
        if spelled in quals:
            out.extend(quals[spelled])
        elif calls and "." in spelled:
            first, tail = spelled.split(".", 1)
            out.extend(f"{q}.{tail}" for q in quals.get(first, []))
    return out


def _reference_violations(quals, aliases, call_targets, decorators, spec) -> list[str]:
    def hit(refs, pattern, calls):
        return any(
            s == pattern or s.endswith("." + pattern)
            for ref in refs
            for s in _reference_spellings(ref, quals, aliases, calls=calls)
        )

    out = [f"Forbidden call '{p}' matched rule forbid_ast.calls" for p in spec["calls"] if hit(call_targets, p, True)]
    out += [
        f"Forbidden decorator '{p}' matched rule forbid_ast.decorators"
        for p in spec["decorators"]
        if hit(decorators, p, False)
    ]
    return out


_NAMES = ["n", "x", "a", "b", "m", "os", "run", "sp", "a.b", "pkg.m", "x::y", "Cmd", "Command"]
_RESTS = ["", ".f", ".run", ".a.b", "::new", "::x.y", ".b::c", ".system"]


class TestSpellingSemantics:
    def test_evaluation_agrees_with_reference_spellings_on_random_inputs(self):
        import random

        rng = random.Random(20261015)
        for case in range(4000):
            quals: dict[str, list[str]] = {}
            aliases: dict[str, list[str]] = {}
            imports = []
            for _ in range(rng.randint(0, 6)):
                src, key = rng.choice(_NAMES[:10]), rng.choice(_NAMES)
                if key != src:
                    imports.append(ImportNode(source=src, imported_symbols=(key,)))
                    if f"{src}.{key}" not in quals.setdefault(key, []):
                        quals[key].append(f"{src}.{key}")
            for _ in range(rng.randint(0, 6)):
                bound, orig = rng.choice(_NAMES[:8] + ["Cmd", "p"]), rng.choice(_NAMES)
                imports.append(ImportNode(source="", aliases=((bound, orig),)))
                if orig not in aliases.setdefault(bound, []):
                    aliases[bound].append(orig)
            targets = [rng.choice(_NAMES + ["Cmd", "p"]) + rng.choice(_RESTS) for _ in range(rng.randint(1, 4))]
            decorators = [rng.choice(_NAMES) + rng.choice(_RESTS[:4]) for _ in range(rng.randint(0, 3))]
            spec = {
                "calls": [rng.choice(_NAMES) + rng.choice(_RESTS) for _ in range(3)],
                "decorators": [rng.choice(_NAMES) + rng.choice(_RESTS[:4]) for _ in range(2)],
            }
            spec["calls"] = list(dict.fromkeys(spec["calls"]))
            spec["decorators"] = list(dict.fromkeys(spec["decorators"]))
            norm_ast = NormalizedAST(
                file_path="<generated>",
                imports=imports,
                call_sites=[CallSiteNode(target=t) for t in targets],
                metadata={"decorators": decorators},
            )
            expected = _reference_violations(quals, aliases, targets, decorators, spec)
            assert evaluate_forbid_ast(norm_ast, spec) == expected, (case, imports, targets, decorators, spec)


    def test_a_pattern_that_is_empty_when_matched_matches_nothing(self):
        # '()()' loses one '()' when read and the other when matched: the empty pattern is
        # no spelling and no dot-suffix of one, so it names no call.
        norm_ast = NormalizedAST(file_path="m.py", call_sites=[CallSiteNode(target="eval"), CallSiteNode(target="os.system")])
        assert evaluate_forbid_ast(norm_ast, {"calls": ["()()"]}) == []
        assert evaluate_forbid_ast(norm_ast, {"calls": ["()()", "eval"]}) == ["Forbidden call 'eval' matched rule forbid_ast.calls"]


# ── Review round 3, finding 3: nesting depth must not make a file unverifiable ──

class TestDeepNestingIsChecked:
    """Any file CPython parses is checked: extraction must not recurse once per nesting level."""

    @pytest.mark.parametrize(
        "prefix",
        [
            "x = a" + ".b()" * 1000 + "\n",
            "x = " + " + ".join(["'s'"] * 2000) + "\n",
            "x = (" + "1 if c else " * 1000 + "2)\n",
            "@" + "a." * 1000 + "b\ndef f():\n    pass\n",
            "__import__('os')" + ".path" * 5 + ".x()" * 1000 + "\n",
        ],
        ids=["method-chain-1000", "concatenation-2000", "conditional-1000", "decorator-attribute-1000", "dynamic-import-chain-1000"],
    )
    def test_long_generated_expression_does_not_hide_violation(self, prefix):
        code = prefix + "import subprocess\nsubprocess.run(['ls'])\n"
        assert _violations(code, {"calls": ["subprocess.run"]}) == [
            "Forbidden call 'subprocess.run' matched rule forbid_ast.calls"
        ]

    def test_call_inside_long_chain_on_dynamic_import_is_reported(self):
        code = "__import__('subprocess').run(['ls'])" + ".strip()" * 1000 + "\n"
        assert _violations(code, {"calls": ["subprocess.run"], "imports": ["subprocess"]}) == [
            "Forbidden import 'subprocess' matched rule forbid_ast.imports",
            "Forbidden call 'subprocess.run' matched rule forbid_ast.calls",
        ]

    def test_deep_decorator_name_is_resolved(self):
        code = "@" + "a." * 1000 + "lru_cache\ndef f():\n    pass\n"
        assert _violations(code, {"decorators": ["lru_cache"]}) == [
            "Forbidden decorator 'lru_cache' matched rule forbid_ast.decorators"
        ]


# ── Review round 3, finding 4: literal dynamic-import spellings ───────────────

class TestLiteralDynamicImportSpellings:
    @pytest.mark.parametrize(
        "code",
        [
            "__builtins__.__import__('subprocess').run(['x'])\n",
            "__import__(f'subprocess').run(['x'])\n",
            "__import__('sub' + 'process').run(['x'])\n",
            "__import__(f'sub' + 'pro' f'cess').run(['x'])\n",
            "import importlib\nimportlib.import_module('.' + 'run', 'subprocess')\n",
        ],
        ids=["__builtins__.__import__", "f-string-without-fields", "concatenated-literals", "mixed-literals", "relative-run"],
    )
    def test_literal_spelling_is_reported_as_import(self, code):
        assert "Forbidden import 'subprocess' matched rule forbid_ast.imports" in _violations(
            code, {"imports": ["subprocess"]}
        )

    @pytest.mark.parametrize(
        "code, imports, expected",
        [
            ("import importlib\nimportlib.import_module('.etree', 'xml')\n", ["xml.etree"], ["xml.etree"]),
            ("import importlib\nimportlib.import_module('..etree', package='xml.dom')\n", ["xml.etree"], ["xml.etree"]),
            ("from importlib import import_module\nimport_module('.', 'xml.etree')\n", ["xml.etree"], ["xml.etree"]),
            ("import importlib\nimportlib.import_module('...etree', 'xml')\n", ["xml.etree"], []),
            ("import importlib\nimportlib.import_module('.etree', pkg)\n", ["xml.etree"], []),
        ],
        ids=["one-dot", "two-dots-package-kw", "dot-only", "beyond-top-level", "non-literal-package"],
    )
    def test_relative_import_module_resolves_against_literal_package(self, code, imports, expected):
        assert _violations(code, {"imports": imports}) == [
            f"Forbidden import '{m}' matched rule forbid_ast.imports" for m in expected
        ]

    def test_call_on_relatively_imported_module_matches_calls_rule(self):
        code = "import importlib\nimportlib.import_module('.ElementTree', 'xml.etree').parse('f')\n"
        assert _violations(code, {"calls": ["xml.etree.ElementTree.parse"]}) == [
            "Forbidden call 'xml.etree.ElementTree.parse' matched rule forbid_ast.calls"
        ]

    def test_subscript_access_stays_documented_out_of_scope(self):
        """Subscript access is dynamic lookup, like getattr: listed in evaluate_forbid_ast's docstring."""
        assert _violations("__builtins__['__import__']('subprocess')\n", {"imports": ["subprocess"]}) == []
        assert "subscript" in evaluate_forbid_ast.__doc__


# ── Review round 3, finding 5: aliases from the TypeScript, Rust and Go drivers ─

class TestExternalDriverAliases:
    @pytest.mark.parametrize(
        "record, expected",
        [
            (
                {"module": "std::process::Command", "imported_names": ["Command"], "alias": "Cmd", "is_wildcard": False},
                (("Cmd", "Command"),),
            ),
            ({"module": "std::process", "imported_names": ["process"], "alias": "p", "is_wildcard": False}, (("p", "process"),)),
            (
                {"source": "child_process", "imported_symbols": ["dflt"], "alias": "cp", "is_wildcard": True},
                (("cp", "child_process"),),
            ),
            ({"module": "os/exec", "imported_names": [], "alias": "ex", "is_wildcard": False}, (("ex", "os/exec"),)),
            ({"module": "os/exec", "imported_names": [], "alias": "_", "is_wildcard": False}, ()),
            ({"module": "fmt", "imported_names": [], "alias": ".", "is_wildcard": False}, ()),
            ({"module": "std::process::{Command", "imported_names": ["{Command"], "alias": "C2, exit}"}, ()),
            ({"module": "m", "imported_names": ["a", "b"], "alias": "z", "is_wildcard": False}, ()),
            ({"module": "m", "imported_names": ["a"], "alias": None}, ()),
        ],
        ids=["rust-use-as", "rust-module-as", "ts-namespace", "go-named", "go-blank", "go-dot", "garbled", "ambiguous", "no-alias"],
    )
    def test_driver_alias_becomes_an_alias_pair(self, record, expected):
        assert ImportNode.from_dict(record).aliases == expected

    @pytest.mark.parametrize(
        "plain, aliased, pattern",
        [
            (
                "use std::process::Command;\nfn main() { Command::new(\"ls\"); }\n",
                "use std::process::Command as Cmd;\nfn main() { Cmd::new(\"ls\"); }\n",
                "Command::new",
            ),
            (
                "use std::process;\nfn main() { process::Command::new(\"ls\"); }\n",
                "use std::process as p;\nfn main() { p::Command::new(\"ls\"); }\n",
                "process::Command::new",
            ),
        ],
        ids=["use-item-as", "use-module-as"],
    )
    def test_rust_alias_is_judged_like_the_plain_use(self, plain, aliased, pattern):
        from aegis_core.ast.drivers.templates.rust_ast import parse_rust_source

        def violations(src: str) -> list[str]:
            return evaluate_forbid_ast(NormalizedAST.from_dict(parse_rust_source(src, "m.rs")), {"calls": [pattern]})

        assert violations(plain) == [f"Forbidden call '{pattern}' matched rule forbid_ast.calls"]
        assert violations(aliased) == violations(plain)


# ── Wave A F1 (d): renamed members of a TypeScript or Rust import group ──────

_TS_DRIVER = Path(__file__).resolve().parents[3] / "aegis_core" / "ast" / "drivers" / "templates" / "ts_ast.js"
_NODE = shutil.which("node")

# Stand-in for the `typescript` package with only the API ts_ast.js calls. It returns the
# tree of `import { exec as run, spawn } from "child_process"; run("ls");` so the compiler
# path can be tested where the real package is not installed.
_TS_COMPILER_STUB = """\
"use strict";
const K = { SourceFile: 1, ImportDeclaration: 2, NamedImports: 3, Identifier: 4, Call: 5 };
const node = (kind, props, children = []) =>
  Object.assign({ kind, children, getStart: () => 0, getEnd: () => 0 }, props);
const id = (text) => node(K.Identifier, { text });
module.exports = {
  ScriptTarget: { Latest: 99 },
  SyntaxKind: { ExportKeyword: 100 },
  createSourceFile() {
    const named = node(K.NamedImports, {
      elements: [{ name: id("run"), propertyName: id("exec") }, { name: id("spawn") }],
    });
    const imp = node(K.ImportDeclaration, {
      moduleSpecifier: { text: "child_process" }, importClause: { namedBindings: named },
    });
    const sf = node(K.SourceFile, {}, [imp, node(K.Call, { expression: id("run") })]);
    sf.getLineAndCharacterOfPosition = () => ({ line: 0, character: 0 });
    return sf;
  },
  forEachChild(n, cb) { for (const c of n.children) cb(c); },
  isImportDeclaration: (n) => n.kind === K.ImportDeclaration,
  isNamespaceImport: () => false,
  isNamedImports: (n) => n.kind === K.NamedImports,
  isCallExpression: (n) => n.kind === K.Call,
  isIdentifier: (n) => n.kind === K.Identifier,
  isFunctionDeclaration: () => false,
  isClassDeclaration: () => false,
  isMethodDeclaration: () => false,
  isPropertyAccessExpression: () => false,
  isBinaryExpression: () => false,
};
"""


def _run_ts_driver(cwd: Path, source: str) -> dict:
    target = cwd / "mod.ts"
    target.write_text(source, encoding="utf-8")
    proc = subprocess.run(
        [_NODE, str(_TS_DRIVER), str(target)], cwd=cwd, capture_output=True, text=True, timeout=60, check=True
    )
    return json.loads(proc.stdout)


@pytest.mark.skipif(_NODE is None, reason="node is not installed; the TypeScript driver needs it")
class TestTypeScriptGroupMemberAliases:
    ALIASED = "import { exec as run, spawn } from 'child_process';\nrun('ls');\n"
    PLAIN = "import { exec, spawn } from 'child_process';\nexec('ls');\n"
    SPEC = {"calls": ["child_process.exec"], "imports": ["exec"]}

    def _violations(self, data: dict) -> list[str]:
        return evaluate_forbid_ast(NormalizedAST.from_dict(data), self.SPEC)

    def test_builtin_lexer_emits_the_alias_pair(self, tmp_path):
        data = _run_ts_driver(tmp_path, self.ALIASED)
        (record,) = data["imports"]
        assert (record["imported_symbols"], record["aliases"]) == (["run", "spawn"], [["run", "exec"]])
        assert self._violations(data) == self._violations(_run_ts_driver(tmp_path, self.PLAIN))
        assert self._violations(data) == [
            "Forbidden import 'exec' matched rule forbid_ast.imports",
            "Forbidden call 'child_process.exec' matched rule forbid_ast.calls",
        ]

    def test_compiler_path_emits_the_alias_pair(self, tmp_path):
        stub = tmp_path / "node_modules" / "typescript"
        stub.mkdir(parents=True)
        (stub / "index.js").write_text(_TS_COMPILER_STUB, encoding="utf-8")
        data = _run_ts_driver(tmp_path, self.ALIASED)
        (record,) = data["imports"]
        assert (record["imported_symbols"], record["aliases"]) == (["run", "spawn"], [["run", "exec"]])
        assert self._violations(data) == [
            "Forbidden import 'exec' matched rule forbid_ast.imports",
            "Forbidden call 'child_process.exec' matched rule forbid_ast.calls",
        ]

    def test_plain_named_import_has_no_alias_pairs(self, tmp_path):
        (record,) = _run_ts_driver(tmp_path, self.PLAIN)["imports"]
        assert record["imported_symbols"] == ["exec", "spawn"]
        assert record.get("aliases", []) == []


class TestRustGroupMemberAliases:
    @pytest.mark.parametrize(
        "plain, aliased, pattern, record",
        [
            (
                'use std::process::{Command, exit};\nfn main() { Command::new("ls"); exit(0); }\n',
                'use std::process::{Command as Cmd, exit};\nfn main() { Cmd::new("ls"); exit(0); }\n',
                "Command::new",
                ("std::process", ["Cmd", "exit"], [["Cmd", "Command"]]),
            ),
            (
                'use std::process;\nfn main() { process::Command::new("ls"); }\n',
                'use std::process::{self as p, exit};\nfn main() { p::Command::new("ls"); }\n',
                "process::Command::new",
                ("std::process", ["p", "exit"], [["p", "process"]]),
            ),
        ],
        ids=["member-as", "self-as"],
    )
    def test_group_member_alias_is_judged_like_the_plain_use(self, plain, aliased, pattern, record):
        from aegis_core.ast.drivers.templates.rust_ast import parse_rust_source

        (imp,) = parse_rust_source(aliased, "m.rs")["imports"]
        assert (imp["module"], imp["imported_names"], imp["aliases"]) == record

        def violations(src: str) -> list[str]:
            return evaluate_forbid_ast(NormalizedAST.from_dict(parse_rust_source(src, "m.rs")), {"calls": [pattern]})

        assert violations(plain) == [f"Forbidden call '{pattern}' matched rule forbid_ast.calls"]
        assert violations(aliased) == violations(plain)

    # A nested or path member of a use-group must be judged exactly like the flat use-group
    # it abbreviates (b1-verify review): `use std::{process::{Command as Cmd}, io};` is
    # `use std::process::{Command as Cmd}; use std::{io};`.
    SPECS = (
        {"calls": ["Command::new"]},
        {"calls": ["process::Command::new"]},
        {"imports": ["std::process"]},
        {"imports": ["Command"]},
        {"imports": ["std::io"]},
    )

    @pytest.mark.parametrize(
        "grouped, flat",
        [
            (
                'use std::{process::{Command as Cmd}, io};\nfn main() { Cmd::new("ls"); }\n',
                'use std::process::{Command as Cmd};\nuse std::{io};\nfn main() { Cmd::new("ls"); }\n',
            ),
            (
                'use std::{process::{Command as Cmd, exit}, io::{self, Write}};\nfn main() { Cmd::new("ls"); }\n',
                'use std::process::{Command as Cmd, exit};\nuse std::io::{self, Write};\n'
                'fn main() { Cmd::new("ls"); }\n',
            ),
            (
                'use std::{process::Command as Cmd, io};\nfn main() { Cmd::new("ls"); }\n',
                'use std::process::{Command as Cmd};\nuse std::{io};\nfn main() { Cmd::new("ls"); }\n',
            ),
            (
                'use std::{process::Command, io};\nfn main() { Command::new("ls"); }\n',
                'use std::process::{Command};\nuse std::{io};\nfn main() { Command::new("ls"); }\n',
            ),
            (
                'use std::{process::{self as p}};\nfn main() { p::Command::new("ls"); }\n',
                'use std::process::{self as p};\nfn main() { p::Command::new("ls"); }\n',
            ),
            (
                'use {std::process::{Command as Cmd}};\nfn main() { Cmd::new("ls"); }\n',
                'use std::process::{Command as Cmd};\nfn main() { Cmd::new("ls"); }\n',
            ),
        ],
        ids=["nested-as", "nested-comma-self", "path-member-as", "path-member", "nested-self-as", "leading-brace"],
    )
    def test_nested_and_path_members_are_judged_like_the_flat_group(self, grouped, flat):
        from aegis_core.ast.drivers.templates.rust_ast import parse_rust_source

        def violations(src: str) -> list[list[str]]:
            norm = NormalizedAST.from_dict(parse_rust_source(src, "m.rs"))
            return [evaluate_forbid_ast(norm, spec) for spec in self.SPECS]

        assert violations(grouped) == violations(flat)
        assert any("matched rule forbid_ast.calls" in v for found in violations(grouped) for v in found)

    def test_no_member_text_leaks_into_a_bound_name(self):
        from aegis_core.ast.drivers.templates.rust_ast import parse_rust_source

        imports = parse_rust_source("use std::{process::{Command as Cmd, exit}, io::*};\n", "m.rs")["imports"]
        names = [n for imp in imports for n in imp["imported_names"]]
        pairs = [a for imp in imports for pair in imp.get("aliases", []) for a in pair]
        assert all(not set(n) & set("{}:, ") for n in names + pairs), (names, pairs)
        assert sorted((imp["module"], imp["is_wildcard"]) for imp in imports) == [
            ("std", False), ("std::io", True), ("std::process", False)
        ]

    def test_a_plain_self_member_binds_the_module_name(self):
        from aegis_core.ast.drivers.templates.rust_ast import parse_rust_source

        def violations(src: str) -> list[str]:
            norm = NormalizedAST.from_dict(parse_rust_source(src, "m.rs"))
            return evaluate_forbid_ast(norm, {"imports": ["process"], "calls": ["process::Command::new"]})

        plain = 'use std::process;\nfn main() { process::Command::new("ls"); }\n'
        grouped = 'use std::process::{self, exit};\nfn main() { process::Command::new("ls"); }\n'
        assert violations(grouped) == violations(plain) == [
            "Forbidden import 'process' matched rule forbid_ast.imports",
            "Forbidden call 'process::Command::new' matched rule forbid_ast.calls",
        ]


class TestRustCallSites:
    """Every Rust call is a call site, and only calls are (b1-verify fix round 2)."""

    def test_a_call_to_a_function_defined_below_it_is_seen(self):
        from aegis_core.ast.drivers.templates.rust_ast import parse_rust_source

        src = "fn main() { helper(); }\nfn helper() {}\n"
        norm = NormalizedAST.from_dict(parse_rust_source(src, "m.rs"))
        assert evaluate_forbid_ast(norm, {"calls": ["helper"]}) == [
            "Forbidden call 'helper' matched rule forbid_ast.calls"
        ]

    @pytest.mark.timing
    def test_a_large_generated_file_parses_in_linear_time(self):
        from aegis_core.ast.drivers.templates.rust_ast import parse_rust_source

        def run(calls: int) -> None:
            src = "fn main() {\n" + "".join(f"    helper({i});\n" for i in range(calls)) + "}\nfn helper(x: u32) {}\n"
            data = parse_rust_source(src, "m.rs")
            assert len(data["call_sites"]) == calls and data["call_sites"][-1]["line"] == calls + 1

        ratio = _doubling_ratio(run, 12_500)
        assert ratio < 3, f"doubling the calls multiplied the parse time by {ratio:.1f}"

    def test_control_flow_keywords_are_not_calls(self):
        from aegis_core.ast.drivers.templates.rust_ast import parse_rust_source

        src = "fn main() { if (a) { b(); } while (c) {} match (d, e) { _ => {} } }\nfn b() {}\n"
        assert [c["target"] for c in parse_rust_source(src, "m.rs")["call_sites"]] == ["b"]


# ── Review round 3: the decorator fallback read must not fail open ────────────

class TestDecoratorFallbackRead:
    def test_bom_source_decorators_are_found_without_metadata(self, tmp_path: Path):
        target = tmp_path / "bom.py"
        target.write_bytes(b"\xef\xbb\xbfimport functools\n@functools.lru_cache\ndef f():\n    pass\n")
        assert evaluate_forbid_ast(parse_python_ast(target), {"decorators": ["functools.lru_cache"]}) == [
            "Forbidden decorator 'functools.lru_cache' matched rule forbid_ast.decorators"
        ]

    def test_unparseable_source_raises_instead_of_passing(self, tmp_path: Path):
        from aegis_core.ast.policy import ASTExtractionError

        target = tmp_path / "broken.py"
        target.write_text("@functools.lru_cache\ndef (:\n", encoding="utf-8")
        with pytest.raises(ASTExtractionError, match=r"^cannot verify .*broken\.py: SyntaxError: "):
            evaluate_forbid_ast(NormalizedAST(file_path=str(target)), {"decorators": ["functools.lru_cache"]})

    def test_unparseable_source_is_not_read_without_decorator_patterns(self, tmp_path: Path):
        target = tmp_path / "broken.py"
        target.write_text("def (:\n", encoding="utf-8")
        assert evaluate_forbid_ast(NormalizedAST(file_path=str(target)), {"calls": ["eval"]}) == []
