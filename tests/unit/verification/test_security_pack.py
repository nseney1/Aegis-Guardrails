"""Behavioral tests for structured forbid_ast call predicates, delta evaluation, and Python security pack."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from aegis_core.ast.drivers.python import _call_args, _render_arg, parse_python_ast
from aegis_core.ast.policy import (
    evaluate_forbid_ast,
    evaluate_forbid_ast_delta,
    evaluate_forbid_ast_structured,
    extract_normalized_ast,
)
from aegis_core.ast.schema import CallSiteNode, NormalizedAST
from aegis_core.packs import import_pack, validate_pack
from aegis_core.rule_integrity import _forbid_patterns, _forbid_tokens
from aegis_core.verification.runner import _forbid_ast_spec_error
from aegis_core.verification.security_pack import (
    PYTHON_SECURITY_RULES,
    build_python_security_pack,
    evaluate_security_pack,
    is_test_path,
)

PACK_SPEC = {
    "calls": [
        {"name": "eval", "builtin": True},
        {"name": "exec", "builtin": True},
        "os.system",
        "os.popen",
        "pickle.loads",
        "pickle.load",
        "marshal.loads",
        "marshal.load",
        "tempfile.mktemp",
        "yaml.unsafe_load",
        {"name": "hashlib.md5", "where": {"usedforsecurity": {"not": False}}},
        {"name": "hashlib.sha1", "where": {"usedforsecurity": {"not": False}}},
        {"name": "subprocess.run", "where": {"shell": True}},
        {"name": "subprocess.Popen", "where": {"shell": True}},
        {"name": "subprocess.call", "where": {"shell": True}},
        {"name": "subprocess.check_output", "where": {"shell": True}},
        {"name": "yaml.load", "where": {"Loader|#1": {"in": ["Loader", "UnsafeLoader", "FullLoader"]}}},
        {"name": "hashlib.new", "where": {"name|#0": {"in": ["'md5'", "'sha1'"]}}},
        {"name": "requests.get", "where": {"verify": False}},
        {"name": "requests.post", "where": {"verify": False}},
    ]
}

_PACK_RULES = {r["id"]: r["forbid_ast"] for r in PYTHON_SECURITY_RULES}
YAML_RULE = _PACK_RULES["sec-py-yaml-unsafe-load"]
HASH_RULE = _PACK_RULES["sec-py-weak-hash-md5-sha1"]

# 36 probe cases covering forbid_probe2.py + predicate operators
PROBE_CASES = [
    ("eval bare TP", "x = eval(s)\n", PACK_SPEC, True),
    ("exec bare TP", "exec(code)\n", PACK_SPEC, True),
    ("builtins.eval TP", "import builtins\nbuiltins.eval(s)\n", PACK_SPEC, True),
    ("builtins alias b.eval TP", "import builtins as b\nb.eval(s)\n", PACK_SPEC, True),
    ("torch model.eval() safe", "model.eval()\n", PACK_SPEC, False),
    ("redis r.eval safe", "r.eval(script, 0)\n", PACK_SPEC, False),
    ("sqlmodel session.exec safe", "session.exec(select(User))\n", PACK_SPEC, False),
    ("self.tk.eval safe", "self.tk.eval('x')\n", PACK_SPEC, False),
    ("ast.literal_eval safe", "import ast\nast.literal_eval(s)\n", PACK_SPEC, False),
    ("shadowed eval via import", "from mylib import eval\neval(x)\n", PACK_SPEC, False),
    ("shadowed eval via local def", "def eval(x):\n    return x\neval(1)\n", PACK_SPEC, False),
    ("os.system TP", "import os\nos.system(c)\n", PACK_SPEC, True),
    ("pickle.loads TP", "import pickle\npickle.loads(b)\n", PACK_SPEC, True),
    ("import pickle as p alias TP", "import pickle as p\np.loads(b)\n", PACK_SPEC, True),
    ("json.loads safe", "import json\njson.loads(b)\n", PACK_SPEC, False),
    ("tempfile.mktemp TP", "import tempfile\ntempfile.mktemp()\n", PACK_SPEC, True),
    ("md5 default TP", "import hashlib\nhashlib.md5(b)\n", PACK_SPEC, True),
    ("md5 usedforsecurity=False safe", "import hashlib\nhashlib.md5(b, usedforsecurity=False)\n", PACK_SPEC, False),
    ("md5 usedforsecurity=True TP", "import hashlib\nhashlib.md5(b, usedforsecurity=True)\n", PACK_SPEC, True),
    ("md5 usedforsecurity=var unknown", "import hashlib\nhashlib.md5(b, usedforsecurity=flag)\n", PACK_SPEC, False),
    ("subprocess shell=True TP", "import subprocess\nsubprocess.run(c, shell=True)\n", PACK_SPEC, True),
    ("subprocess list safe", "import subprocess\nsubprocess.run(['ls'])\n", PACK_SPEC, False),
    ("subprocess shell=var ignored", "import subprocess\nsubprocess.run(c, shell=flag)\n", PACK_SPEC, False),
    ("subprocess **opts advisory", "import subprocess\nsubprocess.run(c, **opts)\n", PACK_SPEC, False),
    ("alias sp.run shell=True TP", "import subprocess as sp\nsp.run(c, shell=True)\n", PACK_SPEC, True),
    ("from subprocess import run shell=True TP", "from subprocess import run\nrun(c, shell=True)\n", PACK_SPEC, True),
    ("from subprocess import Popen as P TP", "from subprocess import Popen as P\nP(c, shell=True)\n", PACK_SPEC, True),
    ("yaml.load unsafe Loader TP", "import yaml\nyaml.load(f, Loader=yaml.Loader)\n", PACK_SPEC, True),
    ("yaml.load positional UnsafeLoader TP", "import yaml\nyaml.load(f, yaml.UnsafeLoader)\n", PACK_SPEC, True),
    ("yaml.load SafeLoader safe", "import yaml\nyaml.load(f, Loader=yaml.SafeLoader)\n", PACK_SPEC, False),
    ("yaml.load variable loader unknown", "import yaml\nyaml.load(f, self.loader)\n", PACK_SPEC, False),
    ("yaml.unsafe_load TP", "import yaml\nyaml.unsafe_load(f)\n", PACK_SPEC, True),
    ("requests verify=False TP", "import requests\nrequests.get(u, verify=False)\n", PACK_SPEC, True),
    ("requests default safe", "import requests\nrequests.get(u)\n", PACK_SPEC, False),
    ("requests verify=ca_path safe", "import requests\nrequests.get(u, verify=CA)\n", PACK_SPEC, False),
    ("hashlib.new('md5') positional TP", "import hashlib\nhashlib.new('md5')\n", PACK_SPEC, True),
    ("pack yaml.load Loader TP", "import yaml\nyaml.load(f, Loader=yaml.Loader)\n", YAML_RULE, True),
    ("pack yaml.load no Loader TP", "import yaml\nyaml.load(f)\n", YAML_RULE, True),
    ("pack yaml.load SafeLoader safe", "import yaml\nyaml.load(f, Loader=yaml.SafeLoader)\n", YAML_RULE, False),
    ("pack yaml.load CBaseLoader safe", "import yaml\nyaml.load(f, yaml.CBaseLoader)\n", YAML_RULE, False),
    ("pack md5 default TP", "import hashlib\nhashlib.md5(b)\n", HASH_RULE, True),
    ("pack md5 usedforsecurity=False safe", "import hashlib\nhashlib.md5(b, usedforsecurity=False)\n", HASH_RULE, False),
    ("pack new('sha1') TP", "import hashlib\nhashlib.new('sha1', b)\n", HASH_RULE, True),
    ("pack new('sha1') not for security", "import hashlib\nhashlib.new('sha1', b, usedforsecurity=False)\n", HASH_RULE, False),
]

# Each malformed where, the argument it names, and what the reason says about it.
MALFORMED_WHERE = [
    ({"shell": {"equal": True}}, "shell", "unknown operator equal (allowed: in, not, absent)"),
    ({"#0": {"in": "SafeLoader"}}, "#0", "in needs a non-empty list of scalars"),
    ({"shell": {"matches": "^(a+)+$"}}, "shell", "unknown operator matches (allowed: in, not, absent)"),
    ({"shell": {"not_equals": False}}, "shell", "unknown operator not_equals (allowed: in, not, absent)"),
    ({"shell": {"equals": True}}, "shell", "unknown operator equals (allowed: in, not, absent)"),
    ({"shell": {"present": True}}, "shell", "unknown operator present (allowed: in, not, absent)"),
    ({"shell": {"in": []}}, "shell", "in needs a non-empty list of scalars"),
    ({"shell": {"in": [["nested"]]}}, "shell", "in needs a non-empty list of scalars"),
    ({"shell": {"in": [1], "not": 2}}, "shell", "a condition is a scalar or one operator: in, not, absent"),
    ({"shell": {"absent": "yes"}}, "shell", "absent needs true or false"),
    ({"shell": {}}, "shell", "a condition is a scalar or one operator: in, not, absent"),
    ({"shell": {"not": {"bogus": 1}}}, "shell", "unknown operator bogus (allowed: in, not, absent)"),
    ({"shell": ["a", "b"]}, "shell", "a condition is a scalar or one operator: in, not, absent"),
    ({"": True}, "", "argument names are identifiers or #N, joined by |"),
    ({"name|": True}, "name|", "argument names are identifiers or #N, joined by |"),
    ({"#x": True}, "#x", "argument names are identifiers or #N, joined by |"),
]
MALFORMED_IDS = ["equal", "in-str", "matches", "not_equals", "equals", "present", "in-empty", "in-nested",
                 "two-ops", "absent-str", "empty", "not-bogus", "list", "empty-key", "trailing-bar", "bad-pos"]


class TestCallSiteArgsAndPredicates:
    def test_call_site_node_args_serialization_roundtrip(self):
        plain = CallSiteNode(target="foo", line=3)
        assert plain.args == {}
        assert "args" not in plain.to_dict()
        assert CallSiteNode.from_dict(plain.to_dict()) == plain

        with_args = CallSiteNode(target="subprocess.run", line=7, args={"#0": "'ls'", "shell": "True"})
        d = with_args.to_dict()
        assert d["args"] == {"#0": "'ls'", "shell": "True"}
        assert CallSiteNode.from_dict(d) == with_args

        norm = parse_python_ast("import subprocess\nsubprocess.run('ls', shell=True)\n", file_path="x.py")
        assert norm.call_sites[0].args == {"#0": "'ls'", "shell": "True"}
        assert NormalizedAST.from_json(norm.to_json()) == norm

    @pytest.mark.parametrize("label,src,spec,expected", PROBE_CASES, ids=[c[0] for c in PROBE_CASES])
    def test_forbid_probe_cases(self, label, src, spec, expected):
        norm = extract_normalized_ast("x.py", code=src)
        got = bool(evaluate_forbid_ast(norm, spec))
        assert got is expected, f"{label}: expected {expected}, got {got}"

    @pytest.mark.parametrize("where,src,expected", [
        ({"k": 1}, "f(k=1)\n", True),
        ({"k": 1}, "f(k=2)\n", False),
        ({"#0": {"in": ["md5", "sha1"]}}, "f('md5')\n", True),
        ({"#0": {"in": ["md5", "sha1"]}}, "f('sha256')\n", False),
        ({"k": {"not": 1}}, "f(k=2)\n", True),
        ({"k": {"not": 1}}, "f(k=1)\n", False),
        ({"k": {"not": {"in": [1, 2]}}}, "f(k=3)\n", True),
        ({"k": {"not": {"in": [1, 2]}}}, "f(k=2)\n", False),
        ({"k": {"absent": True}}, "f()\n", True),
        ({"k": {"absent": True}}, "f(k=1)\n", False),
        ({"k": {"absent": False}}, "f(k=1)\n", True),
        ({"k": {"absent": False}}, "f()\n", False),
    ], ids=["lit-hit", "lit-miss", "in-hit", "in-miss", "not-hit", "not-miss", "notin-hit", "notin-miss",
            "absent-hit", "absent-miss", "present-hit", "present-miss"])
    def test_the_four_spec_forms_evaluate(self, where, src, expected):
        spec = {"calls": [{"name": "f", "where": where}]}
        assert _forbid_ast_spec_error(spec) is None
        assert bool(evaluate_forbid_ast(extract_normalized_ast("x.py", code=src), spec)) is expected

    def test_a_rule_supplied_regex_never_runs(self):
        """Given ``matches`` (a removed operator) reaching the evaluator unvalidated, When a literal
        that makes ``^(a+)+$`` backtrack exponentially is checked, Then it returns at once: the
        operator is UNKNOWN (advisory), never handed to ``re``."""
        spec = {"calls": [{"name": "f", "where": {"#0": {"matches": "^(a+)+$"}}}]}
        norm = extract_normalized_ast("x.py", code="f('" + "a" * 40 + "!')\n")
        confirmed, unverified = evaluate_forbid_ast_structured(norm, spec, rule_id="r")
        assert confirmed == [] and [u["line"] for u in unverified] == [1]

    def test_unknown_is_always_advisory(self):
        norm_kw = extract_normalized_ast("x.py", code="import subprocess\nsubprocess.run(cmd, **kwargs)\n")
        norm_star = extract_normalized_ast("x.py", code="import hashlib\nhashlib.new(*args)\n")
        confirmed, unverified = evaluate_forbid_ast_structured(
            norm_kw, {"calls": [{"name": "subprocess.run", "where": {"shell": True}}]}, rule_id="sec-sub")
        assert confirmed == [] and [u["rule_id"] for u in unverified] == ["sec-sub"]
        assert evaluate_forbid_ast(norm_kw, {"calls": [{"name": "subprocess.run", "where": {"shell": True}}]}) == []
        c_star, u_star = evaluate_forbid_ast_structured(
            norm_star, {"calls": [{"name": "hashlib.new", "where": {"#0": "'md5'"}}]}, rule_id="sec-hash")
        assert c_star == [] and len(u_star) == 1


class TestWhereGrammarIsValidatedAtLoad:
    @pytest.mark.parametrize("where,arg,reason", MALFORMED_WHERE, ids=MALFORMED_IDS)
    def test_a_malformed_where_is_refused_with_its_argument_named(self, where, arg, reason):
        error = _forbid_ast_spec_error({"calls": ["os.system", {"name": "subprocess.run", "where": where}]})
        assert error == f"forbid_ast.calls[1].where.{arg}: {reason}"

    def test_an_empty_where_has_its_own_reason(self):
        assert _forbid_ast_spec_error({"calls": [{"name": "eval", "where": {}}]}) == (
            "forbid_ast.calls[0].where must map argument names to conditions")
        assert _forbid_ast_spec_error({"calls": [{"name": "eval", "where": ["shell"]}]}) == (
            "forbid_ast.calls[0].where must map argument names to conditions")

    @pytest.mark.parametrize("entry,key", [
        ({"name": "subprocess.run", "where": {"shell": True}, "unknown": "flag"}, "unknown"),
        ({"name": "subprocess.run", "unknown": "skip"}, "unknown"),
        ({"name": "subprocess.run", "unknown": "report"}, "unknown"),
        ({"name": "subprocess.run", "unknown": "ignore"}, "unknown"),
        ({"call": "subprocess.run"}, "call"),
        ({"name": "eval", "call": "eval"}, "call"),
    ], ids=["flag", "skip", "report", "ignore", "call-alias", "call-beside-name"])
    def test_a_removed_entry_key_is_refused_by_name(self, entry, key):
        assert _forbid_ast_spec_error({"calls": [entry]}) == (
            f"forbid_ast.calls[0]: unknown key '{key}' (allowed: builtin, name, where)")

    def test_a_where_needs_a_named_entry(self):
        """Sad path: a where cannot ride on a bare-string entry; beside one it is an unknown
        forbid_ast key, and an entry with a where and no name is refused."""
        assert _forbid_ast_spec_error({"calls": ["eval"], "where": {"shell": True}}) == (
            "unknown forbid_ast key 'where' (allowed: imports, calls, decorators)")
        assert _forbid_ast_spec_error({"calls": [{"where": {"shell": True}}]}) == (
            "forbid_ast.calls[0]: name must be a non-empty string and builtin true or false")

    @pytest.mark.parametrize("where", [
        {"shell": True}, {"verify": {"not": True}}, {"name|#0": {"in": ["md5", "sha1"]}},
        {"shell": {"absent": True}}, {"shell": {"not": {"not": None}}}, {"#1": 1.5},
    ], ids=["literal", "not", "in-alternation", "absent", "nested-not", "float"])
    def test_a_well_formed_where_loads(self, where):
        assert _forbid_ast_spec_error({"calls": [{"name": "f", "where": where, "builtin": False}]}) is None


class TestDeltaEvaluationAndRunnerIntegrity:
    def test_delta_vs_base_multiset_semantics(self):
        spec = {"calls": [{"name": "subprocess.run", "where": {"shell": True}}]}
        base_code = "import subprocess\nsubprocess.run('echo 1', shell=True)\n"
        # Shifting line numbers without adding a new violation does not block
        head_shifted = "# comment\n# comment 2\nimport subprocess\nsubprocess.run('echo 1', shell=True)\n"
        base_ast = extract_normalized_ast("app.py", code=base_code)
        head_shifted_ast = extract_normalized_ast("app.py", code=head_shifted)
        assert evaluate_forbid_ast_delta(spec, head_shifted_ast, base_ast, rule_id="r1") == []

        # Adding a second identical call site increases multiset count by 1 -> blocks
        head_added = (
            "import subprocess\n"
            "subprocess.run('echo 1', shell=True)\n"
            "subprocess.run('echo 1', shell=True)\n"
        )
        delta_added = evaluate_forbid_ast_delta(
            spec, extract_normalized_ast("app.py", code=head_added), base_ast, rule_id="r1"
        )
        assert len(delta_added) == 1
        assert delta_added[0]["line"] == 3

        # Changing arguments on existing call site changes args_signature -> blocks
        head_changed_arg = "import subprocess\nsubprocess.run('rm -rf /', shell=True)\n"
        delta_changed = evaluate_forbid_ast_delta(
            spec, extract_normalized_ast("app.py", code=head_changed_arg), base_ast, rule_id="r1"
        )
        assert len(delta_changed) == 1

    def test_runner_spec_validation_and_rule_integrity_tokens(self):
        valid_spec = {
            "calls": [
                "os.system",
                {"name": "eval", "builtin": True},
                {"name": "subprocess.run", "where": {"shell": True}},
            ]
        }
        assert _forbid_ast_spec_error(valid_spec) is None
        assert _forbid_ast_spec_error({"calls": [{}]}) is not None
        assert _forbid_ast_spec_error({"calls": [{"name": ""}]}) is not None
        assert "unknown key 'unknown'" in (_forbid_ast_spec_error({"calls": [{"name": "eval", "unknown": "invalid"}]}) or "")

        tokens = _forbid_tokens(valid_spec, "calls")
        assert tokens == ["os.system", "eval", "subprocess.run"]
        assert _forbid_patterns(valid_spec, "calls") == ["os.system", "eval", "subprocess.run"]
        assert _forbid_tokens(valid_spec["calls"]) == ["os.system", "eval", "subprocess.run"]


class TestPythonSecurityPack:
    def test_eight_rules_metadata_and_pack_validation(self, tmp_path: Path):
        expected_ids = {
            "sec-py-eval-exec",
            "sec-py-pickle-loads",
            "sec-py-yaml-unsafe-load",
            "sec-py-subprocess-shell",
            "sec-py-xml-etree",
            "sec-py-weak-hash-md5-sha1",
            "sec-py-tempfile-mktemp",
            "sec-py-requests-verify-false",
        }
        assert len(PYTHON_SECURITY_RULES) == 8
        assert {r["id"] for r in PYTHON_SECURITY_RULES} == expected_ids
        for rule in PYTHON_SECURITY_RULES:
            assert rule["tier"] == "invariant"
            assert rule["severity"] == "high"
            assert _forbid_ast_spec_error(rule["forbid_ast"]) is None

        pack = build_python_security_pack()
        entries = validate_pack(pack)
        assert len(entries) == 8

        # Verify pack can also be dry-run imported into an Aegis workspace
        (tmp_path / ".aegis" / "rules" / "invariants").mkdir(parents=True)
        res = import_pack(tmp_path, pack, dry_run=True)
        assert len(res.rules) == 8

    def test_is_test_path_classification(self):
        assert is_test_path("tests/unit/test_foo.py") is True
        assert is_test_path("test_example.py") is True
        assert is_test_path("pkg/foo_test.py") is True
        assert is_test_path("conftest.py") is True
        assert is_test_path("src/conftest.py") is True
        assert is_test_path("src/service.py") is False

    def test_evaluate_security_pack_delta_and_test_exemptions(self, tmp_path: Path):
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
        subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@e.st"], check=True)
        subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "T"], check=True)

        src_dir = tmp_path / "src"
        src_dir.mkdir()
        legacy_file = src_dir / "legacy.py"
        legacy_file.write_text("import tempfile\ntempfile.mktemp()\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
        subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "base"], check=True)

        # Shift legacy line without adding new violation, add a new violation in app.py, and add a hit in tests/
        legacy_file.write_text("# header\nimport tempfile\ntempfile.mktemp()\n", encoding="utf-8")
        app_file = src_dir / "app.py"
        app_file.write_text(
            "import xml.etree.ElementTree as ET\n"
            "ET.fromstring('<root/>')\n",
            encoding="utf-8",
        )
        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_eval.py").write_text("eval('1+1')\n", encoding="utf-8")

        report = evaluate_security_pack(tmp_path, base_ref="HEAD")
        assert report["passed"] is False
        # legacy.py's untouched mktemp is suppressed by delta; app.py's xml.etree is flagged
        assert [v["rule_id"] for v in report["violations"]] == ["sec-py-xml-etree"]
        assert report["violations"][0]["file"] == "src/app.py"
        # tests/test_eval.py is not silently dropped: it appears in exempted_test_findings
        assert len(report["exempted_test_findings"]) == 1
        assert report["exempted_test_findings"][0]["rule_id"] == "sec-py-eval-exec"
        assert report["exempted_test_findings"][0]["file"] == "tests/test_eval.py"
