"""Behavioral tests for structured forbid_ast call predicates, delta evaluation, and Python security pack."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from aegis_core.ast.drivers.python import parse_python_ast
from aegis_core.ast.policy import (
    evaluate_forbid_ast,
    evaluate_forbid_ast_delta,
    evaluate_forbid_ast_structured,
    extract_normalized_ast,
)
from aegis_core.ast.schema import CallSiteNode, NormalizedAST
from aegis_core.rule_integrity import _forbid_patterns, _forbid_tokens
from aegis_core.verification.runner import _forbid_ast_spec_error
from aegis_core.verification.security_pack import PYTHON_SECURITY_RULES, evaluate_security_pack

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
        found = evaluate_forbid_ast_structured(norm, spec, rule_id="r")
        assert [(f["line"], f["unknown"]) for f in found] == [(1, True)]

    def test_unknown_is_always_advisory(self):
        norm_kw = extract_normalized_ast("x.py", code="import subprocess\nsubprocess.run(cmd, **kwargs)\n")
        norm_star = extract_normalized_ast("x.py", code="import hashlib\nhashlib.new(*args)\n")
        found = evaluate_forbid_ast_structured(
            norm_kw, {"calls": [{"name": "subprocess.run", "where": {"shell": True}}]}, rule_id="sec-sub")
        assert [(f["rule"], f["unknown"]) for f in found] == [("sec-sub", True)]
        assert evaluate_forbid_ast(norm_kw, {"calls": [{"name": "subprocess.run", "where": {"shell": True}}]}) == []
        found_star = evaluate_forbid_ast_structured(
            norm_star, {"calls": [{"name": "hashlib.new", "where": {"#0": "'md5'"}}]}, rule_id="sec-hash")
        assert [f["unknown"] for f in found_star] == [True]


_EIGHT_KEYS = {"rule", "kind", "pattern", "path", "line", "snippet", "unknown", "override"}
_SHELL = {"calls": [{"name": "subprocess.run", "where": {"shell": True}}]}
_PARITY_CASES = [(label, src, spec) for label, src, spec, _ in PROBE_CASES] + [
    ("import and alias", "import pickle as p\nfrom marshal import loads\n", {"imports": ["pickle", "marshal"]}),
    ("decorator", "import functools\n@functools.lru_cache\ndef f():\n    pass\n", {"decorators": ["functools.lru_cache"]}),
    ("all kinds in spec order", "import pickle\n@app.route('/')\ndef f():\n    eval(x)\n    pickle.loads(b)\n",
     {"imports": ["pickle"], "calls": ["pickle.loads", {"name": "eval", "builtin": True}], "decorators": ["app.route"]}),
    ("allow comment ignored", "eval(x)  # aegis: allow: legacy\n", {"calls": ["eval"]}),
]


def _tree(tmp_path: Path, name: str, code: str):
    """The AST of ``code`` read from a real file, so findings carry its source lines."""
    path = tmp_path / name / "app.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(code.encode("utf-8"))
    return extract_normalized_ast(str(path))


class TestStructuredFindings:
    """R-checks-11: one evaluator returns findings; the messages and the delta derive from them."""

    def test_a_changed_argument_expression_is_a_new_finding(self, tmp_path: Path):
        """Given base `subprocess.run(build_safe(), shell=True)` and a head that only changes the
        argument expression, When the delta runs, Then the head call is reported (the old key
        rendered both arguments as <expr>)."""
        base = _tree(tmp_path, "base", "import subprocess\nsubprocess.run(build_safe(), shell=True)\n")
        head = _tree(tmp_path, "head", "import subprocess\nsubprocess.run(request.args['cmd'] + x, shell=True)\n")
        delta = evaluate_forbid_ast_delta(_SHELL, head, base, rule_id="no-shell")
        assert [(f["kind"], f["line"]) for f in delta] == [("calls", 2)]
        assert "request.args" in delta[0]["snippet"]

    @pytest.mark.parametrize("head", [
        "# moved\n\n\nimport subprocess\nsubprocess.run(build_safe(), shell=True)\n",
        "import subprocess\nif True:\n        subprocess.run(build_safe(),   shell=True)\n",
    ], ids=["moved", "reindented"])
    def test_a_legacy_call_that_only_moved_or_was_reindented_is_not_new(self, tmp_path: Path, head: str):
        base = _tree(tmp_path, "base", "import subprocess\nsubprocess.run(build_safe(), shell=True)\n")
        assert evaluate_forbid_ast_delta(_SHELL, _tree(tmp_path, "head", head), base, rule_id="no-shell") == []

    def test_an_edit_on_a_continuation_line_keeps_the_key(self, tmp_path: Path):
        """Residual R1, accepted for 4.4.0: the key is the call's first source line, so a change
        confined to a later line of a multi-line call is not new. Flip this knowingly."""
        base = _tree(tmp_path, "base", "import subprocess\nsubprocess.run(\n    safe(), shell=True)\n")
        head = _tree(tmp_path, "head", "import subprocess\nsubprocess.run(\n    request.args['x'], shell=True)\n")
        assert evaluate_forbid_ast_delta(_SHELL, head, base, rule_id="no-shell") == []

    def test_two_identical_calls_at_base_and_three_at_head_report_one_head_line_absent_at_base(self, tmp_path: Path):
        call = "subprocess.run(cmd, shell=True)\n"
        base = _tree(tmp_path, "base", "import subprocess\n" + call + "x = 1\n" + call)
        head = _tree(tmp_path, "head", "import subprocess\n" + call + call + "x = 1\n" + call)
        delta = evaluate_forbid_ast_delta(_SHELL, head, base, rule_id="no-shell")
        assert len(delta) == 1 and delta[0]["line"] in (3, 5)

    def test_an_allowed_hit_is_kept_as_an_override_and_an_allow_for_another_rule_is_not(self):
        src = "x = eval(1)  # aegis: allow[no-eval]: reviewed\ny = eval(2)  # aegis: allow[other-rule]: theirs\n"
        found = evaluate_forbid_ast_structured(extract_normalized_ast("x.py", code=src), {"calls": ["eval"]},
                                               rule_id="no-eval", source=src)
        assert isinstance(found, list)
        assert [(f["line"], f["override"]) for f in found] == [(1, "reviewed"), (2, None)]

    def test_every_finding_has_exactly_the_eight_keys(self):
        src = ("import pickle\nimport functools\nimport subprocess\n@functools.lru_cache\ndef f():\n    pass\n"
               "subprocess.run(c, shell=True)\nsubprocess.run(c, **kw)\n")
        spec = {"imports": ["pickle"], "calls": [{"name": "subprocess.run", "where": {"shell": True}}],
                "decorators": ["functools.lru_cache"]}
        found = evaluate_forbid_ast_structured(extract_normalized_ast("x.py", code=src), spec, rule_id="r", source=src)
        assert isinstance(found, list)
        assert [set(f) for f in found] == [_EIGHT_KEYS] * 4
        assert [(f["kind"], f["line"], f["unknown"]) for f in found] == [
            ("imports", 1, False), ("calls", 7, False), ("calls", 8, True), ("decorators", 0, False)]
        assert [f["snippet"] for f in found[:3]] == ["import pickle", "subprocess.run(c, shell=True)",
                                                     "subprocess.run(c, **kw)"]

    @pytest.mark.parametrize("label,src,spec", _PARITY_CASES, ids=[c[0] for c in _PARITY_CASES])
    def test_the_wrapper_returns_the_messages_derived_from_the_findings(self, label, src, spec):
        from aegis_core.ast.policy import violation_messages

        norm = extract_normalized_ast("x.py", code=src)
        assert evaluate_forbid_ast(norm, spec) == violation_messages(evaluate_forbid_ast_structured(norm, spec, source=""))

    def test_an_unparsable_python_file_fails_closed(self):
        from aegis_core.ast.policy import ASTExtractionError

        with pytest.raises(ASTExtractionError):
            extract_normalized_ast("bad.py", code="import os\ndef broken(:\n")

    def test_a_hand_built_tree_keys_on_its_target_and_arguments(self):
        def tree(arg: str) -> NormalizedAST:
            return NormalizedAST(file_path="generated/no_such_file.py", language="python",
                                 call_sites=(CallSiteNode(target="os.system", line=4, args={"#0": arg}),))

        found = evaluate_forbid_ast_structured(tree("'ls'"), {"calls": ["os.system"]}, rule_id="r")
        assert [f["snippet"] for f in found] == ["os.system(#0='ls')"]
        assert evaluate_forbid_ast_delta({"calls": ["os.system"]}, tree("'ls'"), tree("'ls'")) == []
        assert [f["line"] for f in evaluate_forbid_ast_delta({"calls": ["os.system"]}, tree("'rm'"), tree("'ls'"))] == [4]

    def test_long_lines_keep_a_bounded_exact_identity(self):
        prefix = "eval('" + "a" * 300
        src = f"{prefix}b')\n{prefix}c')\n"
        found = evaluate_forbid_ast_structured(extract_normalized_ast("x.py", code=src), {"calls": ["eval"]}, source=src)
        snippets = [f["snippet"] for f in found]
        assert len(snippets) == 2 and snippets[0] != snippets[1]
        assert all(len(s) == 213 and s[:200] == prefix[:200] and s[200] == "#" for s in snippets)


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


_SHIPPED = {r["id"]: r for r in PYTHON_SECURITY_RULES}
# One violating and one clean source per shipped rule: (rule id, positive, its line, negative).
_RULE_FIXTURES = [
    ("sec-py-eval-exec", "x = 1\nx = eval(s)\n", 2, "model.eval()\nsession.exec(q)\n"),
    ("sec-py-pickle-loads", "import pickle\npickle.loads(b)\n", 2, "import json\njson.loads(b)\n"),
    ("sec-py-yaml-unsafe-load", "import yaml\nyaml.load(f)\n", 2, "import yaml\nyaml.load(f, Loader=yaml.SafeLoader)\n"),
    ("sec-py-subprocess-shell", "import subprocess\nsubprocess.run(c, shell=True)\n", 2,
     "import subprocess\nsubprocess.run(['ls'])\n"),
    ("sec-py-weak-hash-md5-sha1", "import hashlib\nhashlib.md5(b)\n", 2, "import hashlib\nhashlib.md5(b, usedforsecurity=False)\n"),
    ("sec-py-tempfile-mktemp", "import tempfile\ntempfile.mktemp()\n", 2, "import tempfile\ntempfile.mkstemp()\n"),
    ("sec-py-requests-verify-false", "import requests\nrequests.get(u, verify=False)\n", 2,
     "import requests\nrequests.get(u)\n"),
]


def _pack(root: Path, files: dict, changed=None, base=None) -> dict:
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
    return evaluate_security_pack(root, list(files) if changed is None else changed, base or {})


class TestPythonSecurityPack:
    def test_the_seven_shipped_rules_each_have_a_fixture_and_load_as_gates(self):
        assert sorted(_SHIPPED) == sorted(rid for rid, *_ in _RULE_FIXTURES)
        for rule in PYTHON_SECURITY_RULES:
            assert (rule["severity"], rule["enforcement"]) == ("high", "gate") and "tier" not in rule
            assert _forbid_ast_spec_error(rule["forbid_ast"]) is None

    @pytest.mark.parametrize("rule_id,positive,line,negative", _RULE_FIXTURES, ids=[f[0] for f in _RULE_FIXTURES])
    def test_each_shipped_rule_flags_its_positive_fixture_and_not_its_negative(self, tmp_path: Path, rule_id, positive,
                                                                              line, negative):
        hit = _pack(tmp_path, {"pos.py": positive, "neg.py": negative})
        assert [(v["rule_id"], v["file"], v["line"]) for v in hit["violations"]] == [(rule_id, "pos.py", line)]
        assert hit["unverified_findings"] == [] and hit["passed"] is False

    def test_an_unreadable_file_is_one_unverified_record_never_a_clean_skip(self, tmp_path: Path):
        report = _pack(tmp_path, {"bad.py": 'import os\nos.system("x")\ndef broken(:\n', "ok.py": 'import os\nos.system("x")\n'})
        assert [v["file"] for v in report["violations"]] == ["ok.py"]
        (record,) = report["unverified_findings"]
        assert {k: record[k] for k in ("rule_id", "file", "line", "kind", "status", "severity")} == {
            "rule_id": "", "file": "bad.py", "line": 0, "kind": "file", "status": "unverified", "severity": "high"}
        assert record["reason"].startswith("SyntaxError") and str(tmp_path) not in record["reason"]

    def test_a_file_it_cannot_decode_is_reported_with_its_codec(self, tmp_path: Path):
        report = _pack(tmp_path, {"seven.py": b"# -*- coding: utf-7 -*-\nimport os\nos.system('x')\n"})
        assert [(u["file"], u["kind"]) for u in report["unverified_findings"]] == [("seven.py", "file")]
        assert "utf-7" in report["unverified_findings"][0]["reason"]

    def test_a_deleted_file_is_absent_not_unverified(self, tmp_path: Path):
        report = evaluate_security_pack(tmp_path, ["gone.py"], {"gone.py": "import os\nos.system('x')\n"})
        assert report == {"passed": True, "violations": [], "exempted_test_findings": [], "unverified_findings": []}

    @pytest.mark.parametrize("spelling", [".hidden/evil.py", "./.hidden/evil.py", ".\\.hidden\\evil.py"],
                             ids=["plain", "dot-slash", "backslashes"])
    def test_a_dot_directory_is_scanned_however_it_is_spelled(self, tmp_path: Path, spelling: str):
        report = _pack(tmp_path, {".hidden/evil.py": "import os\nos.system('x')\n"}, changed=[spelling])
        assert [(v["rule_id"], v["file"]) for v in report["violations"]] == [("sec-py-subprocess-shell", ".hidden/evil.py")]

    @pytest.mark.parametrize("spelling", ["../outside.py", "./../outside.py", "src/../../outside.py", "absolute"],
                             ids=["parent", "dot-parent", "climbing", "absolute"])
    def test_a_path_outside_the_workspace_is_never_scanned(self, tmp_path: Path, spelling: str):
        ws = tmp_path / "ws"
        ws.mkdir()
        (tmp_path / "outside.py").write_bytes(b"import os\nos.system('x')\n")
        changed = [str(tmp_path / "outside.py") if spelling == "absolute" else spelling]
        report = evaluate_security_pack(ws, changed, {})
        assert report["violations"] == [] and report["unverified_findings"] == []

    @pytest.mark.parametrize("src,flagged", [
        ("import requests\ns = requests.Session()\ns.get(u, verify=False)\n", True),
        ("import requests\nrequests.get(u, verify=False)\n", True),
        ("d = {}\nd.get('k', 1)\n", False),
        ("import requests\ns = requests.Session()\ns.get(u, verify=True)\n", False),
        ("import hashlib\nhashlib.new('MD5')\n", True),
        ("import hashlib\nhashlib.new('md5')\n", True),
        ("import hashlib\nhashlib.md5(b, usedforsecurity=False)\n", False),
    ], ids=["session-get", "module-get", "dict-get", "verify-true", "new-MD5", "new-md5", "not-for-security"])
    def test_the_spellings_the_pack_used_to_miss(self, tmp_path: Path, src: str, flagged: bool):
        assert bool(_pack(tmp_path, {"app.py": src})["violations"]) is flagged

    def test_evaluate_security_pack_delta_and_test_exemptions(self, tmp_path: Path):
        from aegis_core import gitsafe

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
        (src_dir / "app.py").write_text("import pickle\npickle.loads(blob)\n", encoding="utf-8")
        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_eval.py").write_text("eval('1+1')\n", encoding="utf-8")
        changed = ["src/legacy.py", "src/app.py", "tests/test_eval.py"]
        base = {rel: (lambda b: None if b is None else b.decode("utf-8"))(gitsafe.read_blob(tmp_path, "HEAD", rel))
                for rel in changed}

        report = evaluate_security_pack(tmp_path, changed, base)
        assert report["passed"] is False
        # legacy.py's untouched mktemp is suppressed by delta; app.py's pickle.loads is flagged
        assert [(v["rule_id"], v["file"], v["line"]) for v in report["violations"]] == [("sec-py-pickle-loads", "src/app.py", 2)]
        # tests/test_eval.py is not silently dropped: it appears in exempted_test_findings
        assert [(f["rule_id"], f["file"]) for f in report["exempted_test_findings"]] == [("sec-py-eval-exec", "tests/test_eval.py")]
