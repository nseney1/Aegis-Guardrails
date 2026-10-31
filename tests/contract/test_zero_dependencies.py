"""AC-32 gates through their CLI; synthetic archives and processes avoid rebuilds."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / ".github" / "scripts" / "check_zero_dependencies.py"
TEMPLATES = Path("aegis_core/ast/drivers/templates")
PROJECT = '[project]\nname = "aegis-guardrails"\ndynamic = ["version"]\ndependencies = []\n'
EXTRAS = '[project.optional-dependencies]\ndev = ["pytest"]\n'


def _run(root, *args, env=None):
    return subprocess.run([sys.executable, str(GATE), args[0], str(root), *args[1:]],
                          capture_output=True, text=True, timeout=10, env=env)


def _source(tmp_path, text=PROJECT + EXTRAS):
    (tmp_path / "pyproject.toml").write_text(text, encoding="utf-8")
    return tmp_path


def test_source_gate_accepts_the_checkout_and_dev_requirements(tmp_path):
    for root in (ROOT, _source(tmp_path)):
        proc = _run(root, "source")
        assert (proc.returncode, proc.stdout.strip()) == (0, "zero dependencies: source ok"), proc.stderr


@pytest.mark.parametrize("text", [
    PROJECT.replace("dependencies = []", 'dependencies = ["requests"]') + EXTRAS,
    PROJECT.replace("dependencies = []\n", "") + EXTRAS + '[tool.other]\ndependencies = []\n',
    PROJECT + EXTRAS + 'parser = []\n', PROJECT + EXTRAS + '"parser" = []\n',
    PROJECT + '[project.optional-dependencies.parser]\nx = []\n',
    PROJECT.replace('dynamic = ["version"]', 'dynamic = ["version", "dependencies"]') + EXTRAS,
    PROJECT.replace("dependencies = []", '"dependencies" = []') + EXTRAS,
    PROJECT + 'optional-dependencies.parser = []\n' + EXTRAS,
    PROJECT + EXTRAS + "[project]\ndependencies = []\n",
    PROJECT.replace("dependencies = []", 'description = """\ndependencies = []\n"""') + EXTRAS,
    PROJECT + EXTRAS.replace('dev = ["pytest"]', 'dev = [not_toml'),
    PROJECT + EXTRAS.replace('"pytest"', 'r"pytest"'),
    PROJECT + EXTRAS.replace('"pytest"', '"py" "test"'),
])
def test_source_gate_rejects_dependencies_extras_and_unsupported_grammar(tmp_path, text):
    proc = _run(_source(tmp_path, text), "source")
    assert proc.returncode == 1 and "zero dependencies: source:" in proc.stderr, proc.stderr


def test_source_gate_reports_a_missing_manifest(tmp_path):
    proc = _run(tmp_path, "source")
    assert proc.returncode == 1 and "cannot read pyproject.toml" in proc.stderr


def _go(tmp_path):
    target = tmp_path / TEMPLATES
    target.mkdir(parents=True)
    (target / "go_ast.go").write_text('package main\nimport "fmt"\nfunc main() { fmt.Print("ok") }\n',
                                         encoding="utf-8")
    (target / "go.mod").write_text("module aegis.local/goast\n\ngo 1.21\n", encoding="utf-8")
    stub = tmp_path / "go_boundary.py"
    stub.write_text('''import json, os, pathlib, sys, time
with open(os.environ["GO_STUB_LOG"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps({"argv": sys.argv[1:], "cwd": os.getcwd(),
        "files": sorted(p.name for p in pathlib.Path.cwd().iterdir()),
        "env": {k: os.environ.get(k) for k in ("GOPROXY", "GOFLAGS", "GOTOOLCHAIN",
            "GOWORK", "GOENV", "GO111MODULE", "CGO_ENABLED")}}) + "\\n")
mode = os.environ.get("GO_STUB_MODE", "ok")
if mode == "timeout" or (mode == "build-timeout" and sys.argv[1] == "build"): time.sleep(5)
if mode == "failure" or (mode == "build-failure" and sys.argv[1] == "build"):
    sys.exit("compiler unavailable")
if sys.argv[1] == "list":
    print("not json" if mode == "malformed" else json.dumps(
        {"Imports": [mode] if mode in ("example.com/parser", "C") else ["fmt", "go/ast"]}))
''', encoding="utf-8")
    env = dict(os.environ, GO_STUB_LOG=str(tmp_path / "calls.jsonl"))
    env.update(GOPROXY="https://invalid", GOFLAGS="-mod=vendor", GOTOOLCHAIN="auto", GOWORK="inherited")
    return stub, env


def test_go_gate_builds_only_copied_first_party_sources_with_offline_env(tmp_path):
    stub, env = _go(tmp_path)
    proc = _run(tmp_path, "go", "--go-command", sys.executable, str(stub), env=env)
    assert (proc.returncode, proc.stdout.strip()) == (0, "zero dependencies: go ok"), proc.stderr
    calls = [json.loads(line) for line in Path(env["GO_STUB_LOG"]).read_text().splitlines()]
    assert calls[0]["argv"] == ["list", "-json", "."]
    assert calls[1]["argv"][0:3] == ["build", "-trimpath", "-o"] and calls[1]["argv"][-1] == "."
    for call in calls:
        assert call["cwd"] != str(tmp_path) and call["files"] == ["go.mod", "go_ast.go"]
        assert call["env"] == {"GOPROXY": "off", "GOFLAGS": "-mod=mod", "GOTOOLCHAIN": "local",
                               "GOWORK": "off", "GOENV": "off", "GO111MODULE": "on", "CGO_ENABLED": "0"}
    assert not Path(calls[0]["cwd"]).exists()


@pytest.mark.parametrize("mode,reason", [("example.com/parser", "non-standard Go import"),
    ("C", "non-standard Go import"), ("failure", "go list failed"),
    ("malformed", "invalid go list result"), ("timeout", "go list timed out"),
    ("build-failure", "go build failed"), ("build-timeout", "go build timed out")])
def test_go_gate_fails_closed_at_the_process_boundary(tmp_path, mode, reason):
    stub, env = _go(tmp_path)
    env["GO_STUB_MODE"] = mode
    args = ["--timeout", "0.2"] if "timeout" in mode else []
    proc = _run(tmp_path, "go", *args, "--go-command", sys.executable, str(stub), env=env)
    assert proc.returncode == 1 and reason in proc.stderr, proc.stderr


@pytest.mark.parametrize("directive", ['require example.com/parser v1.0.0',
    'replace example.com/parser => ../parser', 'toolchain go1.99.0'])
def test_go_gate_rejects_module_directives_before_running_go(tmp_path, directive):
    stub, env = _go(tmp_path)
    with (tmp_path / TEMPLATES / "go.mod").open("a", encoding="utf-8") as stream:
        stream.write(directive + "\n")
    proc = _run(tmp_path, "go", "--go-command", sys.executable, str(stub), env=env)
    assert proc.returncode == 1 and "first-party go.mod" in proc.stderr
    assert not Path(env["GO_STUB_LOG"]).exists()


def test_go_gate_reports_a_missing_toolchain(tmp_path):
    _go(tmp_path)
    proc = _run(tmp_path, "go", "--go-command", str(tmp_path / "missing-go"))
    assert proc.returncode == 1 and "Go executable not found" in proc.stderr
