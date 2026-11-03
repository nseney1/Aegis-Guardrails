"""AC-32: check canonical dependency declarations and build the Go driver offline.

Python 3.9 compatible, with no third-party imports. The source guard accepts the
repository's simple dependency-table syntax; unsupported spellings fail explicitly.
The separate Go command runs once per build, never as part of ordinary pytest.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

TEMPLATES = Path("aegis_core/ast/drivers/templates")
GO_MODULE = ["module aegis.local/goast", "go 1.21"]
GO_ENV = {"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOWORK": "off", "GOFLAGS": "-mod=mod",
          "GOENV": "off", "GO111MODULE": "on", "CGO_ENABLED": "0"}


def source(root):
    try:
        text = (root / "pyproject.toml").read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError("cannot read pyproject.toml: " + str(exc)) from exc
    if '"""' in text or "'''" in text:
        raise ValueError("unsupported multiline TOML strings")
    sections, current = {}, None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line != "]":
            if not re.fullmatch(r"\[[A-Za-z0-9_.-]+\]", line):
                raise ValueError("unsupported TOML table syntax: " + line)
            current = line[1:-1]
            if current in sections:
                raise ValueError("duplicate TOML table: " + current)
            if current.startswith("project.") and current not in (
                    "project.scripts", "project.urls", "project.optional-dependencies"):
                raise ValueError("unsupported project table: " + current)
            sections[current] = []
        elif current is None:
            raise ValueError("unsupported assignment outside a TOML table")
        else:
            sections[current].append(line)
    project = sections.get("project", [])
    keys = set()
    for line in project:
        if "=" not in line or line.startswith("{"):
            continue
        key = line.split("=", 1)[0].strip()
        if not re.fullmatch(r"[a-z][a-z0-9-]*", key) or key == "optional-dependencies":
            raise ValueError("unsupported project key syntax: " + key)
        if key in keys:
            raise ValueError("duplicate project key: " + key)
        keys.add(key)
    body = "\n".join(project)
    if len(re.findall(r"(?m)^dependencies\s*=\s*\[\s*\]\s*$", body)) != 1:
        raise ValueError("[project] must declare dependencies = []")
    dynamic = re.search(r"(?m)^dynamic\s*=\s*(.*)$", body)
    if dynamic and not re.fullmatch(r"\[\s*(['\"])version\1\s*\]", dynamic.group(1)):
        raise ValueError("unsupported dynamic project metadata")
    extras = "\n".join(sections.get("project.optional-dependencies", []))
    dev = re.fullmatch(r"dev\s*=\s*(\[.*\])", extras, re.S)
    if not dev:
        raise ValueError("only the dev optional-dependencies key is allowed")
    string = r'''(?:"[^"\\\r\n]*"|'[^'\\\r\n]*')'''
    array = r"\[\s*(?:" + string + r"(?:\s*,\s*" + string + r")*\s*,?)?\s*\]"
    if not re.fullmatch(array, dev.group(1)):
        raise ValueError("unsupported dev requirements syntax")


def run_go(command, args, directory, env, timeout):
    try:
        proc = subprocess.run(command + args, cwd=directory, env=env,
                              capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise ValueError("go " + args[0] + " timed out") from exc
    if proc.returncode:
        raise ValueError("go " + args[0] + " failed: " + proc.stderr[-1000:].strip())
    return proc.stdout


def go(root, command, timeout):
    template = root / TEMPLATES
    module = (template / "go.mod").read_text(encoding="utf-8")
    statements = [line.split("//", 1)[0].strip() for line in module.splitlines()]
    if [line for line in statements if line] != GO_MODULE:
        raise ValueError("expected first-party go.mod with only module and go 1.21")
    executable = shutil.which(command[0])
    if not executable:
        raise ValueError("Go executable not found: " + command[0])
    command = [executable] + command[1:]
    env = dict(os.environ, **GO_ENV)
    with tempfile.TemporaryDirectory(prefix="aegis-go-dependencies-") as directory:
        for name in ("go_ast.go", "go.mod"):
            shutil.copyfile(template / name, Path(directory) / name)
        result = run_go(command, ["list", "-json", "."], directory, env, timeout)
        try:
            package = json.loads(result)
            imports = package["Imports"]
            if not isinstance(imports, list) or not all(isinstance(p, str) and p for p in imports):
                raise ValueError("missing imports")
            if package.get("Error"):
                raise ValueError("package error")
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError("invalid go list result") from exc
        for path in imports:
            if path == "C" or "." in path.split("/", 1)[0]:
                raise ValueError("non-standard Go import: " + path)
        binary = str(Path(directory) / ("go_ast.exe" if os.name == "nt" else "go_ast"))
        run_go(command, ["build", "-trimpath", "-o", binary, "."], directory, env, timeout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("source", "go"))
    parser.add_argument("root", type=Path)
    parser.add_argument("--go-command", nargs="+", default=["go"], help="Go executable and fixed arguments")
    parser.add_argument("--timeout", type=float, default=120, help="Go command deadline, at most 120 seconds")
    args = parser.parse_args()
    try:
        if not 0 < args.timeout <= 120:
            raise ValueError("timeout must be positive and at most 120 seconds")
        if args.mode == "source":
            source(args.root)
        else:
            go(args.root, args.go_command, args.timeout)
    except (OSError, ValueError, SyntaxError) as exc:
        parser.exit(1, "zero dependencies: " + args.mode + ": " + str(exc) + "\n")
    print("zero dependencies: " + args.mode + " ok")


if __name__ == "__main__":
    main()
