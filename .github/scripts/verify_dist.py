"""Record or verify SHA-256 digests of the release distributions in dist/.

    python verify_dist.py record dist   # after the single build
    python verify_dist.py verify dist   # before testing and before publishing

`record` requires exactly one wheel and one sdist and writes dist/SHA256SUMS.
`verify` fails if any file is missing, altered, or unlisted, so the files that
are tested are byte-for-byte the files that are published. It prints the
verified file paths, one per line, for the caller to use.
"""
import glob
import hashlib
import os
from email.parser import BytesParser
from pathlib import PurePosixPath
import re
import sys
import zipfile

SUMS = "SHA256SUMS"
PACKAGES = {"aegis_core", "aegis_cli", "aegis_mcp", "aegis_sdk"}
TEMPLATE_PREFIX = "aegis_core/ast/drivers/templates/"
# M1 baseline. M2a removes ts_ast.js; M2b removes rust_ast.py here and in package-data.
TEMPLATES = {TEMPLATE_PREFIX + name for name in (
    "__init__.py", "ts_ast.js", "rust_ast.py", "go_ast.go", "go.mod")}
ASSETS = {"aegis_sdk/py.typed", "aegis_core/benchmark_corpus/corpus.json",
          "aegis_core/benchmark_corpus/ast.json"}
ASSETS.update("aegis_core/_data/rules/" + name for name in (
    "__init__.py", "META.md", "cost-optimization.md", "destructive-ops.md", "no-eval.md",
    "providence.md", "subagent-delegation.md", ".oracles/architectural-tenets.md",
    ".oracles/atomic-workstream-protocol.md", ".oracles/documentation.md", ".oracles/feature-specs.md",
    ".oracles/git-workflow.md", ".oracles/polyglot-standards.md", ".oracles/tdd-protocol.md",
    ".oracles/testing.md"))
ASSETS.add("aegis_core/_data/skills/__init__.py")
ASSETS.update("aegis_core/_data/skills/" + name + "/SKILL.md" for name in (
    "adaptive-reviewer", "domain-researcher", "genesis", "governance-auditor", "incident-debug",
    "performance-audit", "post-mortem", "readme-writer", "refactoring-pilot", "security-audit",
    "session-monitor", "session-preflight", "spec-synthesizer", "staff-review", "visual-analyst"))
DIST_INFO = {"METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD",
             "LICENSE", "NOTICE", "licenses/LICENSE", "licenses/NOTICE"}
FORBIDDEN_DIRS = {"node_modules", "vendor", "third_party"}
FORBIDDEN_SUFFIXES = {".so", ".pyd", ".dll", ".dylib", ".wasm", ".node", ".jar"}


def check_metadata(data):
    metadata = BytesParser().parsebytes(data)
    if metadata.get_all("Name") != ["aegis-guardrails"] or metadata.get_all("Provides-Extra") != ["dev"]:
        fail("wheel metadata must name aegis-guardrails and only the dev extra")
    for requirement in metadata.get_all("Requires-Dist", []):
        parts = requirement.split(";", 1)
        if len(parts) != 2 or not re.fullmatch(r"extra\s*==\s*(['\"])dev\1", parts[1].strip()):
            fail("wheel metadata contains a runtime or unsupported requirement: " + requirement)


def check_wheel(path):
    try:
        with zipfile.ZipFile(path) as wheel:
            names = wheel.namelist()
            if len(names) != len(set(names)):
                fail("duplicate wheel member")
            templates, metadata, info_roots = set(), [], set()
            for name in names:
                parts = PurePosixPath(name).parts
                if (not parts or "\\" in name or name.startswith("/") or
                        any(p in ("", ".", "..") for p in name.split("/")) or
                        any(p.lower() in FORBIDDEN_DIRS for p in parts) or
                        PurePosixPath(name).suffix.lower() in FORBIDDEN_SUFFIXES):
                    fail("forbidden wheel member: " + name)
                if name.startswith(TEMPLATE_PREFIX):
                    if name not in TEMPLATES:
                        fail("unexpected wheel member: " + name)
                    templates.add(name)
                elif re.fullmatch(r"aegis_guardrails-[A-Za-z0-9_.+!-]+\.dist-info", parts[0]):
                    info_roots.add(parts[0])
                    if "/".join(parts[1:]) not in DIST_INFO:
                        fail("unexpected wheel member: " + name)
                    if parts[1:] == ("METADATA",):
                        metadata.append(wheel.read(name))
                elif name in ASSETS:
                    continue
                elif (parts[0] not in PACKAGES or "_data" in parts or
                      PurePosixPath(name).suffix != ".py"):
                    fail("unexpected wheel member: " + name)
            if templates != TEMPLATES:
                fail("wheel template allowlist mismatch: " + repr(sorted(templates ^ TEMPLATES)))
            if len(info_roots) != 1:
                fail("unexpected wheel member: multiple dist-info directories")
            if len(metadata) != 1:
                fail("wheel metadata must contain exactly one METADATA file")
            check_metadata(metadata[0])
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        fail("invalid wheel: " + str(exc))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fail(msg):
    print(f"verify_dist: {msg}", file=sys.stderr)
    sys.exit(1)


def dists(d):
    wheels = sorted(glob.glob(os.path.join(d, "*.whl")))
    sdists = sorted(glob.glob(os.path.join(d, "*.tar.gz")))
    if len(wheels) != 1 or len(sdists) != 1:
        fail(f"expected exactly one wheel and one sdist, found {wheels + sdists}")
    return wheels + sdists


def record(d):
    paths = dists(d)
    check_wheel(paths[0])
    lines = [f"{sha256(p)}  {os.path.basename(p)}\n" for p in paths]
    with open(os.path.join(d, SUMS), "w", encoding="utf-8") as f:
        f.writelines(lines)
    sys.stdout.write("".join(lines))


def verify(d):
    sums_path = os.path.join(d, SUMS)
    if not os.path.isfile(sums_path):
        fail(f"{sums_path} is missing")
    expected = {}
    with open(sums_path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                digest, name = line.rstrip("\n").split("  ", 1)
                expected[name] = digest
    present = {os.path.basename(p) for p in dists(d)}
    if present != set(expected):
        fail(f"dist/ contents {sorted(present)} do not match {SUMS} {sorted(expected)}")
    for name, digest in sorted(expected.items()):
        actual = sha256(os.path.join(d, name))
        if actual != digest:
            fail(f"{name}: sha256 {actual} != recorded {digest}")
        if name.endswith(".whl"):
            check_wheel(os.path.join(d, name))
        print(os.path.join(d, name))


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("record", "verify"):
        fail("usage: verify_dist.py record|verify DIST_DIR")
    {"record": record, "verify": verify}[sys.argv[1]](sys.argv[2])
