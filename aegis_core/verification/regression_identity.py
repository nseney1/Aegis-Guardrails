"""Parent-prepared native selections with stable package, target and file ownership."""
from __future__ import annotations

from dataclasses import dataclass, replace
import json
from pathlib import Path, PurePosixPath
import re
import time
from typing import Sequence

from aegis_core import testexec
from aegis_core.ast.driver_errors import ASTDriverError
from aegis_core.ast.drivers.rust import parse as parse_rust
from aegis_core.ast.drivers.rust.tokenizer import tokenize
from aegis_core.ast.policy import ASTExtractionError, extract_normalized_ast
from aegis_core.ast.runner import ASTDriverRunner
from aegis_core.language_runtime import (
    RuntimeUnavailable, language_runtime_environment, prepare_language_runtime, read_runtime_report,
)
from aegis_core.primitives import strict_loads
from aegis_core.testplans import language_settings, resolve_executable
from aegis_core.verification.language_tests import GoTest, LanguageTestPlan, prepare_language_tests
from aegis_core.verification.test_outcomes import RustTarget, TestId


def test_language(path: str) -> str | None:
    """Recognize supported tests; Rust source candidates need Cargo ownership before selection."""
    path = path.replace("\\", "/")
    file = PurePosixPath(path)
    if path.endswith("_test.go"):
        return "go"
    if file.suffix == ".rs":
        return "rust"
    if file.suffix in (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs") and (
            "__tests__" in file.parts[:-1] or file.stem.endswith((".test", ".spec"))):
        return "ts"
    return None


@dataclass(frozen=True)
class NativeSelection:
    plan: LanguageTestPlan
    owners: tuple[tuple[str, tuple[TestId, ...]], ...] = ()

    def belongs(self, identity: TestId, file: str) -> bool:
        if self.plan.language == "ts":
            return bool(identity and identity[0] == file and file in self.plan.files)
        for source, identities in self.owners:
            if source != file:
                continue
            if self.plan.language == "go":
                return any(len(identity) == 2 and identity[0] == owner[0] and (
                    identity[1] == owner[1] or identity[1].startswith(owner[1] + "/")) for owner in identities)
            return identity in identities
        return False


def _relative(snapshot: Path, path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeUnavailable("test_ids_unmapped", "source is missing or a symbolic link")
    try:
        return path.resolve().relative_to(snapshot).as_posix()
    except ValueError as exc:
        raise RuntimeUnavailable("test_ids_unmapped", "source is outside snapshot") from exc


def _metadata(runtime, tool, arguments, workspace, snapshot, scratch, deadline):
    executable = resolve_executable(tool, workspace)
    if executable is None:
        raise RuntimeUnavailable("deps_unavailable", tool + " metadata tool unavailable")
    scratch.mkdir(parents=True)
    env = language_runtime_environment(runtime, scratch / "environment")
    limit = min(10.0, deadline - time.monotonic()) if deadline is not None else 10.0
    if limit <= 0:
        raise RuntimeUnavailable("timeout", "metadata deadline exceeded")
    output, errors = scratch / "metadata.log", scratch / "metadata-stderr.log"
    result = testexec.run_tests((executable, *arguments), snapshot, env, limit, scratch / "unused.xml", output,
                               stderr_output=errors)
    if result.timed_out:
        raise RuntimeUnavailable("timeout", "metadata command timed out")
    stdout, stderr = read_runtime_report(output), read_runtime_report(errors)
    if result.exit:
        raise RuntimeUnavailable("deps_unavailable", f"metadata command failed; stdout: {stdout[:4096]}; stderr: {stderr[:4096]}")
    return stdout


def _metadata_strings(value):
    return isinstance(value, list) and all(isinstance(item, str) and item and "\0" not in item for item in value)


def _go(workspace, snapshot, files, runtime, scratch, deadline):
    directories = sorted({str(PurePosixPath(file).parent) for file in files})
    raw = _metadata(runtime, "go", ("list", "-e", "-json", "-find", *("./" + d for d in directories)),
                    workspace, snapshot, scratch, deadline)
    rows, decoder, offset = [], json.JSONDecoder(), 0
    while offset < len(raw):
        if not raw[offset:].strip():
            break
        offset += len(raw[offset:]) - len(raw[offset:].lstrip())
        row, end = decoder.raw_decode(raw, offset)
        if (not isinstance(row, dict) or not _metadata_strings([row.get("Dir"), row.get("ImportPath")])
                or not all(_metadata_strings(row.get(key, [])) for key in ("TestGoFiles", "XTestGoFiles"))):
            raise RuntimeUnavailable("test_ids_unmapped", "invalid Go package metadata")
        rows.append(row)
        offset = end
        if len(rows) > 10000:
            raise RuntimeUnavailable("test_ids_unmapped", "too many package metadata records")
    tests, owners = [], []
    with ASTDriverRunner() as runner:
        for file in files:
            directory = (snapshot / file).parent
            packages = [row for row in rows if isinstance(row, dict) and row.get("Dir") == str(directory)]
            if len(packages) != 1 or packages[0].get("Error") or not packages[0].get("ImportPath"):
                raise RuntimeUnavailable("test_ids_unmapped", "Go package metadata missing or ambiguous")
            package = packages[0]["ImportPath"]
            if Path(file).name not in packages[0].get("TestGoFiles", []) + packages[0].get("XTestGoFiles", []):
                raise RuntimeUnavailable("test_ids_unmapped", "Go test excluded from selected package")
            tree = extract_normalized_ast(snapshot / file, workspace_root=workspace, ast_runner=runner,
                                          confine_root=snapshot)
            if tree is None:
                raise RuntimeUnavailable("no_driver", "Go native definitions unavailable")
            names = [d.name for d in tree.definitions if d.kind == "function" and re.fullmatch(r"Test(?:[^a-z].*)?", d.name)]
            tests.extend(GoTest(file, package, name) for name in names)
            owners.append((file, tuple((package, name) for name in names)))
    return tests, (), tuple(owners), tuple(files)


def _module_files(snapshot, entry):
    """Resolve ordinary external modules from parsed declarations, never filename guesses alone."""
    pending, found = [(entry, ())], {}
    while pending:
        file, prefix = pending.pop()
        relative = _relative(snapshot, file)
        if relative in found:
            raise RuntimeUnavailable("test_ids_unmapped", "Rust module has multiple ownership paths")
        if len(found) >= 10000:
            raise RuntimeUnavailable("test_ids_unmapped", "too many Rust module files")
        source = read_runtime_report(file)
        tree = parse_rust(source, "entry.rs")
        found[relative] = (prefix, tree)
        lexed = tokenize(source)
        declarations = {(d.line, d.name) for d in tree.definitions if d.kind == "module"}
        inline = []
        for i, token in enumerate(lexed.tokens[:-2]):
            while inline and i > inline[-1][0]:
                inline.pop()
            name, end = lexed.tokens[i + 1:i + 3]
            if token.value != "mod" or (token.line, name.value) not in declarations:
                continue
            if end.value == "{" and i + 2 in lexed.pairs:
                inline.append((lexed.pairs[i + 2], name.value))
            elif end.value == ";":
                # Attribute-selected module paths are unresolved rather than inferred from a filename.
                if i and lexed.tokens[i - 1].value == "]":
                    raise RuntimeUnavailable("test_ids_unmapped", "attributed external module needs explicit ownership")
                base = file.parent if file == entry or file.name == "mod.rs" else file.with_suffix("")
                base = base.joinpath(*(name for _, name in inline))
                candidates = [p for p in (base / (name.value + ".rs"), base / name.value / "mod.rs") if p.is_file()]
                if len(candidates) != 1:
                    raise RuntimeUnavailable("test_ids_unmapped", "Rust module file missing or ambiguous")
                pending.append((candidates[0], (*prefix, *(name for _, name in inline), name.value)))
    return found


def _rust(workspace, snapshot, files, runtime, scratch, deadline):
    raw = _metadata(runtime, "cargo", ("metadata", "--offline", "--locked", "--no-deps", "--format-version", "1"),
                    workspace, snapshot, scratch, deadline)
    document = strict_loads(raw)
    if (not isinstance(document, dict) or not _metadata_strings(document.get("workspace_members"))
            or not isinstance(document.get("packages"), list)):
        raise RuntimeUnavailable("test_ids_unmapped", "invalid Cargo metadata")
    members = set(document.get("workspace_members", ()))
    candidates, paths = {}, {}
    for package in document.get("packages", ()):
        if not isinstance(package, dict) or not _metadata_strings([package.get("id")]):
            raise RuntimeUnavailable("test_ids_unmapped", "invalid Cargo metadata")
        if package.get("id") not in members:
            continue
        if (not _metadata_strings([package.get("name"), package.get("manifest_path")])
                or not isinstance(package.get("targets"), list)):
            raise RuntimeUnavailable("test_ids_unmapped", "invalid Cargo metadata")
        root = Path(package["manifest_path"]).parent
        for target in package.get("targets", ()):
            if not isinstance(target, dict) or not _metadata_strings(target.get("kind")):
                raise RuntimeUnavailable("test_ids_unmapped", "invalid Cargo metadata")
            if target.get("kind") != ["test"]:
                continue
            if not _metadata_strings([target.get("name"), target.get("src_path")]):
                raise RuntimeUnavailable("test_ids_unmapped", "invalid Cargo metadata")
            entry = Path(target["src_path"])
            source = _relative(snapshot, entry)
            modules = _module_files(snapshot, entry)
            if not set(modules) & set(files):
                continue
            identity = RustTarget(package["name"], "test", target["name"])
            for key in {source, entry.relative_to(root).as_posix()}:
                candidates.setdefault(key, set()).add(identity)
            for file, (prefix, tree) in modules.items():
                if file in files:
                    ids = tuple((identity.package, "test", identity.target_name,
                                 "::".join((*prefix, test["id"]))) for test in tree.metadata.get("test_functions", ()))
                    paths.setdefault(file, []).append(ids)
    owners = []
    for file in files:
        choices = paths.get(file, ())
        if len(choices) > 1:
            raise RuntimeUnavailable("test_ids_unmapped", "Rust helper belongs to several targets")
        if choices:
            owners.append((file, choices[0]))
        elif parse_rust(read_runtime_report(snapshot / file), "entry.rs").metadata.get("test_functions"):
            raise RuntimeUnavailable("tests_inline_with_source", "Rust test is outside an integration target")
    if not owners:
        raise RuntimeUnavailable("no_test_changes", "no integration test files selected")
    if any(len(values) != 1 for values in candidates.values()):
        raise RuntimeUnavailable("test_ids_unmapped", "Cargo source header identifies several targets")
    return (), {key: tuple(value) for key, value in candidates.items()}, tuple(owners), tuple(file for file, _ in owners)


def prepare_native_selection(workspace: Path, snapshot: Path, language: str, files: Sequence[str], *,
                             scratch: Path, deadline: float | None = None) -> NativeSelection:
    """Resolve one immutable plan and ownership table, reused by head/base or receipt execution."""
    workspace, snapshot, scratch = Path(workspace).resolve(), Path(snapshot).resolve(), Path(scratch).resolve()
    plan = LanguageTestPlan(language, workspace=str(workspace))
    try:
        if deadline is not None and deadline <= time.monotonic():
            raise RuntimeUnavailable("timeout", "selection deadline exceeded")
        if scratch.is_relative_to(workspace) or scratch.is_relative_to(snapshot):
            raise RuntimeUnavailable("test_ids_unmapped", "selection scratch must be outside source trees")
        files = tuple(sorted({_relative(snapshot, snapshot / file) for file in files}))
        plan = replace(plan, files=files)
        if language == "go" and not ASTDriverRunner().resolve_driver(".go", workspace_root=workspace):
            raise RuntimeUnavailable("no_driver", "Go native definitions unavailable")
        try:
            settings = language_settings(workspace, language)
        except ValueError as exc:
            raise RuntimeUnavailable("tests_runner_not_configured", str(exc)) from exc
        command = settings.command or (("go",) if language == "go" else ("cargo",))
        if language == "ts" and settings.command is None:
            raise RuntimeUnavailable("tests_runner_not_configured", "TS/JS requires a user-scoped runner")
        runtime = prepare_language_runtime(workspace, language, command, scratch=scratch / "runtime")
        go, rust, owners, selected = ((), (), (), files)
        if language == "go":
            go, rust, owners, selected = _go(workspace, snapshot, files, runtime, scratch / "metadata", deadline)
        elif language == "rust":
            go, rust, owners, selected = _rust(workspace, snapshot, files, runtime, scratch / "metadata", deadline)
        plan = prepare_language_tests(workspace, language, selected, scratch=scratch / "plan", go_tests=go,
                                      rust_targets=rust or None, runtime=runtime)
        return NativeSelection(plan, owners)
    except RuntimeUnavailable as exc:
        known = {"timeout", "deps_unavailable", "no_driver", "test_ids_unmapped", "tests_runner_not_configured",
                 "tests_inline_with_source", "no_test_changes"}
        reason = exc.reason if exc.reason in known else "test_ids_unmapped"
        return NativeSelection(replace(plan, reason=reason, detail=exc.reason + ": " + exc.detail))
    except (OSError, ValueError, KeyError, ASTExtractionError, ASTDriverError) as exc:
        return NativeSelection(replace(plan, reason="test_ids_unmapped", detail=str(exc)))
