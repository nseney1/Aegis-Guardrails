"""Configured global regression commands: one invocation, with snapshot Python shielding."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import sys
from typing import Sequence

from aegis_core import testexec
from aegis_core.primitives import is_within
from aegis_core.testplans import rebase_snapshot_arguments

_BOOTSTRAP = (
    "import json,os,sys\n"
    "snap,ws,ext,count=sys.argv[1],sys.argv[2],json.loads(sys.argv[3]),int(sys.argv[4])\n"
    "key=lambda p:os.path.normcase(os.path.realpath(p))\n"
    "within=lambda p,d:key(p)==key(d) or key(p).startswith(key(d).rstrip(os.sep)+os.sep)\n"
    "sys.path[:]=[snap]+[p for p in (*sys.path,*ext) if p and (within(p,snap) or not within(p,ws))]\n"
    "import pytest\n"
    "class Selection:\n"
    " def pytest_configure(self,config):\n"
    "  if not count: return\n"
    "  chosen=config.args[:-count]\n"
    "  paths=[word.partition('::')[0] for word in chosen]\n"
    "  covered=lambda file:any(key(file)==key(path) or (os.path.isdir(path) and within(file,path)) for path in paths)\n"
    "  config.args[:]=chosen+[file for file in config.args[-count:] if not covered(file)]\n"
    "raise SystemExit(pytest.main(sys.argv[5:],plugins=[Selection()]))\n"
)


@dataclass(frozen=True)
class CommandOutcome:
    exit_code: int
    timed_out: bool
    passed_ids: frozenset[str] = frozenset()
    failed_ids: frozenset[str] = frozenset()
    collection_errors: frozenset[str] = frozenset()
    reason: str | None = None


def run_configured_snapshot(command: Sequence[str], snapshot: Path, files: Sequence[str], workspace: Path,
                             scratch: Path, timeout: float) -> CommandOutcome:
    """Unknown wrappers execute once but cannot prove fail-to-pass from a success summary."""
    snapshot, workspace, scratch = Path(snapshot).resolve(), Path(workspace).resolve(), Path(scratch).resolve()
    scratch.mkdir(parents=True)
    home, tmp, junit = scratch / "home", scratch / "tmp", scratch / "results.xml"
    home.mkdir()
    tmp.mkdir()
    argv, logical = testexec.plan_command(command, junit)
    argv = rebase_snapshot_arguments(argv, workspace, snapshot)
    arguments = testexec.pytest_args(logical)
    if arguments is not None:
        arguments = rebase_snapshot_arguments(arguments, workspace, snapshot)
        external = [str(Path(path).resolve()) for path in sys.path if path and Path(path).is_dir()
                    and not is_within(path, workspace, unresolvable=True)]
        # Preserve the configured pytest selection and interpreter options, while keeping live editable installs out.
        module = testexec.python_module_index(logical[1:])
        before = rebase_snapshot_arguments(logical[1:1 + module], workspace, snapshot) if module >= 0 else []
        # Let pytest parse positional selections; option values must never be guessed to be paths.
        delimiter = arguments.index("--") if "--" in arguments else len(arguments)
        selections = arguments[delimiter + 1:]
        arguments = arguments[:delimiter]
        argv = [argv[0], "-I", "-S", "-B", *before, "-c", _BOOTSTRAP, str(snapshot), str(workspace), json.dumps(external),
                str(len(files)),
                *arguments, "-p", "no:cacheprovider", "-o", "addopts=", "--continue-on-collection-errors",
                "--rootdir=" + str(snapshot), "--junitxml=" + str(junit), "--", *selections, *files]
    result = testexec.run_tests(argv, snapshot, testexec.hermetic_env(home, tmp), timeout, junit, scratch / "output.log")
    if arguments is None:
        return CommandOutcome(result.exit, result.timed_out, reason="tests_runner_unsupported")
    passed, failed, errors = testexec.parse_junit_cases(junit)
    reason = "incomplete_test_output" if not result.complete and not errors else None
    return CommandOutcome(result.exit, result.timed_out, frozenset(passed), frozenset(failed), frozenset(errors), reason)
