"""The program AC24's acceptance audit hook records for a spawned process.

CPython audits ``subprocess.Popen`` with ``executable`` exactly as passed: on POSIX
it is ``args[0]``, but on Windows it is usually ``None`` and ``args`` is already the
``list2cmdline`` command line, so the worker must recover the program from it.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / ".github/fixtures/ac24/acceptance.py"


@pytest.fixture(scope="module")
def probe():
    spec = importlib.util.spec_from_file_location("ac24_acceptance", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_posix_event_keeps_the_audited_executable(probe):
    assert probe.audited_program("/usr/bin/node", ["/usr/bin/node", "x"]) == "/usr/bin/node"


def test_windows_quoted_program_is_read_from_the_command_line(probe):
    line = '"C:\\Program Files\\nodejs\\node.exe" D:\\a\\vitest.mjs run'
    assert probe.audited_program(None, line) == "C:\\Program Files\\nodejs\\node.exe"


def test_windows_unquoted_program_ends_at_the_first_space(probe):
    line = "C:\\Git\\git.exe -c core.hooksPath=nul status"
    assert probe.audited_program(None, line) == "C:\\Git\\git.exe"


def test_list_without_executable_uses_the_first_argument(probe):
    assert probe.audited_program(None, ["node", "a"]) == "node"


def test_explicit_executable_wins_over_the_command_line(probe):
    assert probe.audited_program("C:\\x\\node.exe", '"C:\\y\\node.exe" a') == "C:\\x\\node.exe"


@pytest.mark.parametrize("argv", [
    ["C:\\Program Files\\nodejs\\node.exe", "D:\\a\\vitest.mjs", "run"],
    ["C:\\Git\\git.exe", "-c", "core.hooksPath=nul", "status"],
    ["C:\\odd\tdir\\node.exe", "a b"],
    ["node", 'say "hi"', ""],
    ["/usr/bin/node", "x"],
])
def test_program_survives_the_windows_command_line_round_trip(probe, argv):
    assert probe.audited_program(None, subprocess.list2cmdline(argv)) == argv[0]


def test_bytes_and_path_command_lines_are_decoded(probe):
    assert probe.audited_program(None, b'"C:\\Program Files\\x.exe" a') == "C:\\Program Files\\x.exe"
    assert probe.audited_program(None, Path("node")) == "node"


@pytest.mark.parametrize("args", ["", []])
def test_empty_args_name_no_program(probe, args):
    assert probe.audited_program(None, args) is None


def test_real_popen_audit_event_names_the_spawned_program():
    # Audit hooks cannot be removed, so the real event is observed in a child
    # interpreter that only spawns another interpreter (never node, git or the worker).
    child = (
        "import importlib.util, json, subprocess, sys\n"
        "spec = importlib.util.spec_from_file_location('ac24_acceptance', sys.argv[1])\n"
        "probe = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(probe)\n"
        "seen = []\n"
        "def hook(event, args):\n"
        "    if event == 'subprocess.Popen':\n"
        "        seen.append(probe.audited_program(args[0], args[1]))\n"
        "sys.addaudithook(hook)\n"
        "subprocess.run([sys.executable, '-I', '-S', '-B', '-c', 'pass'], stdin=subprocess.DEVNULL,\n"
        "               timeout=60, check=True)\n"
        "print(json.dumps({'seen': seen, 'expected': sys.executable}))\n"
    )
    done = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", child, str(SCRIPT)],
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=120, check=False)
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
    report = json.loads(done.stdout.decode("utf-8"))
    assert report["seen"] == [report["expected"]]
