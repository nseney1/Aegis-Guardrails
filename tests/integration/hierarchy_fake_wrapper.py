"""Give Python fakes a host argv[0] while retaining their Python interpreter."""
import os
from pathlib import Path
import shlex
import sys


def python_argv(program, script, directory, entrypoint=None):
    # A real symlink lets relocatable Python find its libraries before the bootstrap can run.
    binary = Path(directory).absolute() / ".python" / program
    binary.parent.mkdir(parents=True, exist_ok=True)
    if not binary.is_symlink():
        binary.symlink_to(sys.executable)
    paths = [os.path.dirname(os.path.abspath(str(script))), *sys.path]
    bootstrap = ("import runpy, sys; sys.executable = %r; sys.path = %r; sys.argv = sys.argv[1:]; "
                 % (sys.executable, paths))
    if entrypoint is None:
        bootstrap += "runpy.run_path(sys.argv[0], run_name='__main__')"
    else:
        bootstrap += "sys.exit(runpy.run_path(sys.argv[0])[%r](sys.argv[1:]))" % entrypoint
    return [str(binary), "-c", bootstrap, str(script)]


def shell_exec(program, script, directory):
    return shlex.join(["exec", *python_argv(program, script, directory)])
