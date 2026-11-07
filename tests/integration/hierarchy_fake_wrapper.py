"""Give Python fakes a host argv[0] while retaining their Python interpreter."""
import os
import shlex
import sys


def python_argv(program, script):
    # exec -a changes CPython's sys.executable too; children must still run Python, not the host wrapper.
    paths = [os.path.dirname(os.path.abspath(str(script))), *sys.path]
    bootstrap = ("import runpy, sys; sys.executable = %r; sys.path = %r; sys.argv = sys.argv[1:]; "
                 "runpy.run_path(sys.argv[0], run_name='__main__')" % (sys.executable, paths))
    return [program, "-c", bootstrap, str(script)]


def shell_exec(program, script):
    return shlex.join(["exec", "-a", program, sys.executable, *python_argv(program, script)[1:]])
