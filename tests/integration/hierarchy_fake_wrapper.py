"""Give Python fakes a host argv[0] while retaining their Python interpreter."""
import os
from pathlib import Path
import shlex
import sys
import sysconfig
import uuid


def python_argv(program, script, directory, entrypoint=None):
    # A real symlink lets relocatable Python find its libraries before the bootstrap can run.
    binary = Path(directory).absolute() / ".python" / program
    binary.parent.mkdir(parents=True, exist_ok=True)
    temporary = binary.with_name("%s-%s.tmp" % (program, uuid.uuid4().hex))
    try:
        temporary.symlink_to(sys.executable)
        os.replace(temporary, binary)
    finally:
        temporary.unlink(missing_ok=True)
    # Add only the trusted wrapper folder to Python's library paths, never a role's working directory.
    configuration = sysconfig.get_paths(vars={"base": sys.prefix, "platbase": sys.exec_prefix,
                                             "installed_base": sys.base_prefix,
                                             "installed_platbase": sys.base_exec_prefix})
    roots = {Path(configuration[key]).resolve() for key in ("stdlib", "platstdlib", "purelib", "platlib")}
    dynamic = sysconfig.get_config_var("DESTSHARED")
    if dynamic:
        roots.add(Path(dynamic).resolve())
    archive = "python%d%d.zip" % sys.version_info[:2]
    roots.add((Path(configuration["stdlib"]).parent / archive).resolve())
    roots.add((Path(sys.base_prefix) / archive).resolve())
    libraries = [path for path in sys.path if path and Path(path).is_absolute() and Path(path).resolve() in roots]
    paths = [os.path.dirname(os.path.abspath(str(script))), *libraries]
    bootstrap = ("import sys; sys.executable = %r; sys.prefix = %r; sys.exec_prefix = %r; sys.path[:] = %r; "
                 "import runpy; sys.argv = [%r, *sys.argv[1:]]; " %
                 (sys.executable, sys.prefix, sys.exec_prefix, paths, str(script)))
    if entrypoint is None:
        bootstrap += "runpy.run_path(sys.argv[0], run_name='__main__')"
    else:
        bootstrap += "sys.exit(runpy.run_path(sys.argv[0])[%r](sys.argv[1:]))" % entrypoint
    return [str(binary), "-I", "-B", "-c", bootstrap]


def shell_exec(program, script, directory):
    return shlex.join(["exec", *python_argv(program, script, directory)])
