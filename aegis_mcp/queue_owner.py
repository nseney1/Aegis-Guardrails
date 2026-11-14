"""Owner-launched queue MCP connection: python -m aegis_mcp.queue_owner ID."""
import sys

from . import queue_role

_USAGE = queue_role.launch_advice("invalid_arguments")


def _report(code, sentence):
    print("aegis-mcp-queue: " + code + ": " + sentence, file=sys.stderr)


def main(arguments=None):
    arguments = sys.argv[1:] if arguments is None else arguments
    if type(arguments) is not list or len(arguments) != 1 or not queue_role.identifier(arguments[0]):
        _report("invalid_arguments", _USAGE)
        return 2
    try:
        queue_role.issue(arguments[0])
    except queue_role.RoleRefusal as exc:
        _report(exc.reason, queue_role.launch_advice(exc.reason))
        return 1
    except Exception:
        _report("role_io_unavailable", queue_role.launch_advice("role_io_unavailable"))
        return 1
    from .server import run_stdio_server

    return run_stdio_server(queue_registration=arguments[0])


if __name__ == "__main__":
    sys.exit(main())
