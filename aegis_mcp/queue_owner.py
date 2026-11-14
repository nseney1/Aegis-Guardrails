"""Owner-launched queue MCP connection: python -m aegis_mcp.queue_owner ID."""
import sys

from . import queue_role


def main(arguments=None):
    arguments = sys.argv[1:] if arguments is None else arguments
    if type(arguments) is not list or len(arguments) != 1 or not queue_role.identifier(arguments[0]):
        print("aegis-mcp-queue: invalid_arguments", file=sys.stderr)
        return 2
    try:
        queue_role.issue(arguments[0])
    except queue_role.RoleRefusal as exc:
        print("aegis-mcp-queue: " + exc.reason, file=sys.stderr)
        return 1
    from .server import run_stdio_server

    return run_stdio_server(queue_registration=arguments[0])


if __name__ == "__main__":
    sys.exit(main())
