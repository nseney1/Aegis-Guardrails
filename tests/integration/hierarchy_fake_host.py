"""A stand-in for the claude and codex commands, installed on PATH by tests.

It finds its mailbox connection the way a host does, from --mcp-config or Codex's mcp_servers
setting, then talks to the real adapter. A plan file says what each endpoint does in its turn.
It proves the tools and adapter work together, not that a real host behaves this way.
"""
import json
import os
import subprocess
import sys


def server_definition(argv):
    if "--mcp-config" in argv:
        return json.load(open(argv[argv.index("--mcp-config") + 1], encoding="utf-8"))["mcpServers"]["aegis_mailbox"]
    for index, word in enumerate(argv):
        if word == "-c" and argv[index + 1].startswith("mcp_servers="):
            import tomllib  # Python 3.11+, and only Codex connections need it.
            return tomllib.loads(argv[index + 1])["mcp_servers"]["aegis_mailbox"]
    raise SystemExit("no mailbox connection on the command line")


def main():
    argv = sys.argv[1:]
    definition = server_definition(argv)
    arguments = definition["args"]
    endpoint = arguments[arguments.index("--endpoint") + 1]
    stdin_prompt = sys.stdin.read()
    with open(os.environ["FAKE_HOST_LOG"], "a", encoding="utf-8") as log:
        log.write(json.dumps({"endpoint": endpoint, "argv": argv, "stdin": stdin_prompt}) + "\n")
    plan = json.load(open(os.environ["FAKE_HOST_PLAN"], encoding="utf-8")).get(endpoint, {})
    if plan.get("exit") is not None:
        sys.exit(plan["exit"])
    if plan.get("ignore"):
        return
    adapter = subprocess.Popen([definition["command"], *arguments], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def call(identifier, method, params=None):
        adapter.stdin.write(json.dumps({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params or {}}) + "\n")
        adapter.stdin.flush()
        return json.loads(adapter.stdout.readline())

    def tool(identifier, name, tool_arguments):
        return json.loads(call(identifier, "tools/call", {"name": name, "arguments": tool_arguments})["result"]["content"][0]["text"])

    call(1, "initialize")
    inbox = tool(2, "mailbox_inbox", {"limit": 100})
    binding = inbox.get("binding") or {}
    if binding.get("ready") is False:
        tool(3, "mailbox_ack_handoff", {"checkpoint_sha256": binding["checkpoint_sha256"]})
    seen_path = os.environ["FAKE_HOST_LOG"] + "." + endpoint.replace("/", "%2F") + ".replied"
    replied = open(seen_path, encoding="utf-8").read().split() if os.path.exists(seen_path) else []
    number = 10
    for send in plan.get("send", []):
        if send["message_id"] in replied:
            continue
        number += 1
        result = tool(number, "mailbox_publish", send)
        with open(seen_path, "a", encoding="utf-8") as stream:
            stream.write(send["message_id"] + "\n")
        with open(os.environ["FAKE_HOST_LOG"] + ".published", "a", encoding="utf-8") as stream:
            stream.write(json.dumps({"endpoint": endpoint, "result": result}) + "\n")
    adapter.stdin.close()
    adapter.wait(timeout=10)
    adapter.stdout.close()


if __name__ == "__main__":
    main()
