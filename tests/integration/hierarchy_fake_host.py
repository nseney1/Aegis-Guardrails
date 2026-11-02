"""A stand-in for the claude and codex commands, installed on PATH by tests.

It finds its mailbox connection the way a host does, from --mcp-config or Codex's mcp_servers
setting, then talks to the real adapter. A plan file says what each endpoint does in its turn.
It proves the tools and adapter work together, not that a real host behaves this way.

A plan entry's `send` list publishes messages. Its `calls` list runs any tool once, with `name`
to find the result later, `brief_from` to attach an earlier result as a hash-bound brief the way a
read-only role must, and `when_inbox` to wait for a message of a given type and receipt state.
"""
import json
import os
import subprocess
import sys


def server_definitions(argv):
    if "--mcp-config" in argv:
        return json.load(open(argv[argv.index("--mcp-config") + 1], encoding="utf-8"))["mcpServers"]
    for index, word in enumerate(argv):
        if word == "-c" and argv[index + 1].startswith("mcp_servers="):
            import tomllib  # Python 3.11+, and only Codex connections need it.
            return tomllib.loads(argv[index + 1])["mcp_servers"]
    raise SystemExit("no mailbox connection on the command line")


def main():
    argv = sys.argv[1:]
    definitions = server_definitions(argv)
    definition = definitions["aegis_mailbox"]
    arguments = definition["args"]
    endpoint = arguments[arguments.index("--endpoint") + 1]
    stdin_prompt = sys.stdin.read()
    with open(os.environ["FAKE_HOST_LOG"], "a", encoding="utf-8") as log:
        log.write(json.dumps({"endpoint": endpoint, "program": os.path.basename(sys.argv[0]), "cwd": os.getcwd(), "argv": argv,
                              "stdin": stdin_prompt}) + "\n")
    plan = json.load(open(os.environ["FAKE_HOST_PLAN"], encoding="utf-8")).get(endpoint, {})
    if plan.get("exit") is not None:
        sys.exit(plan["exit"])
    if plan.get("ignore"):
        return
    adapter = subprocess.Popen([definition["command"], *arguments], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    servers = {"aegis_mailbox": adapter}

    def server_for(name):
        key = "aegis_board" if name.startswith("board_") else "aegis_mailbox"
        if key not in servers:
            servers[key] = subprocess.Popen([definitions[key]["command"], *definitions[key]["args"]], stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE, text=True)
        return servers[key]

    def call(server, identifier, method, params=None):
        server.stdin.write(json.dumps({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params or {}}) + "\n")
        server.stdin.flush()
        return json.loads(server.stdout.readline())

    def tool(identifier, name, tool_arguments):
        response = call(server_for(name), identifier, "tools/call", {"name": name, "arguments": tool_arguments})
        return json.loads(response["result"]["content"][0]["text"])

    call(adapter, 1, "initialize")
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
    results_path = os.environ["FAKE_HOST_LOG"] + "." + endpoint.replace("/", "%2F") + ".results"
    results = json.load(open(results_path, encoding="utf-8")) if os.path.exists(results_path) else {}
    for item in plan.get("calls", []):
        if item["name"] in results:
            continue
        wanted = item.get("when_inbox")
        if wanted and not any(row["message"]["type"] == wanted["type"]
                              and row["message"].get("receipt", {}).get("state") == wanted.get("state")
                              for row in inbox["messages"]):
            continue
        arguments = dict(item["arguments"])
        if "brief_from" in item:
            arguments["brief"] = {key: results[item["brief_from"]][key] for key in ("path", "sha256")}
        number += 1
        results[item["name"]] = tool(number, item["tool"], arguments)
        with open(results_path, "w", encoding="utf-8") as stream:
            json.dump(results, stream)
    for server in servers.values():
        server.stdin.close()
        server.wait(timeout=10)
        server.stdout.close()


if __name__ == "__main__":
    main()
