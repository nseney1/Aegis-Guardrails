"""Test fake of the `claude` command (hierarchy_fake_claude.py), installed on PATH by tests. Never a real host.

Modelled on what Claude 2.1.316/2.1.319 was seen to do:
- `auth status [--json|--text]`: exit 1 with loggedIn false and authMethod "none" on an empty CLAUDE_CONFIG_DIR,
  creating its .claude.json; exit 0 with authMethod "claude.ai" and fake account keys after a login. The --text
  wording is the fake's own.
- `auth login [--claudeai|--console|--sso|--email E]` writes <CLAUDE_CONFIG_DIR>/.credentials.json, mode 0600. The
  flags are accepted, not told apart.
- Print mode (-p) with the options hierarchy_provision.claude_argv writes: stream-json `system` init, `assistant` and
  one `result` per invocation (usage summed over that invocation), and a transcript at
  <CLAUDE_CONFIG_DIR>/projects/<cwd, each non-alphanumeric as "-">/<session>.jsonl with a user and an assistant record.
Modelled on the docs, never seen here: auth precedence (CLAUDE_CODE_USE_BEDROCK/VERTEX/FOUNDRY give "third_party",
then ANTHROPIC_AUTH_TOKEN and ANTHROPIC_API_KEY give "api_key", then CLAUDE_CODE_OAUTH_TOKEN gives "oauth_token", then
the stored login), and that --output-format stream-json with --print needs --verbose.
Not modelled: a model (the reply is FAKE_CLAUDE_REPLY), permission enforcement (--restricted, --permission-*, allowed
and disallowed tools are parsed, never applied), the real default tool set, background sessions (--bg), interactive
mode, other output formats, a positional prompt, apiKeyHelper or profiles, MCP servers kept alive for the session (each
is asked for its tools once and closed), resume lookup beyond the cwd's own project folder (kept conservative), and a
session variable in MCP children: no real host has shown one there (owner decision B), so children get none.

Knobs: FAKE_CLAUDE_LOG (one JSON line per call), FAKE_CLAUDE_STATUS_DIR (the configDirectory status reports),
FAKE_CLAUDE_LOGIN=fail, FAKE_CLAUDE_EXTRA_TOOLS, FAKE_CLAUDE_SERVED_MODEL, FAKE_CLAUDE_REPLY, FAKE_CLAUDE_USAGE,
FAKE_CLAUDE_MODE ("no-result", "fail" or "hang"), and FAKE_HOST_PLAN, which runs hierarchy_fake_host.py inside the
turn as the Codex fake does.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import uuid

MARK = b"hierarchy_fake_claude.py"
HERE = Path(__file__).resolve()
HOST = HERE.with_name("hierarchy_fake_host.py")
BILLING = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK",
           "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY")
PROVIDERS = (("CLAUDE_CODE_USE_BEDROCK", "bedrock"), ("CLAUDE_CODE_USE_VERTEX", "vertex"),
             ("CLAUDE_CODE_USE_FOUNDRY", "foundry"))
# Obviously fake, so a test can show evidence filters account details out.
ACCOUNT = {"email": "fake@example.invalid", "orgId": "fake-org-id", "orgName": "Fake Org (test fake)",
           "planTier": "fake-plan", "subscriptionType": "fake-subscription", "storedClaudeAiLogin": True}
USAGE_KEYS = ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens", "output_tokens")
DEFAULT_USAGE = {"input_tokens": 3, "cache_creation_input_tokens": 200, "cache_read_input_tokens": 1000,
                 "output_tokens": 40}
FILE_TOOLS = ["Edit", "Glob", "Grep", "Read", "Write"]
MODES = ("", "no-result", "fail", "hang")
VALUES = {"--session-id": "session_id", "--resume": "resume", "-r": "resume", "--mcp-config": "mcp_config",
          "--tools": "tools", "--model": "model", "--effort": "effort", "--permission-mode": "permission_mode",
          "--permission-prompts": "permission_prompts", "--output-format": "output_format", "--settings": "settings",
          "--add-dir": "add_dir", "--agents": "agents", "--name": "name", "-n": "name"}
REPEATED = ("mcp_config", "add_dir")
LISTS = {"--allowedTools": "allowed", "--allowed-tools": "allowed", "--disallowedTools": "disallowed",
         "--disallowed-tools": "disallowed"}
FLAGS = {"--restricted": "restricted", "--strict-mcp-config": "strict_mcp_config", "--verbose": "verbose",
         "--disable-slash-commands": "disable_slash_commands", "-p": "print", "--print": "print"}
PLAIN_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


class Refusal(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


def refuse(code, message):
    raise Refusal(code, message)


def main():
    argv = sys.argv[1:]
    log_call(argv)
    try:
        home = config_dir()
        if argv[:1] == ["auth"]:
            return auth(home, argv[1:])
        return print_mode(home, argv)
    except Refusal as refusal:
        sys.stderr.write(refusal.message + "\n")
        return refusal.code


def log_call(argv):
    if os.environ.get("FAKE_CLAUDE_LOG"):
        with open(os.environ["FAKE_CLAUDE_LOG"], "a", encoding="utf-8") as log:
            log.write(json.dumps({"argv": argv, "cwd": os.getcwd(), "pid": os.getpid(),
                                  "config_dir": os.environ.get("CLAUDE_CONFIG_DIR"),
                                  "billing": sorted(name for name in BILLING if name in os.environ)}) + "\n")


def config_dir():
    value = os.environ.get("CLAUDE_CONFIG_DIR", "")
    # Never fall back to a real ~/.claude, whatever HOME says.
    if not (os.path.isabs(value) and os.path.isdir(value)):
        refuse(2, "fake claude: CLAUDE_CONFIG_DIR must name an existing folder")
    return Path(value)


def auth(home, argv):
    command, options = (argv[0], argv[1:]) if argv else ("(no command)", [])
    if command == "status":
        for word in options:
            if word not in ("--json", "--text"):
                refuse(2, "fake claude: unknown option " + word)
        return status(home, as_text=options[-1:] == ["--text"])
    if command == "login":
        index = 0
        while index < len(options):
            word = options[index]
            if word == "--email":
                if index + 1 >= len(options):
                    refuse(2, "fake claude: --email needs a value")
                index += 1
            elif word not in ("--claudeai", "--console", "--sso"):
                refuse(2, "fake claude: unknown option " + word)
            index += 1
        return login(home)
    refuse(2, "fake claude: auth %s is not modelled" % command)


def auth_method(home):
    """(authMethod, apiProvider), in the documented precedence."""
    for variable, provider in PROVIDERS:
        if os.environ.get(variable):
            return "third_party", provider
    if os.environ.get("ANTHROPIC_AUTH_TOKEN") or os.environ.get("ANTHROPIC_API_KEY"):
        return "api_key", "firstParty"
    if os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"):
        return "oauth_token", "firstParty"
    if (home / ".credentials.json").is_file():
        return "claude.ai", "firstParty"
    return "none", "firstParty"


def status(home, as_text):
    state = home / ".claude.json"
    if not state.exists():
        state.write_text("{}\n", encoding="utf-8")
    method, provider = auth_method(home)
    shown = Path(os.environ.get("FAKE_CLAUDE_STATUS_DIR") or home)
    answer = {"loggedIn": method != "none", "authMethod": method, "apiProvider": provider, "analyticsDisabled": False,
              "projectsDirectory": str(shown / "projects"), "configDirectory": str(shown), "loginExpiresAt": None}
    if method == "claude.ai":
        answer.update(ACCOUNT)
    if as_text:
        print("Logged in: %s\nAuth method: %s\nConfig directory: %s"
              % ("yes" if answer["loggedIn"] else "no", method, answer["configDirectory"]))
    else:
        print(json.dumps(answer, indent=2))
    return 0 if answer["loggedIn"] else 1


def login(home):
    if os.environ.get("FAKE_CLAUDE_LOGIN") == "fail":
        refuse(1, "fake claude: login failed")
    path = home / ".credentials.json"
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump({"fake": "written by hierarchy_fake_claude.py; not a credential"}, stream)
    # O_CREAT's mode only applies to a new file; a login over an older, looser file still ends at 0600.
    os.chmod(str(path), 0o600)
    print("Login successful.")
    return 0


def parse(argv):
    options = {key: None for key in set(VALUES.values()) | {"prompt"}}
    options.update({key: [] for key in REPEATED + tuple(set(LISTS.values()))})
    options.update({key: False for key in FLAGS.values()})
    index = 0
    while index < len(argv):
        word = argv[index]
        if word == "--":
            options["prompt"] = " ".join(argv[index + 1:])
            break
        if word in ("--bg", "--background"):
            refuse(2, "fake claude: background mode is not modelled")
        if word.startswith("--tools="):
            options["tools"] = word[len("--tools="):]
        elif word in FLAGS:
            options[FLAGS[word]] = True
        elif word in VALUES:
            if index + 1 >= len(argv):
                refuse(2, "fake claude: %s needs a value" % word)
            index += 1
            key = VALUES[word]
            if key in REPEATED:
                options[key].append(argv[index])
            else:
                options[key] = argv[index]
        elif word in LISTS:
            # Variadic: it takes every word up to the next option, which is how a trailing prompt was lost on a real
            # host and why claude_argv sends the prompt on stdin.
            index += 1
            while index < len(argv) and not argv[index].startswith("--"):
                options[LISTS[word]].append(argv[index])
                index += 1
            continue
        else:
            refuse(2, "fake claude: unknown option " + word)
        index += 1
    return options


def print_mode(home, argv):
    options = parse(argv)
    if not options["print"]:
        refuse(2, "fake claude: only print mode (-p) and auth are modelled")
    if options["output_format"] != "stream-json":
        refuse(2, "fake claude: only --output-format stream-json is modelled")
    if not options["verbose"]:
        refuse(1, "fake claude: --output-format stream-json with --print needs --verbose")
    cwd = os.getcwd()
    folder = home / "projects" / re.sub(r"[^A-Za-z0-9]", "-", cwd)
    session = session_for(home, folder, options)
    if auth_method(home)[0] == "none":
        refuse(1, "Not logged in · Please run /login")
    mode = os.environ.get("FAKE_CLAUDE_MODE", "")
    if mode not in MODES:
        refuse(2, "fake claude: unknown FAKE_CLAUDE_MODE " + mode)
    usage = usage_from_env()
    prompt = options["prompt"] if options["prompt"] is not None else sys.stdin.read()
    model = os.environ.get("FAKE_CLAUDE_SERVED_MODEL") or options["model"] or "claude-fake-default"
    env = child_env()
    servers, mcp_tools = probe_servers(options["mcp_config"], env)
    emit({"type": "system", "subtype": "init", "cwd": cwd, "session_id": session,
          "tools": offered_tools(options) + mcp_tools, "mcp_servers": servers, "model": model,
          "permissionMode": options["permission_mode"] or "default", "apiKeySource": "none",
          "claude_code_version": "0.0.0-fake"})
    transcript = folder / (session + ".jsonl")
    record(transcript, {"type": "user", "message": {"role": "user", "content": prompt}, "sessionId": session,
                        "timestamp": now(), "cwd": cwd, "uuid": str(uuid.uuid4())})
    if mode == "hang":
        while True:
            time.sleep(3600)
    if mode == "fail":
        emit({"type": "result", "subtype": "error_during_execution", "is_error": True, "num_turns": 1,
              "session_id": session, "total_cost_usd": 0.0, "usage": usage})
        return 1
    code = 0
    if os.environ.get("FAKE_HOST_PLAN") and any(server["name"] == "aegis_mailbox" for server in servers):
        # The fake host finds the mailbox in --mcp-config and drives the real adapter, as the Codex fake's turn does.
        # Its stdout goes to stderr so the stream stays JSON lines.
        code = subprocess.run([sys.executable, str(HOST), *argv], input=prompt, text=True, env=env,
                              stdout=sys.stderr).returncode
    message = {"model": model, "id": "msg_fake_" + uuid.uuid4().hex[:24], "type": "message", "role": "assistant",
               "content": [{"type": "text", "text": os.environ.get("FAKE_CLAUDE_REPLY") or "done"}], "usage": usage}
    emit({"type": "assistant", "message": message, "session_id": session})
    record(transcript, {"type": "assistant", "message": message, "sessionId": session, "timestamp": now(),
                        "cwd": cwd, "uuid": str(uuid.uuid4())})
    if mode != "no-result":
        emit({"type": "result", "subtype": "success", "is_error": False, "num_turns": 1, "session_id": session,
              "total_cost_usd": 0.0, "usage": usage})
    return code


def session_for(home, folder, options):
    new, old = options["session_id"], options["resume"]
    if (new is None) == (old is None):
        refuse(1, "fake claude: give exactly one of --session-id or --resume")
    if new is not None:
        try:
            canonical = str(uuid.UUID(new)) == new
        except ValueError:
            canonical = False
        if not canonical:
            refuse(1, "fake claude: --session-id must be a canonical UUID: " + new)
        if list((home / "projects").glob("*/" + new + ".jsonl")):
            refuse(1, "fake claude: session %s is already in use" % new)
        return new
    # Only the cwd's own folder: whatever wider lookup a real host does, no team path may rely on it.
    if PLAIN_NAME.fullmatch(old) is None or not (folder / (old + ".jsonl")).is_file():
        refuse(1, "fake claude: no conversation found for session %s in %s" % (old, folder))
    return old


def usage_from_env():
    text = os.environ.get("FAKE_CLAUDE_USAGE")
    if not text:
        return dict(DEFAULT_USAGE)
    try:
        usage = json.loads(text)
    except ValueError:
        usage = None
    if not (isinstance(usage, dict) and sorted(usage) == sorted(USAGE_KEYS)
            and all(type(usage[key]) is int for key in USAGE_KEYS)):
        refuse(2, "fake claude: FAKE_CLAUDE_USAGE must be a JSON object with exactly " + ", ".join(USAGE_KEYS))
    return usage


def child_env():
    # No real host has shown a session variable in an MCP child (owner decision B; spec rule 3 waits for T2(b)), and a
    # test run inside Claude Code must not hand its own session to the fake's children.
    return {key: value for key, value in os.environ.items() if key not in ("CLAUDE_CODE_SESSION_ID", "CLAUDECODE")}


def offered_tools(options):
    if options["tools"] is None:
        tools = list(FILE_TOOLS) if options["restricted"] else ["Bash"] + FILE_TOOLS
    else:
        tools = [name.strip() for name in options["tools"].split(",") if name.strip()]
    # A host may offer more than it was asked for; the start check must catch that.
    return tools + [name for name in os.environ.get("FAKE_CLAUDE_EXTRA_TOOLS", "").split(",") if name]


def probe_servers(paths, env):
    servers, tools = [], []
    for path in paths:
        try:
            definitions = json.loads(Path(path).read_text(encoding="utf-8"))["mcpServers"]
            names = list(definitions)
        except (OSError, ValueError, KeyError, TypeError):
            refuse(1, "fake claude: cannot read --mcp-config " + path)
        for name in names:
            listed = list_tools(definitions[name], env)
            servers.append({"name": name, "status": "failed" if listed is None else "connected"})
            tools += ["mcp__%s__%s" % (name, tool) for tool in listed or []]
    return servers, tools


def list_tools(definition, env):
    """The server's tool names from initialize and tools/list over stdio JSON lines, or None if it fails."""
    frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                          "clientInfo": {"name": "hierarchy_fake_claude", "version": "0.0.0-fake"}}},
              {"jsonrpc": "2.0", "method": "notifications/initialized"},
              {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}]
    try:
        done = subprocess.run([definition["command"], *definition.get("args", [])], env=env, capture_output=True,
                              input="".join(json.dumps(frame) + "\n" for frame in frames), text=True, timeout=20)
        answers = {}
        for line in done.stdout.splitlines():
            if line.strip():
                answer = json.loads(line)
                answers[answer.get("id")] = answer
        if done.returncode != 0 or "result" not in answers.get(1, {}):
            return None
        return [tool["name"] for tool in answers[2]["result"]["tools"]]
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.TimeoutExpired):
        return None


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def record(path, row):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(row) + "\n")


def emit(event):
    print(json.dumps(event), flush=True)


def install(bin_dir):
    """Write an executable `claude` into bin_dir that runs this file, and return its path."""
    path = Path(bin_dir) / "claude"
    path.write_text("#!/bin/sh\nexec %s %s \"$@\"\n" % (shlex.quote(sys.executable), shlex.quote(str(HERE))),
                    encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def require_fake(path):
    """The `claude` this PATH resolves to, if it is the test fake; otherwise fail, so no test reaches a real one."""
    found = shutil.which("claude", path=path)
    if found is not None:
        if Path(found).resolve() == HERE:
            return found
        with open(found, "rb") as stream:
            if MARK in stream.read(65536):
                return found
    raise AssertionError("claude on PATH is not the test fake: %s" % found)


if __name__ == "__main__":
    sys.exit(main())
