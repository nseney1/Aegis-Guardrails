"""Test fake of the `claude` command (hierarchy_fake_claude.py), installed on PATH by tests. Never a real host.

Observed on Claude 2.1.316/2.1.319, and modelled as seen:
- `auth status --json` on an empty CLAUDE_CONFIG_DIR: exit 1, loggedIn false, authMethod "none", and it creates
  .claude.json. After a claude.ai login: exit 0, authMethod "claude.ai" and account keys (fake values here).
- After a claude.ai login, <CLAUDE_CONFIG_DIR>/.credentials.json exists with mode 0600 (2.1.319 on the owner's
  machine; only existence and mode were checked, so the fake writes a marker, not real contents).
- The shapes of print mode's stream-json `system` init, `assistant` and `result` events, one result per invocation
  with usage summed over it, and the transcript at <CLAUDE_CONFIG_DIR>/projects/<cwd, each non-alphanumeric as
  "-">/<session>.jsonl.
Modelled, not observed:
- From the docs: auth precedence (CLAUDE_CODE_USE_BEDROCK/VERTEX/FOUNDRY give "third_party", then
  ANTHROPIC_AUTH_TOKEN and ANTHROPIC_API_KEY give "api_key", then CLAUDE_CODE_OAUTH_TOKEN gives "oauth_token", then the
  stored login), and that --output-format stream-json with --print needs --verbose.
- The fake's own choices: a reused --session-id is refused, and it must be a canonical UUID; --resume keeps the same
  id and appends to the same transcript; init's `cwd` is the process cwd; MCP servers are "connected" or "failed"; a
  failed turn's result is `error_during_execution` with `is_error`, and a failed fake-host turn ends the same way,
  with no reply, so its prompt stays unanswered in the transcript; a print turn without a login exits 1 with a
  "fake claude:" line; MCP children and the fake host get the caller's environment minus the outer session's
  variables (below); the --text status wording; login flags are accepted, not told apart.
Not modelled: a model (the reply is FAKE_CLAUDE_REPLY), permission enforcement (--restricted, --permission-*, allowed
and disallowed tools are parsed, never applied), the real default tool set, background sessions (--bg) and session
names (--name), interactive mode, other output formats, a positional or empty prompt, apiKeyHelper or profiles, MCP
servers kept alive for the session (each is asked for its tools once and closed), resume lookup beyond the cwd's own
project folder (kept conservative), and a session variable in MCP children: no real host has shown one there (owner
decision B). So every child the fake starts loses CLAUDECODE and every CLAUDE_* variable but CLAUDE_CONFIG_DIR.

Guards, not modelled behaviour: every command refuses a CLAUDE_CONFIG_DIR that is missing, relative, or the real
user's ~/.claude or inside it, and no write follows a symlink at or below it. Print mode refuses an argv without
--restricted, --strict-mcp-config, --permission-mode, or --permission-prompts none, which claude_argv always writes;
these are checked, never enforced. Each MCP probe and the fake host run in their own process group, killed when they
end, time out, or the fake gets SIGTERM.
Knobs: FAKE_CLAUDE_LOG (one JSON line per call), FAKE_CLAUDE_STATUS_DIR (the configDirectory status reports),
FAKE_CLAUDE_LOGIN=fail, FAKE_CLAUDE_EXTRA_TOOLS, FAKE_CLAUDE_SERVED_MODEL, FAKE_CLAUDE_REPLY, FAKE_CLAUDE_USAGE,
FAKE_CLAUDE_MCP_TIMEOUT (seconds per MCP probe, default 20), FAKE_CLAUDE_MODE ("no-result": a turn whose result event
never arrived, exit 0; "fail"; "hang"), and FAKE_HOST_PLAN, which runs hierarchy_fake_host.py inside the turn as the
Codex fake does, for at most FAKE_CLAUDE_TURN_TIMEOUT seconds (default 60).
"""
from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
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
          "--add-dir": "add_dir", "--agents": "agents"}
REPEATED = ("mcp_config", "add_dir")
LISTS = {"--allowedTools": "allowed", "--allowed-tools": "allowed", "--disallowedTools": "disallowed",
         "--disallowed-tools": "disallowed"}
FLAGS = {"--restricted": "restricted", "--strict-mcp-config": "strict_mcp_config", "--verbose": "verbose",
         "--disable-slash-commands": "disable_slash_commands", "-p": "print", "--print": "print"}
PLAIN_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
SYMLINK = "fake claude: refusing to write through a symlink: %s"
# What claude_argv always writes for a team print turn, as (flag, option key).
CONTRACT = (("--restricted", "restricted"), ("--strict-mcp-config", "strict_mcp_config"),
            ("--permission-mode", "permission_mode"), ("--permission-prompts", "permission_prompts"))
# Process groups of the children running now, for the SIGTERM handler.
GROUPS = set()


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
    real, resolved = real_claude_dir(), Path(value).resolve()
    if resolved == real or real in resolved.parents:
        refuse(2, "fake claude: CLAUDE_CONFIG_DIR is the real ~/.claude")
    return Path(value)


def real_claude_dir():
    """The account's own ~/.claude, from the password database: a test sets HOME, which must not hide it."""
    import pwd  # POSIX only; the test module imports this file on every platform
    try:
        home = pwd.getpwuid(os.getuid()).pw_dir
    except KeyError:
        refuse(2, "fake claude: cannot find the real home folder, so ~/.claude cannot be kept out")
    return (Path(home) / ".claude").resolve()


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
    try:
        write_closing(open_inside(home, [".claude.json"], os.O_WRONLY | os.O_CREAT | os.O_EXCL), "{}\n")
    except FileExistsError:
        if (home / ".claude.json").is_symlink():
            refuse(2, SYMLINK % (home / ".claude.json"))
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
    descriptor = open_inside(home, [".credentials.json"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    # O_CREAT's mode only applies to a new file; a login over an older, looser file still ends at 0600.
    os.fchmod(descriptor, 0o600)
    write_closing(descriptor, json.dumps({"fake": "written by hierarchy_fake_claude.py; not a credential"}))
    print("Login successful.")
    return 0


def open_inside(home, names, flags):
    """A descriptor for home/names..., making missing folders and following no symlink at or below home.

    A symlink planted in a test's config dir must never carry a write to a real file, such as the owner's credentials.
    """
    path = home
    folder = os.open(str(home), os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, name in enumerate(names):
            if name in ("", ".", "..") or "/" in name or "\0" in name:
                refuse(2, "fake claude: refusing to write outside the config dir: %s" % (path / name))
            path = path / name
            try:
                if index == len(names) - 1:
                    return os.open(name, flags | os.O_NOFOLLOW, 0o600, dir_fd=folder)
                try:
                    os.mkdir(name, 0o700, dir_fd=folder)
                except FileExistsError:
                    pass
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=folder)
            except OSError as exc:
                # The open has already refused; lstat only picks the message (O_DIRECTORY on a link gives ENOTDIR).
                if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EISDIR):
                    refuse(2, SYMLINK % path if os.path.islink(str(path))
                           else "fake claude: refusing to write: %s is not a plain file or folder" % path)
                raise
            os.close(folder)
            folder = child
    finally:
        os.close(folder)


def write_closing(descriptor, text):
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(text)


def append(descriptor, row):
    os.write(descriptor, (json.dumps(row) + "\n").encode("utf-8"))


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
        if word in ("--name", "-n"):
            # claude_argv names only background sessions.
            refuse(2, "fake claude: %s is not modelled" % word)
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
            while index < len(argv) and not argv[index].startswith("-"):
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
    # Contract drift must fail loudly; these are checked here, never enforced.
    for flag, key in CONTRACT:
        if options[key] in (None, False):
            refuse(2, "fake claude: team argv is missing " + flag)
    if options["permission_prompts"] != "none":
        refuse(2, "fake claude: team argv --permission-prompts must be none")
    signal.signal(signal.SIGTERM, stop_children)
    cwd = os.getcwd()
    slug = re.sub(r"[^A-Za-z0-9]", "-", cwd)
    session = session_for(home, home / "projects" / slug, options)
    if auth_method(home)[0] == "none":
        refuse(1, "fake claude: not logged in")
    mode = os.environ.get("FAKE_CLAUDE_MODE", "")
    if mode not in MODES:
        refuse(2, "fake claude: unknown FAKE_CLAUDE_MODE " + mode)
    usage = usage_from_env()
    probe_timeout, turn_timeout = seconds("FAKE_CLAUDE_MCP_TIMEOUT", 20.0), seconds("FAKE_CLAUDE_TURN_TIMEOUT", 60.0)
    prompt = options["prompt"] if options["prompt"] is not None else sys.stdin.read()
    if not prompt.strip():
        refuse(2, "fake claude: empty prompt")
    model = os.environ.get("FAKE_CLAUDE_SERVED_MODEL") or options["model"] or "claude-fake-default"
    env = child_env()
    servers, mcp_tools = probe_servers(options["mcp_config"], env, probe_timeout)
    transcript = open_inside(home, ["projects", slug, session + ".jsonl"], os.O_WRONLY | os.O_CREAT | os.O_APPEND)
    try:
        emit({"type": "system", "subtype": "init", "cwd": cwd, "session_id": session,
              "tools": offered_tools(options) + mcp_tools, "mcp_servers": servers, "model": model,
              "permissionMode": options["permission_mode"], "apiKeySource": "none",
              "claude_code_version": "0.0.0-fake"})
        append(transcript, {"type": "user", "message": {"role": "user", "content": prompt}, "sessionId": session,
                            "timestamp": now(), "cwd": cwd, "uuid": str(uuid.uuid4())})
        if mode == "hang":
            while True:
                time.sleep(3600)
        if mode == "fail":
            emit(result(session, usage, error=True))
            return 1
        if os.environ.get("FAKE_HOST_PLAN") and any(server["name"] == "aegis_mailbox" for server in servers):
            code = run_host(argv, prompt, env, turn_timeout)
            if code != 0:
                # Ends like FAKE_CLAUDE_MODE=fail: no reply is recorded, so the meter keeps the prompt as unknown.
                if mode != "no-result":
                    emit(result(session, usage, error=True))
                return code
        message = {"model": model, "id": "msg_fake_" + uuid.uuid4().hex[:24], "type": "message", "role": "assistant",
                   "content": [{"type": "text", "text": os.environ.get("FAKE_CLAUDE_REPLY") or "done"}],
                   "usage": usage}
        emit({"type": "assistant", "message": message, "session_id": session})
        append(transcript, {"type": "assistant", "message": message, "sessionId": session, "timestamp": now(),
                            "cwd": cwd, "uuid": str(uuid.uuid4())})
        if mode != "no-result":
            emit(result(session, usage))
        return 0
    finally:
        os.close(transcript)


def result(session, usage, error=False):
    return {"type": "result", "subtype": "error_during_execution" if error else "success", "is_error": error,
            "num_turns": 1, "session_id": session, "total_cost_usd": 0.0, "usage": usage}


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


def run_host(argv, prompt, env, timeout):
    """The fake host finds the mailbox in --mcp-config and drives the real adapter, as the Codex fake's turn does."""
    # Its own group, so a timeout stops the host and the adapters it started together. Its stdout goes to stderr so
    # the stream stays JSON lines.
    host = subprocess.Popen([sys.executable, str(HOST), *argv], stdin=subprocess.PIPE, stdout=sys.stderr, text=True,
                            env=env, start_new_session=True)
    GROUPS.add(host.pid)
    try:
        host.communicate(prompt, timeout=timeout)
    except subprocess.TimeoutExpired:
        refuse(1, "fake claude: turn timed out")
    finally:
        stop_group(host)
    return host.returncode


def stop_group(process):
    """Kill the child's whole process group, then reap the child within a bound."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    GROUPS.discard(process.pid)


def stop_children(number, frame):
    # The wake stops a turn with SIGTERM to the fake's group, which the probes and the fake host have left: pass the
    # stop on, then die of the same signal. No wait here, since an interrupted communicate may hold the wait lock.
    for group in list(GROUPS):
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass
    signal.signal(number, signal.SIG_DFL)
    os.kill(os.getpid(), number)


def seconds(name, default):
    text = os.environ.get(name)
    if not text:
        return default
    try:
        value = float(text)
    except ValueError:
        value = 0.0
    if not 0 < value < float("inf"):  # NaN fails both comparisons
        refuse(2, "fake claude: %s must be a positive number of seconds" % name)
    return value


def child_env():
    # No real host has shown a session variable in an MCP child (owner decision B; spec rule 3 waits for T2(b)), and a
    # test run inside Claude Code must not hand its outer session's variables to the fake's children. Every CLAUDE_*
    # name goes, so a variable a later host adds cannot leak either; only the config dir is the fake's to pass on.
    return {key: value for key, value in os.environ.items()
            if key == "CLAUDE_CONFIG_DIR" or not (key == "CLAUDECODE" or key.startswith("CLAUDE_"))}


def offered_tools(options):
    if options["tools"] is None:
        tools = list(FILE_TOOLS)  # --restricted is part of the contract, so never Bash
    else:
        tools = [name.strip() for name in options["tools"].split(",") if name.strip()]
    # A host may offer more than it was asked for; the start check must catch that.
    return tools + [name for name in os.environ.get("FAKE_CLAUDE_EXTRA_TOOLS", "").split(",") if name]


def probe_servers(paths, env, timeout):
    servers, tools = [], []
    for path in paths:
        try:
            definitions = json.loads(Path(path).read_text(encoding="utf-8"))["mcpServers"]
            names = list(definitions)
        except (OSError, ValueError, KeyError, TypeError):
            refuse(1, "fake claude: cannot read --mcp-config " + path)
        for name in names:
            listed = list_tools(definitions[name], env, timeout)
            servers.append({"name": name, "status": "failed" if listed is None else "connected"})
            tools += ["mcp__%s__%s" % (name, tool) for tool in listed or []]
    return servers, tools


def list_tools(definition, env, timeout):
    """The server's tool names from initialize and tools/list over stdio JSON lines, or None if it fails."""
    frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                          "clientInfo": {"name": "hierarchy_fake_claude", "version": "0.0.0-fake"}}},
              {"jsonrpc": "2.0", "method": "notifications/initialized"},
              {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}]
    try:
        server = subprocess.Popen([definition["command"], *definition.get("args", [])], env=env, text=True,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  start_new_session=True)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    GROUPS.add(server.pid)
    try:
        stdout, _ = server.communicate("".join(json.dumps(frame) + "\n" for frame in frames), timeout=timeout)
    except subprocess.TimeoutExpired:
        return None
    finally:
        # Its own group: run(timeout=...) would kill only the server and then wait on any child holding its output.
        # A server that answered may have left children too.
        stop_group(server)
    try:
        answers = {}
        for line in stdout.splitlines():
            if line.strip():
                answer = json.loads(line)
                answers[answer.get("id")] = answer
        if server.returncode != 0 or "result" not in answers.get(1, {}):
            return None
        return [tool["name"] for tool in answers[2]["result"]["tools"]]
    except (ValueError, KeyError, TypeError, AttributeError):
        return None


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


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
