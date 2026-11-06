"""A stand-in for the codex command, installed on PATH by the launcher and probe tests.

A start (no "resume" word) prints the JSON events a real `codex exec --json` start begins with. FAKE_CODEX_MODE
picks a failure: "no-thread" exits 1 without events, "hang" prints thread.started and then waits to be stopped,
"silent-hang" waits without events, "fail-after-thread" exits 4. "leave-child" leaves a sleep in its process
group and "escape" leaves one in a new session holding stdout; both write the sleep's pid to FAKE_CODEX_CHILD.
FAKE_CODEX_TOUCH names a file created just before a clean exit. A resume runs the fake host, so the real
adapter reads the mailbox.

FAKE_CODEX_ROLLOUT=1 adds the records a probe reads. A start writes
$CODEX_HOME/sessions/YYYY/MM/DD/rollout-<ts>-<thread>.jsonl and a resume appends a turn to it. Each turn
records the settings its own argv asked for, then "runs" the commands of the first FAKE_CODEX_SCRIPT turn
whose "match" text is in the prompt: {"turns": [{"match", "mode", "commands": [{"command", "target",
"nonce", "mode", "wrong_nonce"}], "patches": [{"path", "line", "mode"}]}]}. A command runs with /bin/sh
only if its target (default the cwd; null for a read) is writable under the argv's sandbox; otherwise it is
recorded as failing with EROFS and never runs (a probe helper command records the JSON the helper prints for
EROFS). Modes: "no-event" (the model declines), "wrong-nonce" (it runs the command with another nonce), "lie"
(it runs unsandboxed but reports EROFS), "fail" (recorded as failing for another reason, never run), "enoent"
(recorded as the helper failing with errno 2, never run), "unsandboxed" (broken enforcement: it runs whatever the
sandbox says and records the real output and exit code) and "hang" (turn level: stays open until stopped). A
patch appends its line when the sandbox allows the path and records a FileChange item; a refused patch records
"patch rejected" in stderr. Patch modes: "no-event", "lie" (writes, reports a rejection) and "mismatch" (fails
on context, no refusal); a patch with "shape": "response_item" is recorded as a custom_tool_call pair instead of
a FileChange item, and "shape": "deep_arguments" as a function_call pair whose arguments nest too deep to parse.
Turn keys: "context_delay" (seconds between task_started and turn_context),
"record_sandbox" (the sandbox the records claim), "incomplete" (no task_complete), "settings_first" (the
turn's thread_settings_applied comes before its task_started, as a resumed process may write it), "served_tier"
(the tier that record claims), "abort_on_stop" (a hang turn writes turn_aborted when it gets SIGTERM),
"partial_record" (a hang turn leaves an unterminated final line, as a writer cut mid-record does) and
"malformed_record" (a complete line that is not JSON right after task_started). A resume with
FAKE_HOST_PLAN set runs the fake host inside the turn. None of this says how a real sandbox behaves.
"""
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time
import uuid

HOST = Path(__file__).resolve().with_name("hierarchy_fake_host.py")
EROFS = "OSError: [Errno 30] Read-only file system: '%s'\n"
HELPER = "native-probe-attempt.py"
COMMAND_MODES = ("", "run", "no-event", "wrong-nonce", "lie", "hang", "fail", "enoent", "unsandboxed")
PATCH_MODES = ("", "run", "no-event", "lie", "mismatch")
DECLINED = "I will not run those commands."
CARVE_OUTS = (".git", ".agents", ".codex")


def main():
    argv = sys.argv[1:]
    if os.environ.get("FAKE_CODEX_ROLLOUT"):
        sys.exit(rollout_main(argv))
    if "resume" in argv:
        os.execv(sys.executable, [sys.executable, str(HOST), *argv])
    log_call(argv)
    mode = os.environ.get("FAKE_CODEX_MODE", "")
    if mode == "no-thread":
        sys.exit(1)
    if mode == "silent-hang":
        time.sleep(120)
    print(json.dumps({"type": "thread.started", "thread_id": os.environ["FAKE_CODEX_THREAD"]}), flush=True)
    if mode == "hang":
        time.sleep(120)
    if mode == "fail-after-thread":
        sys.exit(4)
    if mode in ("leave-child", "escape"):
        child = subprocess.Popen(["sleep", "30"], start_new_session=mode == "escape")
        Path(os.environ["FAKE_CODEX_CHILD"]).write_text(str(child.pid), encoding="utf-8")
    for event in ({"type": "turn.started"},
                  {"type": "item.completed", "item": {"id": "item_0", "type": "agent_message", "text": "READY"}},
                  {"type": "turn.completed", "usage": {"input_tokens": 1, "output_tokens": 1}}):
        print(json.dumps(event), flush=True)
    touch()


def log_call(argv, **extra):
    if os.environ.get("FAKE_CODEX_LOG"):
        with open(os.environ["FAKE_CODEX_LOG"], "a", encoding="utf-8") as log:
            log.write(json.dumps({"argv": argv, "cwd": os.getcwd(), "pid": os.getpid(), **extra}) + "\n")


def touch():
    if os.environ.get("FAKE_CODEX_TOUCH"):
        Path(os.environ["FAKE_CODEX_TOUCH"]).write_text("{}", encoding="utf-8")


def emit(event):
    print(json.dumps(event), flush=True)


class ScriptError(Exception):
    pass


def parse_argv(argv):
    """Read the options codex_argv writes; the last word is the prompt, as the launcher and wake pass it."""
    try:  # Only rollout mode needs TOML.
        import tomllib
    except ModuleNotFoundError:  # Python < 3.11, where pytest itself depends on tomli
        import tomli as tomllib
    options = {"sandbox": "read-only", "cwd": os.getcwd(), "config": {}, "add_dirs": [], "resume": None}
    index = 0
    while index < len(argv):
        word = argv[index]
        if word in ("--sandbox", "-s"):
            options["sandbox"] = argv[index + 1]
        elif word == "-C":
            options["cwd"] = argv[index + 1]
        elif word == "--add-dir":
            options["add_dirs"].append(argv[index + 1])
        elif word == "-c":
            merge(options["config"], tomllib.loads(argv[index + 1]))
        elif word == "--disable":
            pass
        elif word == "resume":
            options["resume"] = argv[index + 1]
            index += 1
        else:
            index -= 1
        index += 2
    options["prompt"] = argv[-1] if argv else ""
    return options


def merge(into, value):
    for key, item in value.items():
        if isinstance(item, dict) and isinstance(into.get(key), dict):
            merge(into[key], item)
        else:
            into[key] = item


class Sandbox:
    def __init__(self, options):
        self.mode = options["sandbox"]
        self.cwd = options["cwd"]
        settings = options["config"].get("sandbox_workspace_write", {})
        self.writable_roots = list(settings.get("writable_roots", []))
        self.network_access = bool(settings.get("network_access", False))
        self.exclude_slash_tmp = bool(settings.get("exclude_slash_tmp", False))
        self.exclude_tmpdir = bool(settings.get("exclude_tmpdir_env_var", False))
        self.add_dirs = options["add_dirs"]

    def roots(self):
        if self.mode != "workspace-write":
            return []
        return [self.cwd, *self.writable_roots, *self.add_dirs]

    def special_roots(self):
        if self.mode != "workspace-write":
            return []
        found = []
        if not self.exclude_slash_tmp:
            found.append(("slash_tmp", "/tmp"))
        if not self.exclude_tmpdir and os.environ.get("TMPDIR"):
            found.append(("tmpdir", os.environ["TMPDIR"]))
        return found

    def policy(self):
        if self.mode != "workspace-write":
            return {"type": self.mode}
        return {"type": "workspace-write", "writable_roots": [*self.writable_roots, *self.add_dirs],
                "network_access": self.network_access, "exclude_slash_tmp": self.exclude_slash_tmp,
                "exclude_tmpdir_env_var": self.exclude_tmpdir}

    def profile(self):
        if self.mode == "danger-full-access":
            return {"type": "disabled"}
        entries = [{"path": {"type": "special", "value": {"kind": "root"}}, "access": "read"}]
        entries += [{"path": {"type": "path", "path": root}, "access": "write"} for root in self.roots()]
        entries += [{"path": {"type": "special", "value": {"kind": kind}}, "access": "write"} for kind, _ in self.special_roots()]
        entries += [{"path": {"type": "path", "path": os.path.join(root, name)}, "access": "read", "missing_path_behavior": "skip"}
                    for root in self.roots() for name in CARVE_OUTS]
        return {"type": "managed", "network": "enabled" if self.network_access else "restricted",
                "file_system": {"type": "restricted", "entries": entries}}

    def allows(self, target):
        if target is None or self.mode == "danger-full-access":
            return True
        path = os.path.realpath(os.path.join(self.cwd, target))
        roots = [os.path.realpath(root) for root in self.roots()]
        if any(inside(path, os.path.join(root, name)) for root in roots for name in CARVE_OUTS):
            return False
        return any(inside(path, root) for root in roots + [os.path.realpath(path) for _, path in self.special_roots()])


def inside(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


class Rollout:
    def __init__(self, path, thread):
        self.path = path
        self.thread = thread

    def write(self, kind, payload):
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".%03dZ" % (time.time() * 1000 % 1000)
        with open(self.path, "a", encoding="utf-8") as stream:
            stream.write(json.dumps({"timestamp": stamp, "type": kind, "payload": payload}) + "\n")
            stream.flush()

    def event(self, payload):
        self.write("event_msg", payload)


def rollout_main(argv):
    if not os.environ.get("CODEX_HOME"):
        sys.stderr.write("fake codex: FAKE_CODEX_ROLLOUT needs CODEX_HOME\n")
        return 2
    options = parse_argv(argv)
    sessions = Path(os.environ["CODEX_HOME"]) / "sessions"
    if options["resume"]:
        thread = options["resume"]
        found = sorted(sessions.glob("*/*/*/rollout-*-%s.jsonl" % thread))
        if not found:
            sys.stderr.write("Error: no rollout found for thread id %s\n" % thread)
            return 1
        rollout = Rollout(found[-1], thread)
    else:
        mode = os.environ.get("FAKE_CODEX_MODE", "")
        if mode == "no-thread":
            return 1
        thread = os.environ.get("FAKE_CODEX_THREAD") or str(uuid.uuid4())
        now = time.localtime()
        folder = sessions / time.strftime("%Y/%m/%d", now)
        folder.mkdir(parents=True, exist_ok=True)
        rollout = Rollout(folder / ("rollout-%s-%s.jsonl" % (time.strftime("%Y-%m-%dT%H-%M-%S", now), thread)), thread)
        rollout.write("session_meta", {"id": thread, "session_id": thread, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                       "cwd": options["cwd"], "originator": "codex_exec", "source": "exec",
                                       "cli_version": os.environ.get("FAKE_CODEX_CLI_VERSION", "0.166.0"),
                                       "model_provider": "openai"})
    log_call(argv, rollout=str(rollout.path))
    try:
        turn = pick_turn(options["prompt"])
    except ScriptError as exc:
        sys.stderr.write("fake codex script error: %s\n" % exc)
        return 2
    emit({"type": "thread.started", "thread_id": thread})
    return run_turn(rollout, options, turn)


def pick_turn(prompt):
    if not os.environ.get("FAKE_CODEX_SCRIPT"):
        return {"commands": []}
    script = json.loads(Path(os.environ["FAKE_CODEX_SCRIPT"]).read_text(encoding="utf-8"))
    turns = script["turns"] if isinstance(script, dict) and "turns" in script else [script]
    turns = [{"commands": turn} if isinstance(turn, list) else turn for turn in turns]
    for turn in turns:
        if turn.get("match", "") in prompt:
            for command in turn.get("commands", []):
                mode = command.get("mode", turn.get("mode", ""))
                if mode == "wrong-nonce" and not command.get("nonce"):
                    raise ScriptError("wrong-nonce needs a nonce")
                if mode not in COMMAND_MODES:
                    raise ScriptError("unknown mode %r" % mode)
            for patch in turn.get("patches", []):
                if patch.get("mode", "") not in PATCH_MODES:
                    raise ScriptError("unknown patch mode %r" % patch.get("mode"))
            return turn
    return {"commands": []}


def run_turn(rollout, options, turn):
    sandbox = Sandbox(options)
    config = options["config"]
    turn_id = str(uuid.uuid4())
    model = config.get("model", "fake-default-model")
    effort = config.get("model_reasoning_effort", "medium")
    approval = config.get("approval_policy", "on-request")
    reviewer = config.get("approvals_reviewer", "user")
    recorded = Sandbox({**options, "sandbox": turn["record_sandbox"]}) if turn.get("record_sandbox") else sandbox
    profile = recorded.profile()
    applied = {"type": "thread_settings_applied", "thread_id": rollout.thread, "thread_settings": {
        "model": model, "service_tier": turn.get("served_tier", config.get("service_tier", "default")),
        "approval_policy": approval, "approvals_reviewer": reviewer, "permission_profile": profile,
        "cwd": options["cwd"], "reasoning_effort": effort}}
    if turn.get("settings_first"):
        rollout.event(applied)
    rollout.event({"type": "task_started", "turn_id": turn_id, "root_turn_id": turn_id, "started_at": int(time.time())})
    if turn.get("malformed_record"):
        with open(rollout.path, "a", encoding="utf-8") as stream:
            stream.write('{"timestamp": "bad", "type": "event_msg", "payload": {"type": "tok\n')
    if turn.get("context_delay"):
        time.sleep(float(turn["context_delay"]))
    if not turn.get("settings_first"):
        rollout.event(applied)
    # The probe stops a hold turn as soon as its turn_context is visible; a turn that
    # "finishes on its own" must not be cut between turn_context and task_complete.
    deferred_stop = turn.get("finish_before_stop") and hasattr(signal, "pthread_sigmask")
    if deferred_stop:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
    rollout.write("turn_context", {"turn_id": turn_id, "root_turn_id": turn_id, "cwd": options["cwd"], "model": model,
                                   "effort": effort, "approval_policy": approval, "approvals_reviewer": reviewer,
                                   "sandbox_policy": recorded.policy(), "permission_profile": profile, "summary": "auto"})
    emit({"type": "turn.started"})
    turn_mode = turn.get("mode", "")
    message = DECLINED if turn_mode == "no-event" else turn.get("message", "DONE")
    for number, command in enumerate(turn.get("commands", [])):
        mode = command.get("mode", turn_mode)
        if mode == "no-event":
            continue
        run_command(rollout, sandbox, turn_id, "item_%d" % number, command, mode)
    for number, patch in enumerate(turn.get("patches", [])):
        if patch.get("mode", "") != "no-event":
            apply_patch(rollout, sandbox, turn_id, "patch_%d" % number, patch)
    if turn_mode == "hang":
        if turn.get("abort_on_stop"):
            def aborted(number, frame):
                rollout.event({"type": "turn_aborted", "turn_id": turn_id, "reason": "interrupted"})
                os._exit(128 + number)
            signal.signal(signal.SIGTERM, aborted)
        if turn.get("partial_record"):
            with open(rollout.path, "a", encoding="utf-8") as stream:
                stream.write('{"timestamp": "cut", "type": "event_msg", "payload": {"type": "tok')
        time.sleep(float(os.environ.get("FAKE_CODEX_HANG_SECONDS", "120")))
        return 0
    if options["resume"] and os.environ.get("FAKE_HOST_PLAN"):
        host = subprocess.run([sys.executable, str(HOST), *sys.argv[1:]])
        if host.returncode:
            return host.returncode
    rollout.event({"type": "item_completed", "thread_id": rollout.thread, "turn_id": turn_id,
                   "item": {"type": "AgentMessage", "id": "msg_" + turn_id, "content": [{"type": "Text", "text": message}]}})
    if not turn.get("incomplete"):
        rollout.event({"type": "task_complete", "turn_id": turn_id, "root_turn_id": turn_id,
                       "last_agent_message": message})
    if deferred_stop:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM})
    emit({"type": "item.completed", "item": {"id": "item_msg", "type": "agent_message", "text": message}})
    emit({"type": "turn.completed", "usage": {"input_tokens": 1, "output_tokens": 1}})
    if not options["resume"]:
        touch()
    return 0


def run_command(rollout, sandbox, turn_id, item_id, command, mode):
    text, target = command["command"], command.get("target", sandbox.cwd)
    if mode == "wrong-nonce":
        nonce = command["nonce"]
        wrong = command.get("wrong_nonce") or hashlib.sha256(nonce.encode()).hexdigest()[:max(len(nonce), 8)]
        text = text.replace(nonce, wrong)
        target = target.replace(nonce, wrong) if target is not None else None
    started = time.time()
    if mode == "fail":
        exit_code, output = 1, "fake codex: the command failed for another reason\n"
    elif mode == "enoent":
        exit_code, output = 1, helper_failure(text, 2, "No such file or directory") or "No such file or directory\n"
    elif mode in ("lie", "unsandboxed") or sandbox.allows(target):
        ran = subprocess.run(["/bin/sh", "-c", text], cwd=sandbox.cwd, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        exit_code, output = ran.returncode, ran.stdout
    else:
        exit_code, output = 1, helper_failure(text) or EROFS % os.path.join(sandbox.cwd, target)
    if mode == "lie":
        exit_code = 1
        output = helper_failure(text) or EROFS % os.path.join(sandbox.cwd, target if target is not None else ".")
    status = "completed" if exit_code == 0 else "failed"
    argv = ["/bin/sh", "-c", text]
    elapsed = time.time() - started
    rollout.event({"type": "item_completed", "thread_id": rollout.thread, "turn_id": turn_id,
                   "started_at_ms": int(started * 1000), "completed_at_ms": int(time.time() * 1000),
                   "item": {"type": "CommandExecution", "id": item_id, "process_id": str(os.getpid()), "command": argv,
                            "cwd": sandbox.cwd, "parsed_cmd": [], "source": "unified_exec_startup", "status": status,
                            "aggregated_output": output, "exit_code": exit_code,
                            "duration": {"secs": int(elapsed), "nanos": int(elapsed % 1 * 1e9)}}})
    emit({"type": "item.completed", "item": {"id": item_id, "type": "command_execution", "command": shlex.join(argv),
                                             "aggregated_output": output, "exit_code": exit_code, "status": status}})


def helper_failure(text, errno=30, reason="Read-only file system"):
    """The JSON the probe helper prints when its open fails, or None when text is not a helper run."""
    try:
        words = shlex.split(text)
    except ValueError:
        return None
    if len(words) != 5 or words[1] != "-I" or os.path.basename(words[2]) != HELPER:
        return None
    path, nonce = words[3], words[4]
    return json.dumps({"ok": False, "path": path, "nonce": nonce, "errno": errno,
                       "error": "OSError: [Errno %d] %s: '%s'" % (errno, reason, path)}) + "\n"


def apply_patch(rollout, sandbox, turn_id, item_id, patch):
    path, mode = patch["path"], patch.get("mode", "")
    stderr = None
    if mode == "mismatch":
        stderr = "Failed to find expected lines in %s\n" % path
    elif mode == "lie" or sandbox.allows(path):
        try:
            with open(os.path.join(sandbox.cwd, path), "a", encoding="utf-8") as stream:
                stream.write(patch["line"] + "\n")
        except OSError as exc:
            stderr = "patch failed: %s\n" % exc
        if mode == "lie":
            stderr = "patch rejected: Read-only file system: '%s'\n" % path
    else:
        stderr = "patch rejected: Read-only file system: '%s'\n" % path
    if patch.get("shape") == "deep_arguments":
        rollout.write("response_item", {"type": "function_call", "name": "apply_patch", "call_id": item_id,
                                        "arguments": "[" * 100000 + "]" * 100000})
        rollout.write("response_item", {"type": "function_call_output", "call_id": item_id,
                                        "output": stderr or "Success."})
        return
    if patch.get("shape") == "response_item":
        # The Responses-API pair: an apply_patch tool call, then its output by call_id. Unconfirmed against a
        # real host; the refusal text is the one evidence/30 quotes.
        if stderr and stderr.startswith("patch rejected"):
            stderr = "patch rejected: writing outside of the project; rejected by user approval settings"
        rollout.write("response_item", {"type": "custom_tool_call", "name": "apply_patch", "call_id": item_id,
                                        "status": "completed", "input": "*** Begin Patch\n*** Add File: %s\n+%s\n"
                                                                        "*** End Patch\n" % (path, patch["line"])})
        rollout.write("response_item", {"type": "custom_tool_call_output", "call_id": item_id,
                                        "output": stderr or "Success. Updated the following files:\nA %s\n" % path})
        return
    item = {"type": "FileChange", "id": item_id, "changes": [{"path": path, "kind": "add"}],
            "status": "failed" if stderr else "completed"}
    if stderr:
        item["stderr"] = stderr
    rollout.event({"type": "item_completed", "thread_id": rollout.thread, "turn_id": turn_id, "item": item})


if __name__ == "__main__":
    main()
