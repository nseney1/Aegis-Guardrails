"""A stand-in for the codex command, installed on PATH by the launcher tests.

A start (no "resume" word) prints the JSON events a real `codex exec --json` start begins with. FAKE_CODEX_MODE
picks a failure: "no-thread" exits 1 without events, "hang" prints thread.started and then waits to be stopped,
"silent-hang" waits without events, "fail-after-thread" exits 4. "leave-child" leaves a sleep in its process
group and "escape" leaves one in a new session holding stdout; both write the sleep's pid to FAKE_CODEX_CHILD.
FAKE_CODEX_TOUCH names a file created just before a clean exit. A resume runs the fake host, so the real
adapter reads the mailbox.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def main():
    argv = sys.argv[1:]
    if "resume" in argv:
        host = str(Path(__file__).resolve().with_name("hierarchy_fake_host.py"))
        os.execv(sys.executable, [sys.executable, host, *argv])
    if os.environ.get("FAKE_CODEX_LOG"):
        with open(os.environ["FAKE_CODEX_LOG"], "a", encoding="utf-8") as log:
            log.write(json.dumps({"argv": argv, "cwd": os.getcwd(), "pid": os.getpid()}) + "\n")
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
    if os.environ.get("FAKE_CODEX_TOUCH"):
        Path(os.environ["FAKE_CODEX_TOUCH"]).write_text("{}", encoding="utf-8")


if __name__ == "__main__":
    main()
