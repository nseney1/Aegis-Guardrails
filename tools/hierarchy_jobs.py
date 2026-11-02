#!/usr/bin/env python3
"""Run orchestrators' job requests through root's fixed recipes and answer each with a receipt.

Validation, commits and other physical work used to be hand-run by root from free-text requests.
This tool does the routine part. An orchestrator names a recipe and an exact source in a hash-bound
packet; root's recipe file says what that recipe runs. The argv comes only from that file, with
exact-word substitution and no shell, so nothing in a message can become a command or an option.

A job is refused unless the checkout is registered for the initiative and its revision, tree and
the bytes of its uncommitted files match the packet exactly. The source is witnessed again afterward,
so a clean exit over changed source is not reported as success. Files Git ignores are not covered. A heavy job takes a ledger slot, and processes the
census finds outside the ledger count against the same limit. A slot is freed only with evidence: a
lost runner leaves `unknown` and keeps the slot until root runs `resolve`.

Every result lands in `<store>/jobs/<initiative>/<message-id>/` before its receipt goes out, so a
receipt that cannot be published is retried by the next run instead of being lost.

A completed job removes its work folders, because one full test run can leave gigabytes, and keeps its
logs and result. A failed job keeps them until root runs `clean`, because they may be evidence.

A receipt is a claim with evidence references, never a verdict on the work. Bubblewrap keeps
accidents contained, but this runs under one OS user and is not a security boundary: Git inspection
of a checkout runs outside the sandbox, so a process that edits that checkout's `.git/config` could
run code there. A process that starts its own session also escapes the stop at the end of a step.
Linux only, because the census and the liveness checks read /proc.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_mailbox import (GIT_ID, SHA256, SLUG, Mailbox, encoded, fields, integer, matching,  # noqa: E402
                               publish_file, read_json, require, safe_path, strict_json, strings, text, timestamp,
                               writer_lock)
from hierarchy_wake import stop_group  # noqa: E402
from hierarchy_workspace import Store, absolute, check_paths, grant_next, verify_evidence  # noqa: E402


RECIPES_SCHEMA = "aegis.hierarchy-job-recipes/v1"
PACKET_SCHEMA = "aegis.hierarchy-job-packet/v1"
RESULT_SCHEMA = "aegis.hierarchy-job-result/v1"
COMMAND_TOKENS = {"$python", "$paths", "$scratch", "$checkout"}
ENV_TOKENS = {"$scratch", "$checkout"}
SANDBOXES = ("bwrap", "none")
# The orchestrator only needs a summary; the full output stays in the evidence files.
TAIL_BYTES = 2000
EMPTY_STATUS = hashlib.sha256(b"").hexdigest()
# A result this tool decided, where no command's own exit says what happened.
NO_VERDICT_EXIT = -1
MAX_PATHS = 256
# Each step leaves up to two files, and a receipt can reference 64.
MAX_STEPS = 20
# A claim this old with nothing readable in it was left by a runner that died while writing it.
CLAIM_GRACE_SECONDS = 60
MAX_RESULT_BYTES = 4194304
MAX_JOBS_DEFAULT = 20
MAX_TIMEOUT_SECONDS = 86400
DEFAULT_LOCK_WAIT_SECONDS = 30.0
# A leading dash would become an option, and pathspec and glob characters would widen what is named.
PATH_ARGUMENT = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_./@+-]*(::[^\x00-\x1f]{1,512})?")
JOB_ID = re.compile(SLUG.pattern + "/" + SLUG.pattern)
ERRORS = (ValueError, OSError, UnicodeError, RecursionError, TypeError, KeyError, subprocess.SubprocessError)
WORK_FOLDERS = ("scratch", "tmp", "home", "cargo-target", "ruff-cache", "hypothesis")
HOME_FOLDERS = {"HOME": "", "USERPROFILE": "", "APPDATA": "AppData/Roaming", "LOCALAPPDATA": "AppData/Local",
                "CODEX_HOME": ".codex", "CLAUDE_CONFIG_DIR": ".claude", "XDG_CONFIG_HOME": ".config",
                "XDG_CACHE_HOME": ".cache", "XDG_DATA_HOME": ".local/share", "XDG_STATE_HOME": ".local/state",
                "CARGO_HOME": ".cargo", "PYTHONUSERBASE": ".local"}


def checked_words(words, allowed, label):
    for word in words:
        # Exact words only: no recipe or packet value is ever formatted into a larger argument.
        require(isinstance(word, str) and word and "\0" not in word, "invalid word in " + label)
        require("$" not in word or word in allowed, "unsupported token in " + label + ": " + word)


def validate_recipe(name, recipe):
    matching(name, SLUG, "recipe name")
    require(isinstance(recipe, dict) and recipe.get("kind") in ("command", "commit"), "invalid kind for recipe " + name)
    integer(recipe.get("timeout_seconds"), "timeout_seconds", maximum=MAX_TIMEOUT_SECONDS)
    require(recipe.get("sandbox") in SANDBOXES, "invalid sandbox for recipe " + name)
    if recipe["kind"] == "commit":
        fields(recipe, {"kind", "timeout_seconds", "sandbox"})
        return
    fields(recipe, {"kind", "timeout_seconds", "sandbox", "heavy", "steps"}, {"writable_checkout"})
    require(type(recipe["heavy"]) is bool, "invalid heavy flag for recipe " + name)
    require(type(recipe.get("writable_checkout", False)) is bool, "invalid writable_checkout for recipe " + name)
    steps = recipe["steps"]
    require(isinstance(steps, list) and 0 < len(steps) <= MAX_STEPS and all(isinstance(step, list) and step for step in steps),
            "invalid steps for recipe " + name)
    for step in steps:
        checked_words(step, COMMAND_TOKENS, "recipe " + name)


def existing_folders(value, label):
    strings(value, label)
    for folder in value:
        path = Path(folder)
        require(path.is_absolute() and path.is_dir(), label + " must list existing absolute folders: " + folder)


def load_recipes(path):
    recipes = read_json(path)
    fields(recipes, {"schema", "python", "path", "recipes"}, {"identity", "env", "hide", "ro_binds", "prefix", "min_free_gigabytes"})
    if "min_free_gigabytes" in recipes:
        integer(recipes["min_free_gigabytes"], "min_free_gigabytes", minimum=0)
    require(recipes["schema"] == RECIPES_SCHEMA, "unsupported recipes schema")
    require(isinstance(recipes["python"], str) and Path(recipes["python"]).is_absolute(), "python must be an absolute path")
    strings(recipes["path"], "path", nonempty=True)
    require(all(Path(folder).is_absolute() for folder in recipes["path"]), "path must list absolute folders")
    existing_folders(recipes.get("hide", []), "hide")
    existing_folders(recipes.get("ro_binds", []), "ro_binds")
    prefix = recipes.get("prefix", [])
    strings(prefix, "prefix")
    require(not prefix or Path(prefix[0]).is_absolute(), "prefix must start with an absolute command")
    env = recipes.get("env", {})
    require(isinstance(env, dict) and all(isinstance(value, str) for value in env.values()), "invalid env")
    for key, value in env.items():
        require(re.fullmatch(r"[A-Z_][A-Z0-9_]*", key) is not None, "invalid env name: " + key)
        require("$" not in value or value in ENV_TOKENS, "unsupported token in env: " + value)
    table = recipes["recipes"]
    require(isinstance(table, dict) and table, "recipes must not be empty")
    for name, recipe in table.items():
        validate_recipe(name, recipe)
    if any(recipe["kind"] == "commit" for recipe in table.values()):
        identity = recipes.get("identity")
        require(isinstance(identity, dict), "a commit recipe needs an identity")
        fields(identity, {"name", "email"})
        text(identity["name"], "identity name", 256)
        text(identity["email"], "identity email", 256)
    return recipes


def is_heavy(recipe):
    return recipe.get("heavy", False)


def packet_text(raw):
    """A packet is either a whole file or the body of a mailbox message, so read-only roles can send one."""
    content = raw.decode("utf-8")
    if not content.startswith("---\n"):
        return content
    _, separator, body = content[4:].partition("\n---\n\n")
    require(bool(separator), "packet message has no body")
    return body


def checked_paths(packet, recipe, checkout):
    paths = packet.get("paths")
    commit = recipe["kind"] == "commit"
    takes_paths = commit or any("$paths" in step for step in recipe["steps"])
    if not takes_paths:
        require(not paths, "this recipe takes no paths")
        return []
    require(isinstance(paths, list) and bool(paths), "this recipe needs paths")
    require(len(paths) <= MAX_PATHS, "too many paths")
    for path in paths:
        require(isinstance(path, str) and PATH_ARGUMENT.fullmatch(path) is not None, "invalid path: " + str(path))
        name, _, selector = path.partition("::")
        require(".." not in name.split("/") and not (commit and selector), "invalid path: " + path)
        # A commit may name a deleted file. Tests must exist, so a typo reads as a refusal and not a failed run.
        require(commit or (Path(checkout) / name).exists(), "path does not exist in the checkout: " + name)
    return paths


def path_fingerprint(path):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return b"absent"
    if stat.S_ISLNK(info.st_mode):
        return b"link:" + os.fsencode(os.readlink(path))
    if not stat.S_ISREG(info.st_mode):
        return b"other"
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            digest.update(chunk)
    return b"file:" + (b"x" if info.st_mode & 0o111 else b"-") + b":" + digest.hexdigest().encode()


def uncommitted_content(checkout):
    """Git status names the paths that differ, not their bytes, so one status can hide different content."""
    status = subprocess.run(["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
                            cwd=checkout, capture_output=True, timeout=120)
    require(status.returncode == 0, "could not read the status of " + str(checkout))
    tokens = status.stdout.split(b"\0")
    digest = hashlib.sha256()
    count = index = 0
    while index < len(tokens):
        token = tokens[index]
        index += 1
        if not token:
            continue
        count += 1
        names = [token[3:]]
        if token[:1] in (b"R", b"C") or token[1:2] in (b"R", b"C"):
            names.append(tokens[index])
            index += 1
        digest.update(token[:2] + b"\0")
        for name in names:
            digest.update(name + b"\0" + path_fingerprint(os.path.join(os.fsencode(checkout), name)) + b"\0")
    return digest.hexdigest(), count


def source_state(mailbox, checkout):
    return {**mailbox.source_witness(checkout), "dirty_content_sha256": uncommitted_content(checkout)[0]}


def source_digest(checkout):
    """What an orchestrator needs for a packet. A lane with a shell can run this and report it."""
    path = safe_path(text(checkout, "checkout"))
    digest, count = uncommitted_content(path)
    return 0, {"commit": Mailbox.git(path, "rev-parse", "HEAD"), "tree": Mailbox.git(path, "rev-parse", "HEAD^{tree}"),
               "dirty_content_sha256": digest, "dirty_entries": count}


def admit(ledger, initiative, message, mailbox, recipes):
    """Everything a job must satisfy before it runs. A ValueError here becomes the refusal's reason."""
    raw = mailbox.brief(message["brief"])
    try:
        packet = strict_json(packet_text(raw))
    except UnicodeError as exc:
        raise ValueError("packet is not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("packet is not valid JSON") from exc
    fields(packet, {"schema", "recipe", "checkout", "commit", "tree"},
           {"dirty_content_sha256", "paths", "expected_tree", "message"})
    require(packet["schema"] == PACKET_SCHEMA, "unsupported packet schema")
    name = packet["recipe"]
    require(isinstance(name, str) and name in recipes["recipes"], "unknown recipe: " + str(name)[:128])
    recipe = recipes["recipes"][name]
    checkout = absolute(packet["checkout"], "checkout")
    require(checkout in initiative["checkouts"], "checkout is not registered for this initiative: " + checkout)
    matching(packet["commit"], GIT_ID, "commit")
    matching(packet["tree"], GIT_ID, "tree")
    dirty = packet.get("dirty_content_sha256", EMPTY_STATUS)
    matching(dirty, SHA256, "dirty_content_sha256")
    paths = checked_paths(packet, recipe, checkout)
    if recipe["kind"] == "commit":
        require("expected_tree" in packet and "message" in packet, "a commit recipe needs expected_tree and message")
        matching(packet["expected_tree"], GIT_ID, "expected_tree")
        text(packet["message"], "commit message", 65536)
        require(packet["expected_tree"] != packet["tree"], "this commit would make no change")
        code, overlap = check_paths(ledger, initiative["id"], paths)
        require(code == 0, "paths overlap another lease or a checkout could not be read: " + json.dumps(
            overlap["conflicts"] + overlap["unreadable_checkouts"], sort_keys=True)[:1024])
    else:
        require("expected_tree" not in packet and "message" not in packet,
                "only a commit recipe takes expected_tree or message")
    require(recipe["sandbox"] == "none" or shutil.which("bwrap") is not None,
            "this recipe needs bubblewrap, which is not available")
    witness = source_state(mailbox, checkout)
    require((witness["source_revision"], witness["source_tree"], witness["dirty_content_sha256"]) ==
            (packet["commit"], packet["tree"], dirty), "source does not match the packet")
    return {**packet, "dirty_content_sha256": dirty, "paths": paths}, raw


def patient(action, wait):
    """Locks fail fast by design, but a finished job should not lose its receipt to a moment's contention."""
    deadline = time.monotonic() + wait
    while True:
        try:
            return action()
        except ValueError as exc:
            if "busy" not in str(exc) or time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def process_start(pid):
    """Process start time, which tells a live process from a reused PID. None when it is gone or a zombie."""
    try:
        after_name = Path("/proc/%d/stat" % pid).read_text(encoding="ascii", errors="replace").rpartition(")")[2].split()
    except OSError:
        return None
    return None if after_name[0] in ("Z", "X") else after_name[19]


def group_members(group):
    """Live members of a process group. Zombies cannot act, so they do not count."""
    members = []
    for item in Path("/proc").glob("[0-9]*/stat"):
        try:
            after_name = item.read_text(encoding="ascii", errors="replace").rpartition(")")[2].split()
        except OSError:
            continue
        if after_name[2] == str(group) and after_name[0] not in ("Z", "X"):
            members.append(int(item.parent.name))
    return members


def heavy_command(words):
    """Root's census rule, kept identical so this and root's own controller count the same work."""
    if not words:
        return False
    name = Path(words[0]).name
    if name in ("cargo", "rustc", "pytest", "py.test"):
        return True
    if not name.startswith("python"):
        return False
    index = 1
    while index < len(words):
        word = words[index]
        if word == "-m":
            return index + 1 < len(words) and words[index + 1] == "pytest"
        if word in ("-c", "-"):
            return False
        if word in ("-W", "-X"):
            index += 2
            continue
        if word.startswith("-"):
            index += 1
            continue
        path = Path(word)
        return path.name in ("pytest", "py.test", "pytest.py") or (path.name == "__main__.py" and path.parent.name == "pytest")
    return False


def outside_heavy_roots(owners):
    """Topmost heavy processes that no running job of this ledger started."""
    parents, heavy = {}, set()
    for item in Path("/proc").glob("[0-9]*/cmdline"):
        pid = int(item.parent.name)
        try:
            words = [word.decode(errors="replace") for word in item.read_bytes().split(b"\0") if word]
            parents[pid] = int((item.parent / "stat").read_text(encoding="ascii", errors="replace")
                               .rpartition(")")[2].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        if heavy_command(words):
            heavy.add(pid)
    roots = []
    for pid in heavy:
        line, current = set(), parents.get(pid, 0)
        while current and current not in line:
            line.add(current)
            current = parents.get(current, 0)
        if not line & heavy and not line & owners and pid not in owners:
            roots.append(pid)
    return sorted(roots)


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Job:
    def __init__(self, store_path, initiative, message):
        self.initiative = initiative
        self.message = message
        self.id = initiative["id"] + "/" + message["message_id"]
        self.holder = "job:" + self.id
        self.folder = safe_path(Path(store_path) / "jobs" / initiative["id"] / message["message_id"])
        self.claim_path = self.folder / "claim.json"
        self.result_path = self.folder / "result.json"
        self.process_path = self.folder / "process.json"

    def result(self):
        return read_json(self.result_path) if self.result_path.exists() else None

    def claim(self, packet_raw):
        """Exclusive, so two runners or a retry can never start the same job twice."""
        self.folder.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.folder.mkdir(mode=0o700)
        except FileExistsError:
            return False
        ticks = process_start(os.getpid())
        publish_file(self.claim_path, encoded({"pid": os.getpid(), "start": ticks, "job": self.id, "at": timestamp()}) + b"\n")
        if packet_raw is not None:
            publish_file(self.folder / "packet.md", packet_raw)
        return True

    def runner_alive(self):
        try:
            claim = read_json(self.claim_path)
        except (ValueError, OSError):
            # Probably a runner that is starting right now, so unsure means alive for a moment.
            return time.time() - self.folder.stat().st_mtime < CLAIM_GRACE_SECONDS
        return process_start(claim["pid"]) == claim["start"]

    def process_group(self):
        try:
            return read_json(self.process_path)["group"]
        except (ValueError, OSError):
            return None

    def evidence(self):
        names = sorted(path for path in self.folder.iterdir() if path.name.startswith("step-") or path.name == "result.json")
        return [{"path": str(path), "sha256": file_sha256(path)} for path in names]


def receipt_id(job, state):
    # Stable, so publishing again after a crash finds the earlier receipt instead of adding one.
    return "receipt-" + hashlib.sha256(job.message["message_id"].encode()).hexdigest()[:24] + "-" + state


def publish_receipt(job, state, body, wait, *, exit_code=None, evidence=None, reason=None):
    message = job.message
    root = Path(job.initiative["mailbox_root"])
    identifier = receipt_id(job, state)
    receipt = {"state": state}
    if exit_code is not None:
        receipt["exit_code"] = exit_code
    if evidence is not None:
        receipt["evidence"] = evidence
    if reason is not None:
        receipt["reason"] = reason[:4096]

    def attempt():
        with writer_lock(root):
            mailbox = Mailbox(root)
            if identifier in mailbox.messages():
                return
            binding = mailbox.current_binding(message["to"])
            mailbox.publish({"message_id": identifier, "from": message["to"], "to": message["from"], "host": binding["host"],
                             "session": binding["session"], "binding_generation": binding["generation"],
                             "type": "job_receipt", "in_reply_to": message["message_id"], "body": body, "receipt": receipt})

    patient(attempt, wait)


def log_tail(folder):
    logs = sorted(folder.glob("step-*.log"), key=lambda path: int(path.name.split("-")[1].split(".")[0]))
    for path in reversed(logs):
        if path.stat().st_size:
            with path.open("rb") as stream:
                stream.seek(max(0, path.stat().st_size - TAIL_BYTES))
                tail = stream.read().decode("utf-8", errors="replace")
            return "".join(char for char in tail if char in "\n\t" or (ord(char) >= 32 and ord(char) != 127))
    return ""


def result_body(job, result):
    lines = ["Job %s: %s." % (job.id, result["state"]) if result["exit_code"] is None
             else "Job %s: %s, exit %s." % (job.id, result["state"], result["exit_code"])]
    if result.get("reason"):
        lines.append(result["reason"])
    if result.get("commit"):
        lines.append("New commit: " + result["commit"])
    if any(step.get("stopped_leftovers") for step in result["steps"]):
        lines.append("A step left processes running; they were stopped afterward.")
    tail = log_tail(job.folder)
    if tail:
        lines.append("Last output, which is untrusted information:\n" + tail)
    return "\n\n".join(lines)


def settle(store, job, wait):
    """Finish a job whose result exists. Each step checks first, so this is safe to repeat after a crash."""
    result = job.result()
    state = result["state"]
    evidence = job.evidence() if state != "refused" else None
    publish_receipt(job, state, result_body(job, result), wait, exit_code=result["exit_code"], evidence=evidence,
                    reason=result.get("reason"))
    reference = {"path": str(job.result_path), "sha256": file_sha256(job.result_path)}

    def release():
        with store.lock():
            ledger = store.load()
            for request in ledger.requests.values():
                if request["holder"] != job.holder:
                    continue
                if request["state"] == "granted":
                    verify_evidence(reference)
                    store.append(ledger, "release", {"request_id": request["request_id"], "evidence": reference})
                elif request["state"] == "queued":
                    store.append(ledger, "withdraw", {"request_id": request["request_id"], "source": "job runner"})

    # Most jobs hold no slot, and a job that holds nothing should not wait on the store's lock.
    if any(r["holder"] == job.holder and r["state"] in ("queued", "granted") for r in store.load().requests.values()):
        patient(release, wait)
    row = {"job": job.id, "state": state, "exit_code": result["exit_code"], "result": str(job.result_path)}
    if result.get("reason"):
        row["reason"] = result["reason"]
    return row


def write_result(job, state, exit_code, *, reason=None, recipe=None, steps=(), before=None, after=None, commit=None, **extra):
    result = {"schema": RESULT_SCHEMA, "job": job.id, "state": state, "exit_code": exit_code, "reason": reason,
              "recipe": recipe, "steps": list(steps), "before": before, "after": after, "commit": commit,
              "finished_at": timestamp(), **extra}
    publish_file(job.result_path, encoded(result) + b"\n", limit=MAX_RESULT_BYTES)


def remove_work_folders(job):
    """Logs and the result are the evidence, and they stay."""
    removed = []
    for name in WORK_FOLDERS:
        folder = job.folder / name
        if not folder.exists():
            continue
        # Test fixtures can leave read-only folders, which would stop a plain removal. A symlink
        # is skipped, because changing its mode would change whatever it points at.
        os.chmod(folder, 0o700)
        for current, folders, _ in os.walk(folder):
            for child in folders:
                path = os.path.join(current, child)
                if not os.path.islink(path):
                    os.chmod(path, 0o700)
        shutil.rmtree(folder)
        removed.append(name)
    return removed


def refuse(store, job, reason, wait):
    if not job.claim(None):
        return {"job": job.id, "state": "running", "process_group": job.process_group()}
    write_result(job, "refused", None, reason=reason[:4096])
    return settle(store, job, wait)


def git_folders(checkout):
    found = subprocess.run(["git", "-c", "core.fsmonitor=false", "rev-parse", "--path-format=absolute", "--git-dir",
                            "--git-common-dir"], cwd=checkout, capture_output=True, text=True, timeout=30)
    require(found.returncode == 0, "could not locate the checkout's Git data")
    return sorted(set(found.stdout.splitlines()))


def sandbox_prefix(recipes, recipe, job, checkout):
    if recipe["sandbox"] == "none":
        return []
    bwrap = shutil.which("bwrap")
    require(bwrap is not None, "this recipe needs bubblewrap, which is not available")
    # No --new-session: the job runs in a session of its own with no terminal, and staying in one
    # process group is what lets the stop at the end of a step reach every child.
    argv = [bwrap, "--die-with-parent", "--unshare-net", "--ro-bind", "/", "/", "--tmpfs", "/tmp"]
    for folder in recipes.get("hide", []):
        argv += ["--tmpfs", folder]
    argv += ["--dev", "/dev", "--proc", "/proc"]
    for folder in recipes.get("ro_binds", []):
        argv += ["--ro-bind", folder, folder]
    commit = recipe["kind"] == "commit"
    argv += ["--bind" if recipe.get("writable_checkout") else "--ro-bind", checkout, checkout]
    for folder in git_folders(checkout):
        argv += ["--bind" if commit else "--ro-bind", folder, folder]
    # The job folder itself stays read-only inside, so a job cannot write its own result, claim or logs.
    argv += ["--ro-bind", str(job.folder), str(job.folder)]
    for name in WORK_FOLDERS:
        argv += ["--bind", str(job.folder / name), str(job.folder / name)]
    return argv + ["--chdir", checkout, "--"]


def scratch_argument(job):
    # Below the bound folder, because pytest removes and recreates --basetemp, and a mount point cannot be removed.
    return str(job.folder / "scratch" / "run")


def job_environment(recipes, job, checkout):
    for name in WORK_FOLDERS:
        (job.folder / name).mkdir(mode=0o700, exist_ok=True)
    home = job.folder / "home"
    scratch_tmp = job.folder / "tmp"
    env = {"PATH": os.pathsep.join(recipes["path"]), "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONNOUSERSITE": "1", "GIT_OPTIONAL_LOCKS": "0", "TMP": str(scratch_tmp), "TEMP": str(scratch_tmp),
           "TMPDIR": str(scratch_tmp),
           # These tools otherwise write beside the source, and a job usually cannot write there.
           "CARGO_TARGET_DIR": str(job.folder / "cargo-target"), "RUFF_CACHE_DIR": str(job.folder / "ruff-cache"),
           "HYPOTHESIS_STORAGE_DIRECTORY": str(job.folder / "hypothesis")}
    for name, folder in HOME_FOLDERS.items():
        path = home / folder
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        env[name] = str(path)
    tokens = {"$checkout": checkout, "$scratch": scratch_argument(job)}
    for key, value in recipes.get("env", {}).items():
        env[key] = tokens.get(value, value)
    return env


class Step:
    def __init__(self, argv, env=None, capture=False):
        self.argv, self.env, self.capture = argv, env or {}, capture


class Halt(Exception):
    """A recipe's own check failed, so later steps must not run and nothing further should change."""


def command_steps(recipe, packet, recipes, scratch):
    tokens = {"$python": [recipes["python"]], "$paths": packet["paths"], "$scratch": [scratch],
              "$checkout": [packet["checkout"]]}
    for step in recipe["steps"]:
        yield Step([part for word in step for part in tokens.get(word, [word])])
    return None


def commit_steps(packet, recipes, job):
    """Built on a throwaway index, so a wrong tree leaves the checkout's index, HEAD and files as they were."""
    identity = recipes["identity"]
    git = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false",
           "-c", "user.name=" + identity["name"], "-c", "user.email=" + identity["email"]]
    plain = {"GIT_LITERAL_PATHSPECS": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    temporary = {**plain, "GIT_INDEX_FILE": str(job.folder / "scratch" / "index")}
    message_file = job.folder / "scratch" / "commit-message"
    message_file.parent.mkdir(mode=0o700, exist_ok=True)
    message_file.write_text(packet["message"], encoding="utf-8")
    yield Step(git + ["read-tree", packet["commit"]], temporary)
    yield Step(git + ["add", "--", *packet["paths"]], temporary)
    tree = yield Step(git + ["write-tree"], temporary, capture=True)
    if tree != packet["expected_tree"]:
        raise Halt("the staged tree %s is not the expected tree %s" % (tree, packet["expected_tree"]))
    commit = yield Step(git + ["commit-tree", tree, "-p", packet["commit"], "-F", str(message_file)], plain, capture=True)
    # The old value makes this a compare-and-swap, so a lane committing in between cannot be overwritten.
    yield Step(git + ["update-ref", "-m", "hierarchy job " + job.id, "HEAD", commit, packet["commit"]], plain)
    yield Step(git + ["add", "--", *packet["paths"]], plain)
    return commit


def run_step(job, number, step, sandbox, env, checkout, deadline, on_start, prefix):
    log_path = job.folder / ("step-%d.log" % number)
    out_path = job.folder / ("step-%d.out" % number)
    argv = prefix + sandbox + step.argv
    began = time.monotonic()
    row = {"argv": step.argv, "exit_code": None, "timed_out": False, "stopped_leftovers": False}
    with open(log_path, "xb") as log, open(out_path, "xb") if step.capture else open(os.devnull, "wb") as out:
        process = subprocess.Popen(argv, cwd=checkout, env={**env, **step.env}, stdin=subprocess.DEVNULL,
                                   stdout=out if step.capture else log, stderr=log, start_new_session=True)
    held = encoded({"group": process.pid, "step": number, "at": timestamp()})
    pending = job.process_path.with_suffix(".pending")
    pending.write_bytes(held)
    pending.replace(job.process_path)
    try:
        on_start()
    except ERRORS:
        stop_group(process)  # A job that could not be recorded must not keep running.
        raise
    remaining = max(0.0, deadline - time.monotonic())
    try:
        process.wait(timeout=remaining)
        row["stopped_leftovers"] = bool(group_members(process.pid))
    except subprocess.TimeoutExpired:
        row["timed_out"] = True
    stop_group(process)
    row["exit_code"] = process.returncode
    row["seconds"] = round(time.monotonic() - began, 3)
    return row, out_path.read_text(encoding="utf-8", errors="replace").strip() if step.capture else None


def execute(job, recipe, packet, recipes, on_start):
    checkout = packet["checkout"]
    env = job_environment(recipes, job, checkout)
    sandbox = sandbox_prefix(recipes, recipe, job, checkout)
    prefix = list(recipes.get("prefix", []))
    deadline = time.monotonic() + recipe["timeout_seconds"]
    commit = recipe["kind"] == "commit"
    plan = commit_steps(packet, recipes, job) if commit else command_steps(recipe, packet, recipes, scratch_argument(job))
    rows, reason, exit_code, created, output = [], None, 0, None, None
    started = False

    def started_once():
        nonlocal started
        if not started:
            on_start()
            started = True

    try:
        step = plan.send(None)
        while True:
            row, output = run_step(job, len(rows) + 1, step, sandbox, env, checkout, deadline, started_once, prefix)
            rows.append(row)
            if row["timed_out"]:
                reason = "timed out after %d seconds" % recipe["timeout_seconds"]
                exit_code = row["exit_code"] or NO_VERDICT_EXIT
                break
            if row["exit_code"] != 0:
                reason, exit_code = "step %d exited %d" % (len(rows), row["exit_code"]), row["exit_code"]
                break
            step = plan.send(output)
    except StopIteration as stop:
        created = stop.value
    except Halt as halt:
        reason, exit_code = str(halt), NO_VERDICT_EXIT
    return rows, reason, exit_code, created


def run_job(store, job, packet, packet_raw, recipes, wait):
    recipe = recipes["recipes"][packet["recipe"]]
    if not job.claim(packet_raw):
        return {"job": job.id, "state": "running", "process_group": job.process_group()}
    mailbox = Mailbox(job.initiative["mailbox_root"])
    checkout = packet["checkout"]
    try:
        before = source_state(mailbox, checkout)
    except ERRORS as exc:
        write_result(job, "refused", None, reason="could not witness the source: " + str(exc)[:2048])
        return settle(store, job, wait)
    if (before["source_revision"], before["source_tree"], before["dirty_content_sha256"]) != (
            packet["commit"], packet["tree"], packet["dirty_content_sha256"]):
        # The job may have waited hours for a slot, so the exact source is checked again here.
        write_result(job, "refused", None, reason="source does not match the packet: it changed while the job waited")
        return settle(store, job, wait)

    def announce():
        publish_receipt(job, "started", "Job %s started." % job.id, wait)

    try:
        rows, reason, exit_code, created = execute(job, recipe, packet, recipes, announce)
    except ERRORS as exc:
        rows, reason, exit_code, created = [], "the job could not run: " + str(exc)[:2048], NO_VERDICT_EXIT, None
    try:
        after = source_state(mailbox, checkout)
    except ERRORS as exc:
        # Without this the job would have no result, and so no receipt, and would hold its slot.
        after = None
        reason = reason or "could not witness the source afterward: " + str(exc)[:2048]
        exit_code = exit_code or NO_VERDICT_EXIT
    if not reason:
        if recipe["kind"] == "commit":
            if (after["source_revision"], after["source_tree"]) != (created, packet["expected_tree"]):
                reason, exit_code = "the checkout does not show the new commit afterward", NO_VERDICT_EXIT
        elif after != before:
            reason, exit_code = "source changed during the job, so its exit proves nothing", NO_VERDICT_EXIT
    write_result(job, "failed" if reason else "completed", exit_code if reason else 0, reason=reason, recipe=packet["recipe"],
                 steps=rows, before=before, after=after, commit=created if not reason else None)
    cleanup_error = None
    if not reason:
        try:
            remove_work_folders(job)
        except OSError as exc:
            # The result stands either way, so this only tells root that space was not freed.
            cleanup_error = str(exc)[:512]
    row = settle(store, job, wait)
    if reason:
        row["work_kept"] = True
    if cleanup_error:
        row["cleanup_error"] = cleanup_error
    return row


def blocked_row(job, exc):
    return {"job": job.id, "state": "settle_pending", "error": str(exc)[:2048]}


def visit_existing(store, job, wait):
    """Rows for a job this or an earlier run already took. None when the job is new."""
    if job.result_path.exists():
        try:
            return settle(store, job, wait)
        except ERRORS as exc:
            return blocked_row(job, exc)
    if not job.folder.exists():
        return None
    group = job.process_group()
    if job.runner_alive():
        return {"job": job.id, "state": "running", "process_group": group}
    alive = bool(group and group_members(group))
    try:
        publish_receipt(job, "unknown", "Job %s has no result: its runner stopped before reporting. Root must "
                        "resolve it." % job.id, wait, reason="the runner stopped before the job reported an exit")
    except ERRORS as exc:
        return blocked_row(job, exc)
    return {"job": job.id, "state": "abandoned", "process_group": group, "process_alive": alive}


def finish_closed_jobs(store, ledger, initiative, records, open_ids, wait, rows):
    """A receipt can go out before a busy store lets the slot go. The request is closed by then, so the ledger is the record."""
    prefix = "job:" + initiative["id"] + "/"
    for request in ledger.requests.values():
        identifier = request["holder"][len(prefix):] if request["holder"].startswith(prefix) else None
        if identifier and identifier not in open_ids and request["state"] in ("queued", "granted") and identifier in records:
            job = Job(store.path, initiative, records[identifier]["message"])
            if job.result_path.exists():
                try:
                    rows.append(settle(store, job, wait))
                except ERRORS as exc:
                    rows.append(blocked_row(job, exc))


def admit_requests(store, ledger, initiatives, recipes, wait, rows):
    """Settle what is finished and refuse what cannot run, in priority order. Returns the jobs ready to run."""
    ready = []
    for initiative in initiatives:
        try:
            mailbox = Mailbox(initiative["mailbox_root"])
            records = mailbox.messages()
            requests = mailbox.open_job_requests(records)
        except ERRORS as exc:
            rows.append({"initiative": initiative["id"], "state": "mailbox_error", "error": str(exc)[:512]})
            continue
        finish_closed_jobs(store, ledger, initiative, records, {message["message_id"] for message in requests}, wait, rows)
        for message in requests:
            job = Job(store.path, initiative, message)
            existing = visit_existing(store, job, wait)
            if existing is not None:
                rows.append(existing)
                continue
            try:
                packet, raw = admit(ledger, initiative, message, mailbox, recipes)
            except ERRORS as exc:
                try:
                    rows.append(refuse(store, job, str(exc), wait))
                except ERRORS as failure:
                    rows.append(blocked_row(job, failure))
                continue
            ready.append((job, packet, raw))
    return ready


def enqueue(store, job, wait):
    def attempt():
        with store.lock():
            ledger = store.load()
            if not any(r["holder"] == job.holder and r["state"] in ("queued", "granted") for r in ledger.requests.values()):
                store.append(ledger, "request", {"request_id": "req-%08d" % (ledger.seq + 1), "initiative": job.initiative["id"],
                                                 "kind": "heavy", "holder": job.holder, "reference": job.id})

    patient(attempt, wait)


def census(store_path, ledger, fixture):
    held = ledger.held("heavy")
    if fixture is not None:
        return {"limit": ledger.limits["heavy"], "held": len(held), "external_roots": sorted(read_json(fixture)), "census": "fixture"}
    owners = set()
    for request in held:
        if request["holder"].startswith("job:"):
            claim = safe_path(Path(store_path) / "jobs" / request["holder"][4:] / "claim.json")
            if claim.exists():
                owners.add(read_json(claim)["pid"])
    return {"limit": ledger.limits["heavy"], "held": len(held), "external_roots": outside_heavy_roots(owners), "census": "proc"}


def run_heavy(store, heavy, recipes, wait, fixture, budget, rows, store_busy=False):
    """Grant in the ledger's own order, which applies the owner's priorities, until nothing more can start."""
    waiting = dict(heavy)
    held_reason = "store_busy" if store_busy else None
    capacity = None
    minimum = recipes.get("min_free_gigabytes", 0)
    while waiting and budget > 0 and not store_busy:
        if shutil.disk_usage(store.path).free < minimum * 1000000000:
            held_reason = "low_disk"
            break
        ledger = store.load()
        capacity = census(store.path, ledger, fixture)
        granted = next((holder for holder in waiting
                        if any(r["holder"] == holder and r["state"] == "granted" for r in ledger.requests.values())), None)
        if granted is None:
            if capacity["held"] + len(capacity["external_roots"]) >= capacity["limit"]:
                held_reason = "capacity_full"
                break
            try:
                code, answer = patient(lambda: grant_next(store, "heavy"), wait)
            except ValueError as exc:
                if "busy" not in str(exc):
                    raise
                held_reason = "store_busy"
                break
            if code != 0:
                held_reason = answer.get("reason", "not_granted")
                break
            granted = answer["granted"]["holder"]
            if granted not in waiting:
                rows.append({"state": "granted_elsewhere", "holder": granted, "request_id": answer["granted"]["request_id"]})
                continue
        job, packet, raw = waiting.pop(granted)
        budget -= 1
        try:
            rows.append(run_job(store, job, packet, raw, recipes, wait))
        except ERRORS as exc:
            rows.append(blocked_row(job, exc))
    for job, _, _ in waiting.values():
        row = {"job": job.id, "state": "waiting", "reason": held_reason or "job_limit"}
        if capacity is not None:
            row["capacity"] = capacity
        rows.append(row)


NEEDS_ROOT = {"waiting", "running", "abandoned", "settle_pending", "mailbox_error", "granted_elsewhere"}


def run_open(store_path, recipes_path, chosen, max_jobs, fixture, wait):
    require(type(max_jobs) is int and max_jobs > 0, "invalid max-jobs")
    recipes = load_recipes(recipes_path)
    require(Path("/proc/self/stat").exists(), "the job runner needs /proc")
    store = Store(store_path)
    ledger = store.load()
    for identifier in chosen:
        ledger.initiative(identifier)
    initiatives = sorted((i for i in ledger.initiatives.values() if i["state"] == "active" and "mailbox_root" in i
                          and (not chosen or i["id"] in chosen)), key=lambda i: (i["priority"], i["id"]))
    rows = []
    ready = admit_requests(store, ledger, initiatives, recipes, wait, rows)
    budget = max_jobs
    heavy = {}
    store_busy = False
    for job, packet, raw in ready:
        if is_heavy(recipes["recipes"][packet["recipe"]]):
            heavy[job.holder] = (job, packet, raw)
            try:
                enqueue(store, job, wait)
            except ValueError as exc:
                # Nothing has started, so this job just waits. Other work still gets done and reported.
                if "busy" not in str(exc):
                    raise
                store_busy = True
        elif budget > 0:
            budget -= 1
            try:
                rows.append(run_job(store, job, packet, raw, recipes, wait))
            except ERRORS as exc:
                rows.append(blocked_row(job, exc))
        else:
            rows.append({"job": job.id, "state": "waiting", "reason": "job_limit"})
    run_heavy(store, heavy, recipes, wait, fixture, budget, rows, store_busy)
    return (3 if any(row["state"] in NEEDS_ROOT for row in rows) else 0), {"rows": rows}


def resolve(store_path, identifier, reason, wait):
    require(isinstance(identifier, str) and JOB_ID.fullmatch(identifier) is not None, "invalid job: " + str(identifier)[:128])
    text(reason, "reason")
    initiative_id, message_id = identifier.split("/")
    store = Store(store_path)
    initiative = store.load().initiative(initiative_id)
    mailbox = Mailbox(initiative["mailbox_root"])
    record = mailbox.messages().get(message_id)
    folder = safe_path(store.path / "jobs" / initiative_id / message_id)
    require(record is not None and folder.exists(), "no running job here: " + identifier)
    job = Job(store.path, initiative, record["message"])
    require(not job.result_path.exists(), "job is already finished: " + identifier)
    require(not job.runner_alive(), "its runner is still running: " + identifier)
    group = job.process_group()
    require(not (group and group_members(group)), "its process group %s is still running; stop it first" % group)
    write_result(job, "failed", NO_VERDICT_EXIT, reason="Resolved by root: " + reason, resolved_by_root=True)
    return 0, settle(store, job, wait)


def clean(store_path, identifier):
    require(isinstance(identifier, str) and JOB_ID.fullmatch(identifier) is not None, "invalid job: " + str(identifier)[:128])
    initiative_id, message_id = identifier.split("/")
    job_folder = safe_path(Store(store_path).path / "jobs" / initiative_id / message_id)
    require(job_folder.is_dir(), "no job here: " + identifier)
    require((job_folder / "result.json").exists(), "job is not finished: " + identifier)
    job = Job(store_path, {"id": initiative_id}, {"message_id": message_id})
    return 0, {"job": identifier, "removed": remove_work_folders(job)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--store", help="Absolute path to the workspace store")
    parser.add_argument("--recipes", help="Absolute path to root's recipe file")
    parser.add_argument("--lock-wait", type=float, default=DEFAULT_LOCK_WAIT_SECONDS,
                        help="Seconds to wait for a busy mailbox or store before leaving a receipt for the next run")
    parser.add_argument("--census-fixture", help="For tests: a JSON list of PIDs that replaces the process census")
    commands = parser.add_subparsers(dest="command", required=True)
    opened = commands.add_parser("run-open", help="Run every job request that can run now")
    opened.add_argument("--initiative", action="append", default=[], help="Only this initiative; can repeat")
    opened.add_argument("--max-jobs", type=int, default=MAX_JOBS_DEFAULT)
    commands.add_parser("check-recipes", help="Validate the recipe file and summarize it")
    resolved = commands.add_parser("resolve", help="Close a job whose runner stopped, once nothing of it is running")
    resolved.add_argument("--job", required=True, help="<initiative>/<message-id>")
    resolved.add_argument("--reason", required=True)
    commands.add_parser("clean", help="Remove a finished job's work folders, keeping its logs and result").add_argument(
        "--job", required=True, help="<initiative>/<message-id>")
    commands.add_parser("source-digest", help="Print the commit, tree and uncommitted-content digest a packet needs").add_argument(
        "--checkout", required=True)
    args = parser.parse_args(argv)
    try:
        require(args.command == "source-digest" or args.store is not None, "--store is required")
        if args.command == "source-digest":
            code, result = source_digest(args.checkout)
        elif args.command == "resolve":
            code, result = resolve(args.store, args.job, args.reason, args.lock_wait)
        elif args.command == "clean":
            code, result = clean(args.store, args.job)
        else:
            require(args.recipes is not None, "--recipes is required")
            if args.command == "check-recipes":
                recipes = load_recipes(args.recipes)
                code, result = 0, {"recipes": {name: {"kind": recipe["kind"], "heavy": is_heavy(recipe),
                                                      "sandbox": recipe["sandbox"]}
                                               for name, recipe in recipes["recipes"].items()}}
            else:
                code, result = run_open(args.store, args.recipes, args.initiative, args.max_jobs, args.census_fixture, args.lock_wait)
    except ERRORS as exc:
        code, result = 2, {"error": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
