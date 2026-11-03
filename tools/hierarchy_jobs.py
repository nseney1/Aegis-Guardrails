#!/usr/bin/env python3
"""Run orchestrators' job requests through root's fixed recipes and answer each with a receipt.

Validation, commits and other physical work used to be hand-run by root from free-text requests.
This tool does the routine part. An orchestrator names a recipe and an exact source in a hash-bound
packet; root's recipe file says what that recipe runs. The argv comes only from that file, with
exact-word substitution and no shell, so nothing in a message can become a command or an option.

A job is refused unless the checkout is registered for the initiative and its revision, tree and
the bytes of its uncommitted files match the packet exactly. The source is witnessed again afterward,
so a clean exit over changed source is not reported as success. Files Git ignores are not covered.

A `merge` recipe merges one commit (`merge`) into a clean checkout's HEAD (`commit`). Like a `commit` recipe it
changes nothing until the result is checked: `git merge-tree --write-tree` must merge cleanly to exactly
`expected_tree`, then HEAD moves by compare-and-swap, and only then do the index and files follow. A second merge is
a second job. A change to any `.gitattributes` file on either side is refused; that merge goes to an integrator lane.
The orchestrator predicts `expected_tree` with the runner's pinned config and no global or system config:
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git -c merge.renames=true -c merge.directoryRenames=false \
    -c merge.renameLimit=7000 -c merge.renormalize=false merge-tree --write-tree <commit> <merge>

A heavy job takes a ledger slot, and processes the
census finds outside the ledger count against the same limit. A slot is freed only with evidence: a
lost runner leaves `unknown` and keeps the slot until root runs `resolve`.

Every result lands in `<store>/jobs/<initiative>/<message-id>/` before its receipt goes out, so a
receipt that cannot be published is retried by the next run instead of being lost.

A completed job removes its work folders, because one full test run can leave gigabytes, and keeps its
logs and result. Every job removes `cargo-target/`, a build cache that is never evidence, and a Heavy-Tests job
removes all of its work folders, failed or not. Another failed job keeps the rest until root runs `clean`,
because they may be evidence. Files a recipe names in `keep` are copied to `evidence/` before any cleanup.

A receipt is a claim with evidence references, never a verdict on the work. Bubblewrap keeps
accidents contained, but this runs under one OS user and is not a security boundary: Git inspection
of a checkout runs outside the sandbox, so a process that edits that checkout's `.git/config` could
run code there. In a bubblewrap recipe every process of the job lives in the sandbox's PID namespace and
ends with it. Under `sandbox: none` a process that starts its own session escapes the stop at the end of a step.
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
COMMAND_TOKENS = {"$python", "$paths", "$scratch", "$checkout", "$cargo_target"}
ENV_TOKENS = {"$scratch", "$checkout"}
SANDBOXES = ("bwrap", "none")
# The ledger kinds a heavy job can wait for, in the order they are granted. Each has its own limit.
HEAVY_KINDS = ("heavy", "heavy-tests")
# Cargo subcommands and aliases that compile. fmt, metadata, tree and --version stay light.
CARGO_COMPILING = {"build", "b", "test", "t", "check", "c", "run", "r", "bench", "clippy", "doc", "d", "rustc", "install",
                   "nextest", "miri"}
# The orchestrator only needs a summary; the full output stays in the evidence files.
TAIL_BYTES = 2000
EMPTY_STATUS = hashlib.sha256(b"").hexdigest()
# A result this tool decided, where no command's own exit says what happened.
NO_VERDICT_EXIT = -1
MAX_PATHS = 256
# Every step can repeat the paths, so their total is bounded to keep a result well under its write limit.
MAX_PATHS_BYTES = 65536
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
# Tagged so backup and indexing tools skip them (https://bford.info/cachedir/). Only the first line is the standard.
CACHE_FOLDERS = ("cargo-target", "ruff-cache", "hypothesis")
CACHEDIR_TAG = (b"Signature: 8a477f597d28d172789f06886806bc55\n"
                b"# This file is a cache directory tag created by the hierarchy job runner.\n"
                b"# For information about cache directory tags see https://bford.info/cachedir/\n")
# A recipe's kept files are evidence a green runner may never print, so they are copied out before cleanup.
MAX_KEEP = 16
MAX_KEEP_BYTES = 67108864
# Rename handling is pinned so the orchestrator's merge-tree prediction and the runner's merge agree. Repository-local
# config still applies under GIT_CONFIG_GLOBAL=/dev/null, so these go on the command line, where they win over it.
MERGE_CONFIG = ("merge.renames=true", "merge.directoryRenames=false", "merge.renameLimit=7000", "merge.renormalize=false")
# The built-in merge drivers as check-attr reports them: unspecified or set is text, unset is binary.
BUILT_IN_MERGE = {b"unspecified", b"set", b"unset", b"text", b"binary"}
PINNED_GIT_ENV = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
# The merge steps' view of the owner's files: no global or system config, and a HOME and XDG_CONFIG_HOME that hold
# nothing, so no global excludes or attributes. A merge's clean checks read status this way too, so a file only the owner's
# global excludes ignore counts as uncommitted there, and read-tree never meets it as a surprise after HEAD has moved.
MERGE_VIEW_ENV = {**PINNED_GIT_ENV, "HOME": os.devnull, "XDG_CONFIG_HOME": os.devnull}
HOME_FOLDERS = {"HOME": "", "USERPROFILE": "", "APPDATA": "AppData/Roaming", "LOCALAPPDATA": "AppData/Local",
                "CODEX_HOME": ".codex", "CLAUDE_CONFIG_DIR": ".claude", "XDG_CONFIG_HOME": ".config",
                "XDG_CACHE_HOME": ".cache", "XDG_DATA_HOME": ".local/share", "XDG_STATE_HOME": ".local/state",
                "CARGO_HOME": ".cargo", "PYTHONUSERBASE": ".local"}


def checked_words(words, allowed, label):
    for word in words:
        # Exact words only: no recipe or packet value is ever formatted into a larger argument.
        require(isinstance(word, str) and word and "\0" not in word, "invalid word in " + label)
        require("$" not in word or word in allowed, "unsupported token in " + label + ": " + word)


def cargo_step(words):
    """A step that compiles Rust: rustc itself, or cargo with a subcommand that builds. Only the step's own program
    and subcommand are read, so a script that runs cargo inside it is not seen. Returns what it matched, else None."""
    if not words:
        return None
    name = Path(words[0]).name
    if name == "rustc":
        return name
    if name != "cargo":
        return None
    subcommand = next((word for word in words[1:] if not word.startswith(("-", "+"))), None)
    return name + " " + subcommand if subcommand in CARGO_COMPILING else None


def validate_recipe(name, recipe):
    matching(name, SLUG, "recipe name")
    require(isinstance(recipe, dict) and recipe.get("kind") in ("command", "commit", "merge"), "invalid kind for recipe " + name)
    integer(recipe.get("timeout_seconds"), "timeout_seconds", maximum=MAX_TIMEOUT_SECONDS)
    require(recipe.get("sandbox") in SANDBOXES, "invalid sandbox for recipe " + name)
    if recipe["kind"] in ("commit", "merge"):
        fields(recipe, {"kind", "timeout_seconds", "sandbox"})
        return
    fields(recipe, {"kind", "timeout_seconds", "sandbox", "heavy", "steps"}, {"writable_checkout", "heavy_tests", "keep"})
    keep = recipe.get("keep", [])
    require(isinstance(keep, list) and len(keep) <= MAX_KEEP, "invalid keep for recipe %s: at most %d paths" % (name, MAX_KEEP))
    for entry in keep:
        # Relative to scratch/ and plain, so a kept path can neither leave scratch nor name it twice.
        require(isinstance(entry, str) and "\0" not in entry and all(part not in ("", ".", "..") for part in entry.split("/")),
                "invalid keep for recipe %s: %s" % (name, str(entry)[:256]))
    require(type(recipe["heavy"]) is bool, "invalid heavy flag for recipe " + name)
    require(type(recipe.get("writable_checkout", False)) is bool, "invalid writable_checkout for recipe " + name)
    require(type(recipe.get("heavy_tests", False)) is bool, "invalid heavy_tests flag for recipe " + name)
    # Heavy-Tests is a heavy slot of its own, so a recipe that is light cannot claim it.
    require(recipe["heavy"] or not recipe.get("heavy_tests", False), "heavy_tests needs heavy for recipe " + name)
    steps = recipe["steps"]
    require(isinstance(steps, list) and 0 < len(steps) <= MAX_STEPS and all(isinstance(step, list) and step for step in steps),
            "invalid steps for recipe " + name)
    for number, step in enumerate(steps, 1):
        checked_words(step, COMMAND_TOKENS, "recipe " + name)
        # Cargo fills gigabytes and saturates the machine, so the owner allows it only in the single Heavy-Tests slot.
        compiles = cargo_step(step)
        require(not compiles or recipe.get("heavy_tests", False),
                "recipe %s step %d runs a cargo build or test (%s), which only a heavy_tests recipe may run"
                % (name, number, compiles))


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
    if any(recipe["kind"] in ("commit", "merge") for recipe in table.values()):
        identity = recipes.get("identity")
        require(isinstance(identity, dict), "a commit or merge recipe needs an identity")
        fields(identity, {"name", "email"})
        text(identity["name"], "identity name", 256)
        text(identity["email"], "identity email", 256)
    return recipes


def is_heavy(recipe):
    return recipe.get("heavy", False)


def job_kind(recipe):
    """The ledger kind a heavy job waits for. Cargo has the single Heavy-Tests slot; other test jobs share heavy."""
    return "heavy-tests" if recipe.get("heavy_tests", False) else "heavy"


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
    takes_paths = commit or (recipe["kind"] == "command" and any("$paths" in step for step in recipe["steps"]))
    if not takes_paths:
        require(not paths, "this recipe takes no paths")
        return []
    require(isinstance(paths, list) and bool(paths), "this recipe needs paths")
    require(len(paths) <= MAX_PATHS, "too many paths")
    require(len(json.dumps(paths)) <= MAX_PATHS_BYTES, "paths are too long together: the limit is %d bytes" % MAX_PATHS_BYTES)
    for path in paths:
        require(isinstance(path, str) and PATH_ARGUMENT.fullmatch(path) is not None, "invalid path: " + str(path))
        name, _, selector = path.partition("::")
        require(".." not in name.split("/") and not (commit and selector), "invalid path: " + path)
        # A commit may name a deleted file. Tests must exist, so a typo reads as a refusal and not a failed run.
        require(commit or (Path(checkout) / name).exists(), "path does not exist in the checkout: " + name)
    return paths


def path_fingerprint(path, name):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return b"absent"
    if stat.S_ISLNK(info.st_mode):
        return b"link:" + os.fsencode(os.readlink(path))
    if not stat.S_ISREG(info.st_mode):
        # A constant here would let any content behind the entry, such as a nested repository, pass as the same source.
        raise ValueError("cannot witness %s byte for byte: only regular files and symlinks can be witnessed, so nested "
                         "repositories, submodules and special files are not supported" % os.fsdecode(name)[:512])
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            digest.update(chunk)
    return b"file:" + (b"x" if info.st_mode & 0o111 else b"-") + b":" + digest.hexdigest().encode()


def refuse_submodules(checkout, revisions=()):
    """A submodule's bytes and revision live in another repository, and the parent's status shows the same ` M sub`
    for any of them, while a clean or uninitialized one shows nothing. None can be bound to a packet, so all are
    refused by path. The submodule itself is never read, so nothing outside the checkout is followed. A merge also
    names commits that are not checked out, so their trees are read as well."""
    listed = subprocess.run(["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "ls-files", "--stage", "-z"],
                            cwd=checkout, capture_output=True, timeout=120)
    require(listed.returncode == 0, "could not read the index of " + str(checkout))
    gitlinks = [entry.partition(b"\t")[2] for entry in listed.stdout.split(b"\0") if entry.startswith(b"160000 ")]
    for revision in revisions:
        tree = subprocess.run(["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "ls-tree", "-r", "-z", "--full-tree",
                               revision], cwd=checkout, capture_output=True, timeout=120)
        require(tree.returncode == 0, "could not read the tree of " + revision)
        gitlinks += [entry.partition(b"\t")[2] for entry in tree.stdout.split(b"\0") if entry.startswith(b"160000 ")]
    require(not gitlinks, "submodules are not supported, because their content cannot be witnessed byte for byte: "
            + ", ".join(sorted({os.fsdecode(path) for path in gitlinks}))[:1024])


def pinned_git(checkout, *args, stdin=None):
    """A read with the config the merge steps see, so what admit refuses and what the merge does agree."""
    return subprocess.run(["git", "--no-optional-locks", "-c", "core.fsmonitor=false", *args], cwd=checkout, input=stdin,
                          env={**os.environ, **PINNED_GIT_ENV}, capture_output=True, timeout=120)


def refuse_attributes(checkout, paths, revisions):
    """A filter (LFS and the like) runs outside Git's merge and would run again on checkout, and a merge driver other than
    the built-in text or binary, union included, can turn a conflict into a result that looks clean. Each path is read as
    each side's own attributes describe it, because either side can add the attribute."""
    if not paths:
        return
    flagged = set()
    for revision in revisions:
        found = pinned_git(checkout, "check-attr", "-z", "--stdin", "--source", revision, "filter", "merge",
                           stdin=b"".join(path + b"\0" for path in paths))
        require(found.returncode == 0, "could not read the attributes of the paths the merge changes")
        parts = found.stdout.split(b"\0")
        for index in range(0, len(parts) - 2, 3):
            path, name, value = parts[index:index + 3]
            if (name == b"filter" and value not in (b"unspecified", b"unset")) or (name == b"merge" and value not in BUILT_IN_MERGE):
                flagged.add("%s (%s=%s)" % (os.fsdecode(path), name.decode(), value.decode(errors="replace")))
    require(not flagged, "a merge job refuses changed paths with a filter attribute or a merge attribute other than the "
            "built-in text or binary: " + ", ".join(sorted(flagged))[:1024])


def merge_refusals(checkout, commit, merge):
    """J2's refusals that Git objects, attributes and config alone decide, before a merge job runs. `commit` is HEAD by now."""
    # An unspecified merge attribute uses merge.default, and a configured driver named text or binary wins over the
    # built-in one, so either brings back the union or custom-driver merge the attribute check below refuses.
    configured = pinned_git(checkout, "config", "--get-regexp", r"^merge\.(default|.+\.driver)$")
    require(configured.returncode in (0, 1), "could not read the merge config")
    keys = sorted({line.partition(" ")[0] for line in configured.stdout.decode(errors="replace").splitlines() if line})
    require(not keys, "a merge job refuses merge.default and merge.<driver>.driver in the repository's config, because they "
            "can merge a changed path by union or by a command; send this merge to an integrator lane: " + ", ".join(keys)[:1024])
    found = pinned_git(checkout, "rev-parse", "--verify", "--quiet", "--end-of-options", merge + "^{commit}")
    require(found.returncode == 0 and found.stdout.decode().strip() == merge, "merge %s is not a commit in this repository" % merge)
    contained = pinned_git(checkout, "merge-base", "--is-ancestor", merge, commit)
    require(contained.returncode in (0, 1), "could not tell whether merge is already in commit")
    require(contained.returncode == 1, "merge %s is already contained in commit %s, so it would make no change" % (merge, commit))
    found = pinned_git(checkout, "merge-base", "--all", commit, merge)
    bases = found.stdout.decode().split()
    require(found.returncode in (0, 1), "could not find the merge base")
    require(bool(bases), "commit and merge have no merge base: unrelated histories are not merged")
    refuse_submodules(checkout, (commit, merge))
    changed = set()
    for base in bases:
        for side in (commit, merge):
            listed = pinned_git(checkout, "diff-tree", "-r", "-z", "--name-only", "--no-renames", base, side)
            require(listed.returncode == 0, "could not list the paths changed on either side")
            changed.update(name for name in listed.stdout.split(b"\0") if name)
    refuse_attributes(checkout, sorted(changed), (commit, merge))
    # A .gitattributes change can give a filter or merge driver to paths neither side changed, which the per-path check
    # above never reads; the merge would run, and only the post-run check would catch it, after HEAD had moved.
    edited = sorted({os.fsdecode(name) for name in changed if name.rsplit(b"/", 1)[-1] == b".gitattributes"})
    require(not edited, "a merge job refuses any .gitattributes change on either side, because it can change how paths "
            "neither side changed are filtered or merged; send this merge to an integrator lane: " + ", ".join(edited)[:1024])


def uncommitted_content(checkout, view=None):
    """Git status names the paths that differ, not their bytes, so one status can hide different content. `view` overrides
    part of the environment, as a merge's checks do to read status the way its steps do."""
    status = subprocess.run(["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
                            cwd=checkout, env={**os.environ, **view} if view else None, capture_output=True, timeout=120)
    require(status.returncode == 0, "could not read the status of " + str(checkout))
    refuse_submodules(checkout)
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
            digest.update(name + b"\0" + path_fingerprint(os.path.join(os.fsencode(checkout), name), name) + b"\0")
    return digest.hexdigest(), count


def source_state(mailbox, checkout, view=None):
    return {**mailbox.source_witness(checkout), "dirty_content_sha256": uncommitted_content(checkout, view)[0]}


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
           {"dirty_content_sha256", "paths", "expected_tree", "message", "merge"})
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
    kind = recipe["kind"]
    if kind in ("commit", "merge"):
        require("expected_tree" in packet and "message" in packet, "a %s recipe needs expected_tree and message" % kind)
        matching(packet["expected_tree"], GIT_ID, "expected_tree")
        text(packet["message"], "commit message", 65536)
    else:
        require("expected_tree" not in packet and "message" not in packet,
                "only a commit recipe or a merge recipe takes expected_tree or message")
    require(kind == "merge" or "merge" not in packet, "only a merge recipe takes merge")
    if kind == "commit":
        require(packet["expected_tree"] != packet["tree"], "this commit would make no change")
        code, overlap = check_paths(ledger, initiative["id"], paths)
        require(code == 0, "paths overlap another lease or a checkout could not be read: " + json.dumps(
            overlap["conflicts"] + overlap["unreadable_checkouts"], sort_keys=True)[:1024])
    if kind == "merge":
        # A merge whose tree equals HEAD's still records the other history, so only merge == commit counts as no change.
        require("merge" in packet, "a merge recipe needs merge: the commit to merge")
        matching(packet["merge"], GIT_ID, "merge")
        require(packet["merge"] != packet["commit"], "merge equals commit, so it would make no change")
        # Clean before, so that afterward the checkout can be compared with exactly the merged tree.
        count = uncommitted_content(checkout, MERGE_VIEW_ENV)[1]
        require(count == 0, "a merge needs a clean worktree, and this one has %d uncommitted entries, read as the merge steps "
                "read them: without the owner's global excludes" % count)
        require(dirty == EMPTY_STATUS, "a merge needs a clean worktree, so dirty_content_sha256 must be the empty digest")
    require(recipe["sandbox"] == "none" or shutil.which("bwrap") is not None,
            "this recipe needs bubblewrap, which is not available")
    witness = source_state(mailbox, checkout, MERGE_VIEW_ENV if kind == "merge" else None)
    require((witness["source_revision"], witness["source_tree"], witness["dirty_content_sha256"]) ==
            (packet["commit"], packet["tree"], dirty), "source does not match the packet")
    if kind == "merge":
        merge_refusals(checkout, packet["commit"], packet["merge"])
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


def census_command(words, kind):
    """Root's census rule for one ledger kind, which root's own controller must apply the same way: the test slots
    (`heavy`) count the pytest family, and Heavy-Tests counts cargo builds and tests and rustc."""
    if kind == "heavy-tests":
        return cargo_step(words) is not None
    if not words:
        return False
    name = Path(words[0]).name
    if name in ("pytest", "py.test"):
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


def outside_roots(owners, kind):
    """Topmost processes of this kind that no running job of this ledger started."""
    parents, heavy = {}, set()
    for item in Path("/proc").glob("[0-9]*/cmdline"):
        pid = int(item.parent.name)
        try:
            words = [word.decode(errors="replace") for word in item.read_bytes().split(b"\0") if word]
            parents[pid] = int((item.parent / "stat").read_text(encoding="ascii", errors="replace")
                               .rpartition(")")[2].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        if census_command(words, kind):
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
        """Read with the same limit it was written with, or a valid large result could never be settled."""
        if not self.result_path.exists():
            return None
        info = os.lstat(self.result_path)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_RESULT_BYTES, "result is not a readable file within its limit")
        return strict_json(self.result_path.read_bytes().decode("utf-8"))

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

    def process_record(self):
        try:
            record = read_json(self.process_path)
        except (ValueError, OSError):
            return None
        return record if isinstance(record, dict) else None

    def process_group(self):
        return (self.process_record() or {}).get("group")

    def unrecorded_step(self):
        """The latest step that may have started while its own group is not on record, else None.

        A step's launch is recorded before its log is opened and its process started, and its group once it runs. A
        record naming an earlier step, or this step without a group, means the runner was lost in between, and an
        earlier step's stopped group says nothing about whether this one still runs."""
        numbers = [int(path.name[5:-4]) for path in self.folder.glob("step-*.log") if path.name[5:-4].isdigit()]
        latest = max(numbers, default=0)
        record = self.process_record()
        if not latest:
            return None
        if record is None or not isinstance(record.get("step"), int) or record["step"] < latest:
            return latest
        if record["step"] == latest and not record.get("group"):
            return latest
        # A later recorded launch whose log was never opened never started, and its earlier steps were confirmed stopped.
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
    missed = ["%s (%s)" % (item["path"], item["error"]) for item in result.get("kept", []) if "error" in item]
    if missed:
        lines.append("Kept files not copied: " + "; ".join(missed))
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


def remove_work_folders(job, names=WORK_FOLDERS):
    """Logs and the result are the evidence, and they stay."""
    removed = []
    for name in names:
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


def copy_kept(source, target):
    """Copies at most the keep limit plus one byte, so a file that grew past its listed size is caught, not cut."""
    digest, size = hashlib.sha256(), 0
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(os.open(source, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream, open(target, "xb") as out:
        for chunk in iter(lambda: stream.read(1048576), b""):
            size += len(chunk)
            if size > MAX_KEEP_BYTES:
                break
            digest.update(chunk)
            out.write(chunk)
    return digest.hexdigest(), size


def keep_evidence(job, keep):
    """Copy each kept file out of scratch/ into evidence/ before any cleanup. Each one that cannot be kept is reported."""
    scratch = os.path.realpath(job.folder / "scratch")
    rows, total = [], 0
    for entry in keep:
        source, target = os.path.join(scratch, entry), job.folder / "evidence" / entry
        try:
            info = os.lstat(source)
        except (FileNotFoundError, NotADirectoryError):
            rows.append({"path": entry, "error": "missing"})
            continue
        except OSError as exc:
            rows.append({"path": entry, "error": str(exc)[:256]})
            continue
        # A symlink, or a parent that is one, could point anywhere, so only a regular file truly inside scratch counts.
        if not stat.S_ISREG(info.st_mode) or not os.path.realpath(source).startswith(scratch + os.sep):
            rows.append({"path": entry, "error": "not a regular file inside scratch"})
            continue
        if total + info.st_size > MAX_KEEP_BYTES:
            rows.append({"path": entry, "bytes": info.st_size,
                         "error": "over the keep limit of %d bytes together" % MAX_KEEP_BYTES})
            continue
        try:
            sha256, size = copy_kept(source, target)
        except OSError as exc:
            rows.append({"path": entry, "error": "could not copy: " + str(exc)[:256]})
            continue
        if total + size > MAX_KEEP_BYTES:
            target.unlink()
            rows.append({"path": entry, "error": "over the keep limit of %d bytes together" % MAX_KEEP_BYTES})
            continue
        total += size
        rows.append({"path": entry, "sha256": sha256, "bytes": size, "copy": str(target)})
    return rows


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
    # process group is what lets the stop at the end of a step reach every child. A child that calls
    # setsid leaves that group, so the PID namespace is what takes it down: when the stop ends bwrap,
    # --die-with-parent ends the namespace's first process and the kernel ends every other one in it.
    argv = [bwrap, "--die-with-parent", "--unshare-net", "--unshare-pid", "--ro-bind", "/", "/", "--tmpfs", "/tmp"]
    for folder in recipes.get("hide", []):
        argv += ["--tmpfs", folder]
    argv += ["--dev", "/dev", "--proc", "/proc"]
    for folder in recipes.get("ro_binds", []):
        argv += ["--ro-bind", folder, folder]
    writes_git = recipe["kind"] in ("commit", "merge")
    # A merge brings the working tree forward itself, so it writes the checkout as well as the Git data.
    argv += ["--bind" if recipe.get("writable_checkout") or recipe["kind"] == "merge" else "--ro-bind", checkout, checkout]
    for folder in git_folders(checkout):
        argv += ["--bind" if writes_git else "--ro-bind", folder, folder]
    # The job folder itself stays read-only inside, so a job cannot write its own result, claim or logs.
    argv += ["--ro-bind", str(job.folder), str(job.folder)]
    for name in WORK_FOLDERS:
        argv += ["--bind", str(job.folder / name), str(job.folder / name)]
    return argv + ["--chdir", checkout, "--"]


def scratch_argument(job):
    # Below the bound folder, because pytest removes and recreates --basetemp, and a mount point cannot be removed.
    return str(job.folder / "scratch" / "run")


def cargo_target(job):
    """One path for both CARGO_TARGET_DIR and $cargo_target, so a runner's --target-dir never splits the cache."""
    return str(job.folder / "cargo-target")


def job_environment(recipes, job, checkout):
    for name in WORK_FOLDERS:
        (job.folder / name).mkdir(mode=0o700, exist_ok=True)
    for name in CACHE_FOLDERS:
        (job.folder / name / "CACHEDIR.TAG").write_bytes(CACHEDIR_TAG)
    home = job.folder / "home"
    scratch_tmp = job.folder / "tmp"
    env = {"PATH": os.pathsep.join(recipes["path"]), "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONNOUSERSITE": "1", "GIT_OPTIONAL_LOCKS": "0", "TMP": str(scratch_tmp), "TEMP": str(scratch_tmp),
           "TMPDIR": str(scratch_tmp),
           # These tools otherwise write beside the source, and a job usually cannot write there.
           "CARGO_TARGET_DIR": cargo_target(job), "RUFF_CACHE_DIR": str(job.folder / "ruff-cache"),
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
    def __init__(self, argv, env=None, capture=False, verdict=False):
        # A verdict step's exit is the plan's to judge: it receives (exit code, output), so a non-zero exit can halt the
        # job with a reason of its own, such as the conflicted paths, instead of a bare exit code. Its output is the
        # captured stdout, or else its log, so that reason can quote git's own error.
        self.argv, self.env, self.capture, self.verdict = argv, env or {}, capture, verdict


class Halt(Exception):
    """A recipe's own check failed, so later steps must not run and nothing further should change."""


class StillRunning(Exception):
    """A step's processes could not be confirmed stopped, so the job must keep its slot and get no result."""

    def __init__(self, group, reason):
        super().__init__("process group %d may still be running: %s" % (group, reason))
        self.group = group


def stop_for_certain(process):
    try:
        stop_group(process)
    except (OSError, subprocess.SubprocessError) as exc:
        raise StillRunning(process.pid, str(exc)[:512]) from exc
    if group_members(process.pid):
        raise StillRunning(process.pid, "members were left after the stop")


def command_steps(recipe, packet, recipes, job):
    tokens = {"$python": [recipes["python"]], "$paths": packet["paths"], "$scratch": [scratch_argument(job)],
              "$checkout": [packet["checkout"]], "$cargo_target": [cargo_target(job)]}
    for step in recipe["steps"]:
        yield Step([part for word in step for part in tokens.get(word, [word])])
    return None


def git_error(output):
    """Git's own words from a step, on one bounded line, for a reason."""
    return " ".join((output or "").split())[:1024] or "no output"


def put_back(git, env, job, old, new, failed, code, output):
    """A step past the swap failed, so HEAD goes back by compare-and-swap, and the reason says whether it did."""
    restored, _ = yield Step(git + ["update-ref", "-m", "hierarchy job %s: put back" % job.id, "HEAD", old, new], env, verdict=True)
    outcome = ("HEAD was restored to %s by compare-and-swap" % old if restored == 0 else
               "HEAD was not restored: the compare-and-swap back to %s failed (exit %d)" % (old, restored))
    raise Halt("%s failed after HEAD moved to %s (exit %d): %s. %s." % (failed, new, code, git_error(output), outcome))


def commit_steps(packet, recipes, job, details):
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
    commit = details["new_commit"] = yield Step(git + ["commit-tree", tree, "-p", packet["commit"], "-F", str(message_file)],
                                                plain, capture=True)
    # The old value makes this a compare-and-swap, so a lane committing in between cannot be overwritten.
    yield Step(git + ["update-ref", "-m", "hierarchy job " + job.id, "HEAD", commit, packet["commit"]], plain)
    code, output = yield Step(git + ["add", "--", *packet["paths"]], plain, verdict=True)
    if code != 0:
        yield from put_back(git, plain, job, packet["commit"], commit, "git add on the real index", code, output)
    return commit


def merge_steps(packet, recipes, job, details):
    """Like commit_steps: the merged tree is checked before any ref moves, HEAD moves by compare-and-swap, and only then
    do the index and files follow. Before the swap, git writes objects only: merge-tree and commit-tree write new objects,
    and the dry run reads the real index and files without writing them. If read-tree then fails, HEAD goes back."""
    identity = recipes["identity"]
    git = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false",
           "-c", "user.name=" + identity["name"], "-c", "user.email=" + identity["email"]]
    plain = {"GIT_LITERAL_PATHSPECS": "1", **PINNED_GIT_ENV}
    temporary = {**plain, "GIT_INDEX_FILE": str(job.folder / "scratch" / "index")}
    commit, merge = packet["commit"], packet["merge"]
    message_file = job.folder / "scratch" / "commit-message"
    message_file.parent.mkdir(mode=0o700, exist_ok=True)
    message_file.write_text(packet["message"], encoding="utf-8")
    details["merge_bases"] = (yield Step(git + ["merge-base", "--all", commit, merge], temporary, capture=True)).split()
    pinned = [part for item in MERGE_CONFIG for part in ("-c", item)]
    code, output = yield Step(git + pinned + ["merge-tree", "--write-tree", commit, merge], temporary, capture=True, verdict=True)
    lines = output.splitlines()
    # A clean merge prints its tree and nothing else. A conflicted one exits 1 and still writes a tree, with markers in
    # it, so a packet that copied that tree is refused here too.
    if code != 0 or len(lines) != 1 or GIT_ID.fullmatch(lines[0]) is None or "CONFLICT" in output:
        conflicted = sorted({line.partition("\t")[2] for line in lines[1:] if "\t" in line})
        notes = " ".join(line for line in lines if line.startswith("CONFLICT"))
        raise Halt("merge-tree did not merge cleanly (exit %d), so nothing was changed; conflicted paths: %s. %s"
                   % (code, ", ".join(conflicted) or "none listed", notes))
    tree = details["tree"] = lines[0]
    listing = yield Step(git + ["ls-tree", "-r", "--full-tree", tree], temporary, capture=True)
    gitlinks = [line.partition("\t")[2] for line in listing.splitlines() if line.startswith("160000 ")]
    if gitlinks:
        raise Halt("the merged tree has submodules, which are not supported: " + ", ".join(gitlinks)[:1024])
    if tree != packet["expected_tree"]:
        raise Halt("the merged tree %s is not the expected tree %s" % (tree, packet["expected_tree"]))
    # On the real index and files, so a held index.lock or an untracked file at a path the merge adds is refused while
    # nothing has moved. One that appears after this is met past the swap, below.
    code, output = yield Step(git + ["read-tree", "-n", "-m", "-u", commit, tree], plain, verdict=True)
    if code != 0:
        raise Halt("a dry run of read-tree refused to bring the index and files to the merge (exit %d), so HEAD, the index "
                   "and the files were not changed: %s" % (code, git_error(output)))
    created = yield Step(git + ["commit-tree", tree, "-p", commit, "-p", merge, "-F", str(message_file)], plain, capture=True)
    details["new_commit"] = created
    code, _ = yield Step(git + ["update-ref", "-m", "hierarchy job " + job.id, "HEAD", created, commit], plain, verdict=True)
    if code != 0:
        raise Halt("the compare-and-swap of HEAD from %s failed (exit %d): another writer moved HEAD or held its lock, "
                   "and the index and files were not touched" % (commit, code))
    code, output = yield Step(git + ["read-tree", "-m", "-u", commit, created], plain, verdict=True)
    if code != 0:
        yield from put_back(git, plain, job, commit, created, "read-tree", code, output)
    return created


def record_process(job, record, suffix):
    """Replaced whole, so a reader sees the earlier record or the new one, never part of either."""
    temporary = job.process_path.with_suffix(suffix)
    temporary.write_bytes(encoded(record))
    temporary.replace(job.process_path)


def run_step(job, number, step, sandbox, env, checkout, deadline, on_start, prefix):
    log_path = job.folder / ("step-%d.log" % number)
    out_path = job.folder / ("step-%d.out" % number)
    argv = prefix + sandbox + step.argv
    began = time.monotonic()
    row = {"argv": step.argv, "exit_code": None, "timed_out": False, "stopped_leftovers": False}
    # On record before anything starts, so a runner lost at any later moment leaves a record naming this step rather
    # than the previous step's stopped group. If this cannot be written, the step does not start.
    launch = {"step": number, "group": None, "at": timestamp()}
    record_process(job, launch, ".intent")
    with open(log_path, "xb") as log, open(out_path, "xb") if step.capture else open(os.devnull, "wb") as out:
        process = subprocess.Popen(argv, cwd=checkout, env={**env, **step.env}, stdin=subprocess.DEVNULL,
                                   stdout=out if step.capture else log, stderr=log, start_new_session=True)
    try:
        # Everything after the launch is guarded: a process must never outlive a job that is reported over.
        record_process(job, {**launch, "group": process.pid, "start": process_start(process.pid), "at": timestamp()},
                       ".pending")
        on_start()
        remaining = max(0.0, deadline - time.monotonic())
        try:
            process.wait(timeout=remaining)
            row["stopped_leftovers"] = bool(group_members(process.pid))
        except subprocess.TimeoutExpired:
            row["timed_out"] = True
    except BaseException:
        stop_for_certain(process)
        raise
    stop_for_certain(process)
    row["exit_code"] = process.returncode
    row["seconds"] = round(time.monotonic() - began, 3)
    source = out_path if step.capture else log_path if step.verdict else None
    return row, source.read_text(encoding="utf-8", errors="replace").strip() if source else None


def execute(job, recipe, packet, recipes, on_start, details):
    checkout = packet["checkout"]
    env = job_environment(recipes, job, checkout)
    sandbox = sandbox_prefix(recipes, recipe, job, checkout)
    prefix = list(recipes.get("prefix", []))
    deadline = time.monotonic() + recipe["timeout_seconds"]
    if recipe["kind"] == "commit":
        plan = commit_steps(packet, recipes, job, details)
    elif recipe["kind"] == "merge":
        plan = merge_steps(packet, recipes, job, details)
    else:
        plan = command_steps(recipe, packet, recipes, job)
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
            if step.verdict:
                step = plan.send((row["exit_code"], output))
                continue
            if row["exit_code"] != 0:
                reason, exit_code = "step %d exited %d" % (len(rows), row["exit_code"]), row["exit_code"]
                break
            step = plan.send(output)
    except StopIteration as stop:
        created = stop.value
    except Halt as halt:
        reason, exit_code = str(halt), NO_VERDICT_EXIT
    return rows, reason, exit_code, created


def checkout_state(checkout, commit, created, view):
    """Where a commit or merge left the checkout once HEAD may have moved: what HEAD names, which tree the index holds,
    and how many entries status shows against HEAD."""
    try:
        found = pinned_git(checkout, "rev-parse", "--verify", "--quiet", "HEAD")
        head = found.stdout.decode().strip() if found.returncode == 0 else "nothing readable"
        role = {commit: "the packet's commit", created: "the new commit"}.get(head, "neither the packet's commit nor the new one")
        index = next((name for revision, name in ((created, "the new commit"), (commit, "the packet's commit"))
                      if pinned_git(checkout, "diff-index", "--cached", "--quiet", revision, "--").returncode == 0), "neither commit")
        count = uncommitted_content(checkout, view)[1]
    except ERRORS as exc:
        return "The checkout's state could not be read afterward: " + str(exc)[:512]
    return ("Afterward HEAD names %s (%s), the index holds the tree of %s, and status shows %d uncommitted entries against "
            "HEAD." % (head, role, index, count))


def run_job(store, job, packet, packet_raw, recipes, wait):
    recipe = recipes["recipes"][packet["recipe"]]
    if not job.claim(packet_raw):
        return {"job": job.id, "state": "running", "process_group": job.process_group()}
    mailbox = Mailbox(job.initiative["mailbox_root"])
    checkout = packet["checkout"]
    view = MERGE_VIEW_ENV if recipe["kind"] == "merge" else None
    try:
        before = source_state(mailbox, checkout, view)
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

    details = {}
    try:
        rows, reason, exit_code, created = execute(job, recipe, packet, recipes, announce, details)
    except StillRunning as exc:
        # Without a confirmed stop there is no honest result, so the job keeps its slot until root resolves it.
        row = {"job": job.id, "state": "abandoned", "process_group": exc.group, "process_alive": True, "error": str(exc)}
        if details.get("new_commit"):
            row["checkout_state"] = checkout_state(checkout, packet["commit"], details["new_commit"], view)
        return row
    except ERRORS as exc:
        rows, reason, exit_code, created = [], "the job could not run: " + str(exc)[:2048], NO_VERDICT_EXIT, None
    try:
        after = source_state(mailbox, checkout, view)
    except ERRORS as exc:
        # Without this the job would have no result, and so no receipt, and would hold its slot.
        after = None
        reason = reason or "could not witness the source afterward: " + str(exc)[:2048]
        exit_code = exit_code or NO_VERDICT_EXIT
    if not reason:
        if recipe["kind"] in ("commit", "merge"):
            if (after["source_revision"], after["source_tree"]) != (created, packet["expected_tree"]):
                reason, exit_code = "the checkout does not show the new commit afterward", NO_VERDICT_EXIT
            elif recipe["kind"] == "merge" and after["dirty_content_sha256"] != EMPTY_STATUS:
                reason, exit_code = "the worktree is not clean after the merge", NO_VERDICT_EXIT
        elif after != before:
            reason, exit_code = "source changed during the job, so its exit proves nothing", NO_VERDICT_EXIT
    moved = details.get("new_commit")
    if reason and moved:
        # Once the swap may have run, "failed" no longer means "untouched", so the reason says where everything is.
        reason += " " + checkout_state(checkout, packet["commit"], moved, view)
    if not reason:
        commit = created
    else:
        commit = moved if after is not None and moved and after["source_revision"] == moved else None
    extra = {"kept": keep_evidence(job, recipe["keep"])} if recipe.get("keep") else {}
    if recipe["kind"] == "merge":
        # Every input and the pinned config, so the receipt binds them and anyone can predict the tree again.
        extra["merge"] = {"commit": packet["commit"], "merge": packet["merge"], "merge_bases": details.get("merge_bases"),
                          "expected_tree": packet["expected_tree"], "tree": details.get("tree"),
                          "new_commit": details.get("new_commit"), "config": list(MERGE_CONFIG)}
    write_result(job, "failed" if reason else "completed", exit_code if reason else 0, reason=reason, recipe=packet["recipe"],
                 steps=rows, before=before, after=after, commit=commit, **extra)
    # A build cache is never evidence, and a cargo job's can be gigabytes, so Heavy-Tests leaves nothing behind. Other
    # failed jobs keep the rest of their work for diagnosis until root runs clean.
    names = WORK_FOLDERS if not reason or recipe.get("heavy_tests", False) else ("cargo-target",)
    removed, cleanup_error = [], None
    for name in names:
        try:
            removed += remove_work_folders(job, (name,))
        except OSError as exc:
            # The result stands either way, so this only tells root that space was not freed.
            cleanup_error = cleanup_error or str(exc)[:512]
    row = settle(store, job, wait)
    row["removed"] = removed
    kept = [name for name in WORK_FOLDERS if (job.folder / name).exists()]
    if kept:
        row["work_kept"] = kept
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
    unrecorded = job.unrecorded_step()
    try:
        publish_receipt(job, "unknown", "Job %s has no result: its runner stopped before reporting. Root must "
                        "resolve it." % job.id, wait, reason="the runner stopped before the job reported an exit")
    except ERRORS as exc:
        return blocked_row(job, exc)
    row = {"job": job.id, "state": "abandoned", "process_group": group, "process_alive": alive}
    if unrecorded and not alive:
        # Unknown, not stopped: the step that may still run was never recorded.
        row.update(process_alive=None, unrecorded_step=unrecorded)
    return row


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


def enqueue(store, job, kind, wait):
    def attempt():
        with store.lock():
            ledger = store.load()
            if not any(r["holder"] == job.holder and r["state"] in ("queued", "granted") for r in ledger.requests.values()):
                store.append(ledger, "request", {"request_id": "req-%08d" % (ledger.seq + 1), "initiative": job.initiative["id"],
                                                 "kind": kind, "holder": job.holder, "reference": job.id})

    patient(attempt, wait)


def fixture_roots(fixture, kind):
    """For tests: a list of PIDs, or {"external_roots": ..., "delay_seconds": n} to make the census take time like a
    real one. external_roots is a list, or an object of lists by kind; a bare list counts against heavy only."""
    data = read_json(fixture)
    if isinstance(data, list):
        return sorted(data) if kind == "heavy" else []
    fields(data, {"external_roots"}, {"delay_seconds"})
    delay = data.get("delay_seconds", 0)
    require(isinstance(delay, (int, float)) and 0 <= delay <= 5, "invalid delay_seconds")
    time.sleep(delay)
    roots = data["external_roots"]
    if isinstance(roots, list):
        roots = {"heavy": roots}
    require(isinstance(roots, dict), "invalid census fixture")
    unknown = sorted(set(roots) - set(HEAVY_KINDS))
    require(not unknown, "unknown census fixture kind: " + ", ".join(unknown)[:256])
    return sorted(roots.get(kind, []))


def census(store_path, ledger, fixture, kind):
    held = ledger.held(kind)
    if fixture is not None:
        return {"limit": ledger.limits[kind], "held": len(held), "external_roots": fixture_roots(fixture, kind),
                "census": "fixture"}
    owners = set()
    # Whatever any running job of this ledger started is its own work, not outside work, whichever kind it holds.
    for request in [r for name in HEAVY_KINDS for r in ledger.held(name)]:
        if request["holder"].startswith("job:"):
            claim = safe_path(Path(store_path) / "jobs" / request["holder"][4:] / "claim.json")
            if claim.exists():
                owners.add(read_json(claim)["pid"])
    return {"limit": ledger.limits[kind], "held": len(held), "external_roots": outside_roots(owners, kind), "census": "proc"}


def run_heavy(store, heavy, recipes, wait, fixture, budget, rows, store_busy=False):
    """Each kind is a slot class of its own, so one kind being full never holds the other. Returns the budget left."""
    for kind in HEAVY_KINDS:
        waiting = {holder: entry for holder, entry in heavy.items()
                   if job_kind(recipes["recipes"][entry[1]["recipe"]]) == kind}
        budget = run_kind(store, kind, waiting, recipes, wait, fixture, budget, rows, store_busy)
    return budget


def run_kind(store, kind, waiting, recipes, wait, fixture, budget, rows, store_busy):
    """Grant in the ledger's own order, which applies the owner's priorities, until nothing more can start."""
    held_reason = "store_busy" if store_busy else None
    capacity = None
    minimum = recipes.get("min_free_gigabytes", 0)
    while waiting and budget > 0 and not store_busy:
        if shutil.disk_usage(store.path).free < minimum * 1000000000:
            held_reason = "low_disk"
            break
        ledger = store.load()
        granted = next((holder for holder in waiting
                        if any(r["holder"] == holder and r["state"] == "granted" for r in ledger.requests.values())), None)
        if granted is None:
            seen = {}

            def outside(locked):
                # Counted under the store lock, together with the grant, so another runner cannot take the
                # same free slot between this count and the grant.
                seen.update(census(store.path, locked, fixture, kind))
                return seen["external_roots"]

            try:
                code, answer = patient(lambda: grant_next(store, kind, outside=outside), wait)
            except ValueError as exc:
                if "busy" not in str(exc):
                    raise
                held_reason = "store_busy"
                break
            capacity = dict(seen) or capacity
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
        row = {"job": job.id, "state": "waiting", "kind": kind, "reason": held_reason or "job_limit"}
        if capacity is not None:
            row["capacity"] = capacity
        rows.append(row)
    return budget


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
        recipe = recipes["recipes"][packet["recipe"]]
        if is_heavy(recipe):
            heavy[job.holder] = (job, packet, raw)
            try:
                enqueue(store, job, job_kind(recipe), wait)
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


def resolve(store_path, identifier, reason, wait, process_stopped=False):
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
    unrecorded = job.unrecorded_step()
    if unrecorded:
        require(process_stopped, "step %d started but its process was never recorded, and an earlier step's stopped group "
                "proves nothing about it; check by hand that it stopped, then pass --process-stopped" % unrecorded)
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


def work_bytes(folder):
    """Bytes the work folders hold, counted without following a symlink out of them."""
    total = 0
    for name in WORK_FOLDERS:
        path = folder / name
        if path.is_symlink() or not path.is_dir():
            continue
        for current, _, files in os.walk(path):
            for item in files:
                try:
                    total += os.lstat(os.path.join(current, item)).st_size
                except OSError:
                    continue
    return total


def clean_finished(store_path, initiative_id):
    """Root's batch cleanup. Only a job with a result is finished; any other may still be running, so it is skipped."""
    matching(initiative_id, SLUG, "initiative")
    store = Store(store_path)
    base = safe_path(store.path / "jobs" / initiative_id)
    rows, not_finished = [], []
    for folder in sorted(base.iterdir()) if base.is_dir() else []:
        if folder.is_symlink() or not folder.is_dir() or SLUG.fullmatch(folder.name) is None:
            continue
        identifier = initiative_id + "/" + folder.name
        if not (folder / "result.json").exists():
            not_finished.append(identifier)
            continue
        freed = work_bytes(folder)
        removed = remove_work_folders(Job(store.path, {"id": initiative_id}, {"message_id": folder.name}))
        if removed:
            rows.append({"job": identifier, "removed": removed, "freed_bytes": freed})
    return 0, {"initiative": initiative_id, "jobs": rows, "freed_bytes": sum(row["freed_bytes"] for row in rows),
               "not_finished": not_finished}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--store", help="Absolute path to the workspace store")
    parser.add_argument("--recipes", help="Absolute path to root's recipe file")
    parser.add_argument("--lock-wait", type=float, default=DEFAULT_LOCK_WAIT_SECONDS,
                        help="Seconds to wait for a busy mailbox or store before leaving a receipt for the next run")
    parser.add_argument("--census-fixture", help="For tests: JSON that replaces the process census, a list of PIDs for "
                        "heavy or {\"external_roots\": {\"heavy\": [...], \"heavy-tests\": [...]}}")
    commands = parser.add_subparsers(dest="command", required=True)
    opened = commands.add_parser("run-open", help="Run every job request that can run now")
    opened.add_argument("--initiative", action="append", default=[], help="Only this initiative; can repeat")
    opened.add_argument("--max-jobs", type=int, default=MAX_JOBS_DEFAULT)
    commands.add_parser("check-recipes", help="Validate the recipe file and summarize it")
    resolved = commands.add_parser("resolve", help="Close a job whose runner stopped, once nothing of it is running")
    resolved.add_argument("--job", required=True, help="<initiative>/<message-id>")
    resolved.add_argument("--reason", required=True)
    resolved.add_argument("--process-stopped", action="store_true", help="Confirm by hand that an unrecorded process has stopped")
    cleaned = commands.add_parser("clean", help="Remove finished jobs' work folders, keeping their logs and results")
    cleaned.add_argument("--job", help="<initiative>/<message-id>")
    cleaned.add_argument("--initiative", help="With --finished: every finished job of this initiative")
    cleaned.add_argument("--finished", action="store_true", help="Clean every finished job of --initiative; skip the rest")
    commands.add_parser("source-digest", help="Print the commit, tree and uncommitted-content digest a packet needs").add_argument(
        "--checkout", required=True)
    args = parser.parse_args(argv)
    try:
        require(args.command == "source-digest" or args.store is not None, "--store is required")
        if args.command == "source-digest":
            code, result = source_digest(args.checkout)
        elif args.command == "resolve":
            code, result = resolve(args.store, args.job, args.reason, args.lock_wait, args.process_stopped)
        elif args.command == "clean" and args.job is None:
            require(args.initiative is not None, "clean needs --job, or --initiative with --finished")
            require(args.finished, "clean --initiative needs --finished")
            code, result = clean_finished(args.store, args.initiative)
        elif args.command == "clean":
            require(args.initiative is None and not args.finished, "clean takes --job or --initiative, not both")
            code, result = clean(args.store, args.job)
        else:
            require(args.recipes is not None, "--recipes is required")
            if args.command == "check-recipes":
                recipes = load_recipes(args.recipes)
                code, result = 0, {"recipes": {name: {"kind": recipe["kind"], "heavy": is_heavy(recipe),
                                                      "heavy_tests": recipe.get("heavy_tests", False),
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
