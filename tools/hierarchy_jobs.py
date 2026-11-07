#!/usr/bin/env python3
"""Run orchestrators' job requests through root's fixed recipes and answer each with a receipt.

Validation, commits and other physical work used to be hand-run by root from free-text requests.
This tool does the routine part. An orchestrator names a recipe and an exact source in a hash-bound
packet; root's recipe file says what that recipe runs. The argv comes only from that file, with
exact-word substitution and no shell, so nothing in a message can become a command or an option. A recipe word may
also be `$scratch/<plain relative path>`, which joins only the job's scratch folder with that fixed suffix from the
recipe file; packet values are never joined into a word.

A job is refused unless the checkout is registered for the initiative and its revision, tree and
the bytes of its uncommitted files match the packet exactly. The source is witnessed again afterward,
so a clean exit over changed source is not reported as success. Files Git ignores are not covered by the witness, so a
`require_clean` recipe does not run on the checkout at all: it refuses a path not in the packet's commit, then runs on
`<job>/source/`, a read-only export of exactly that commit (its blobs as `cat-file` reads them, so no attribute applies),
which `$checkout`, the working folder and bubblewrap's `--chdir` all name. Ignored files, nested repositories and
symlinks into ignored folders are simply absent there. Under bubblewrap the live checkout and its Git data are hidden
behind empty tmpfs mounts; `sandbox: none` cannot hide them, so there only the working folder and `$checkout` move. The
export is removed once the steps end; the logs and kept files are the evidence.

A `merge` recipe merges one commit (`merge`) into a clean checkout's HEAD (`commit`); a second merge is a second job.
Its packet names `merge`, `expected_tree` and `message`, has no `paths` key, and omits `dirty_content_sha256` or gives
the empty digest. Admit refuses a dirty worktree (read as the steps read it, without the owner's global excludes), a
merge equal to or already in `commit`, unrelated histories, submodules on either side, a changed path with a `filter`
attribute or a `merge` attribute other than the built-in text or binary, any `.gitattributes` change on either side, and
`merge.default` or any `merge.<name>.driver` in the repository's config. Those merges go to an integrator lane.
Before any ref moves, `git merge-tree --write-tree` must merge cleanly to exactly `expected_tree` with no submodule, and
a dry run of `read-tree -m -u` must accept the real index and files; until then git writes new objects only. HEAD then
moves by compare-and-swap to a commit with parents `commit` and `merge`, and the index and files follow. If read-tree
fails there, HEAD goes back by compare-and-swap and the reason says whether it did. After a timeout or a failed check
past the swap, the reason says what HEAD, the index and status show, and the result's `commit` names the new commit
whenever HEAD does. The result's `merge` record binds the inputs, the branch HEAD points at, and the git version.
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
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ElementTree

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_git import object_read_argv, object_read_env  # noqa: E402
from hierarchy_mailbox import (GIT_ID, GIT_STATUS_TIMEOUT_SECONDS, SHA256, SLUG, Mailbox, encoded, fields, integer, matching,  # noqa: E402
                               publish_file, read_bytes, read_json, require, safe_path, strict_json, strings, text, timestamp,
                               status_entries, writer_lock)
from hierarchy_wake import stop_group  # noqa: E402
from hierarchy_workspace import (Store, absolute, capacity_view, check_paths, grant_next, initiative_view,  # noqa: E402
                                 verify_evidence)


RECIPES_SCHEMA = "aegis.hierarchy-job-recipes/v1"
PACKET_SCHEMA = "aegis.hierarchy-job-packet/v1"
DEPENDENT_PACKET_SCHEMA = "aegis.hierarchy-job-packet/v2"
RESULT_SCHEMA = "aegis.hierarchy-job-result/v1"
RECOVERY_SCHEMA = "aegis.hierarchy-recovery-status/v1"
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
MAX_RESULT_BYTES = 4194304
MAX_JOBS_DEFAULT = 20
MAX_TIMEOUT_SECONDS = 86400
DEFAULT_LOCK_WAIT_SECONDS = 30.0
# A leading dash would become an option, and pathspec and glob characters would widen what is named.
PATH_ARGUMENT = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_./@+-]*(::[^\x00-\x1f]{1,512})?")
JOB_ID = re.compile(SLUG.pattern + "/" + SLUG.pattern)
ERRORS = (ValueError, OSError, UnicodeError, RecursionError, TypeError, KeyError, subprocess.SubprocessError)
WORK_FOLDERS = ("scratch", "tmp", "home", "cargo-target", "ruff-cache", "hypothesis")
# A require_clean job's read-only export of its commit. Not a work folder: the job never writes it, and it is removed
# after the steps whatever their outcome, or by clean if the runner was lost first.
EXPORT_FOLDER = "source"
CLEANUP_FOLDERS = WORK_FOLDERS + (EXPORT_FOLDER,)
MAX_EXPORT_BYTES = 2147483648
MAX_EXPORT_ENTRIES = 200000
EXPORT_SECONDS = 600
# As the kernel's ELOOP limit: a link that needs more hops than this to resolve is refused, so one link costs a bounded walk.
MAX_LINK_HOPS = 40
# Tagged so backup and indexing tools skip them (https://bford.info/cachedir/). Only the first line is the standard.
CACHE_FOLDERS = ("cargo-target", "ruff-cache", "hypothesis")
CACHEDIR_TAG = (b"Signature: 8a477f597d28d172789f06886806bc55\n"
                b"# This file is a cache directory tag created by the hierarchy job runner.\n"
                b"# For information about cache directory tags see https://bford.info/cachedir/\n")
# A recipe's kept files are evidence a green runner may never print, so they are copied out before cleanup.
MAX_KEEP = 16
MAX_KEEP_BYTES = 67108864
# A test recipe's report, named in keep relative to scratch/, where `$scratch/junit.xml` (scratch/run/junit.xml) lands.
JUNIT_KEEP = "run/junit.xml"
JUNIT_WORD = "$scratch/junit.xml"
MAX_JUNIT_BYTES = 8388608
JUNIT_COUNTS = ("tests", "failures", "errors", "skipped")
# A step word may name a plain path below $scratch, such as pytest's --junitxml target. Only the recipe file writes these.
SCRATCH_WORD = "$scratch/"
PYTHON_PROBE_SECONDS = 30
PYTHON_PROBE_DRAIN_SECONDS = 5
PYTHON_PROBE = "import platform; print(platform.python_version())"
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


def plain_relative(path):
    return all(part not in ("", ".", "..") for part in path.split("/"))


def scratch_word(word):
    """`$scratch/<plain path>`: the one token that joins a fixed suffix, so a recipe can name a file pytest writes there."""
    rest = word[len(SCRATCH_WORD):]
    return word.startswith(SCRATCH_WORD) and "$" not in rest and plain_relative(rest)


def checked_words(words, allowed, label, scratch_paths=False):
    for word in words:
        # Exact words only: no packet value is ever formatted into a larger argument, and a recipe joins only $scratch/.
        require(isinstance(word, str) and word and "\0" not in word, "invalid word in " + label)
        require("$" not in word or word in allowed or (scratch_paths and scratch_word(word)),
                "unsupported token in " + label + ": " + word)


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
    fields(recipe, {"kind", "timeout_seconds", "sandbox", "heavy", "steps"},
           {"writable_checkout", "heavy_tests", "keep", "require_clean", "expects_tests", "export_git"})
    keep = recipe.get("keep", [])
    require(isinstance(keep, list) and len(keep) <= MAX_KEEP, "invalid keep for recipe %s: at most %d paths" % (name, MAX_KEEP))
    for entry in keep:
        # Relative to scratch/ and plain, so a kept path can neither leave scratch nor name it twice.
        require(isinstance(entry, str) and "\0" not in entry and plain_relative(entry),
                "invalid keep for recipe %s: %s" % (name, str(entry)[:256]))
    require(type(recipe["heavy"]) is bool, "invalid heavy flag for recipe " + name)
    require(type(recipe.get("writable_checkout", False)) is bool, "invalid writable_checkout for recipe " + name)
    require(type(recipe.get("heavy_tests", False)) is bool, "invalid heavy_tests flag for recipe " + name)
    require(type(recipe.get("require_clean", False)) is bool, "invalid require_clean flag for recipe " + name)
    require(not (recipe.get("require_clean", False) and recipe.get("writable_checkout", False)),
            "require_clean recipe %s cannot take writable_checkout: it runs on a read-only export of the commit" % name)
    require(type(recipe.get("expects_tests", False)) is bool, "invalid expects_tests flag for recipe " + name)
    require(type(recipe.get("export_git", False)) is bool, "invalid export_git flag for recipe " + name)
    # The stub is written into the export, so a recipe that runs on the checkout has nowhere to put it.
    require(recipe.get("require_clean", False) or not recipe.get("export_git", False),
            "export_git needs require_clean for recipe " + name)
    # The counts are read from the kept copy, so a report that is not kept could never be read.
    require(not recipe.get("expects_tests", False) or JUNIT_KEEP in keep,
            "expects_tests needs keep to include %s for recipe %s" % (JUNIT_KEEP, name))
    # Heavy-Tests is a heavy slot of its own, so a recipe that is light cannot claim it.
    require(recipe["heavy"] or not recipe.get("heavy_tests", False), "heavy_tests needs heavy for recipe " + name)
    steps = recipe["steps"]
    require(isinstance(steps, list) and 0 < len(steps) <= MAX_STEPS and all(isinstance(step, list) and step for step in steps),
            "invalid steps for recipe " + name)
    for number, step in enumerate(steps, 1):
        checked_words(step, COMMAND_TOKENS, "recipe " + name, scratch_paths=True)
        # Cargo fills gigabytes and saturates the machine, so the owner allows it only in the single Heavy-Tests slot.
        compiles = cargo_step(step)
        require(not compiles or recipe.get("heavy_tests", False),
                "recipe %s step %d runs a cargo build or test (%s), which only a heavy_tests recipe may run"
                % (name, number, compiles))
    # Without the exact word no step can be shown to write the report that keep copies.
    require(not recipe.get("expects_tests", False) or any(JUNIT_WORD in step for step in steps),
            "expects_tests needs a step that writes %s for recipe %s" % (JUNIT_WORD, name))


def existing_folders(value, label):
    strings(value, label)
    for folder in value:
        path = Path(folder)
        require(path.is_absolute() and path.is_dir(), label + " must list existing absolute folders: " + folder)


def load_recipes(path):
    raw = read_bytes(path)
    recipes = strict_json(raw.decode("utf-8"))
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
    # Hashed from the bytes that were parsed, so a result names exactly the recipe file it ran under. The key cannot come
    # from the file: fields() above refuses it there.
    recipes["recipes_sha256"] = hashlib.sha256(raw).hexdigest()
    return recipes


def clean_refusal(name):
    return "recipe %s requires a clean checkout; commit or discard local changes" % name


PYTHON_INFO = {}


def python_info(recipes):
    """The recipe python's version, read once per run without the sandbox. It is provenance, so a probe that fails is
    recorded with its error and never fails the job: the steps themselves show whether that python runs."""
    executable = recipes["python"]
    if executable not in PYTHON_INFO:
        info = {"version": None, "executable": executable}
        try:
            # -S keeps site-packages and .pth files out; its own session lets a timeout stop anything it started, and
            # a child left holding the pipe would otherwise keep communicate() waiting.
            process = subprocess.Popen([executable, "-I", "-S", "-c", PYTHON_PROBE], stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, start_new_session=True,
                                       env={"PATH": os.pathsep.join(recipes["path"]), "LANG": "C.UTF-8"})
            try:
                stdout, _ = process.communicate(timeout=PYTHON_PROBE_SECONDS)
            except subprocess.TimeoutExpired as expired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                # A child that left the group (setsid, a daemonizing shim) can still hold the pipe, so the drain is bounded.
                try:
                    process.communicate(timeout=PYTHON_PROBE_DRAIN_SECONDS)
                except subprocess.TimeoutExpired:
                    pass
                raise expired
            version = stdout.decode("utf-8", errors="replace").strip()
            if process.returncode != 0:
                info["error"] = "the version probe exited %d" % process.returncode
            elif re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+]*", version) is None:
                info["error"] = "the version probe printed no version"
            else:
                info["version"] = version
        except subprocess.TimeoutExpired:
            info["error"] = "the version probe took longer than %s seconds" % PYTHON_PROBE_SECONDS
        except (OSError, subprocess.SubprocessError) as exc:
            info["error"] = "the version probe could not run: " + str(exc)[:256]
        PYTHON_INFO[executable] = info
    return dict(PYTHON_INFO[executable])


def junit_counts(raw):
    """Counts from a junit report, summed over the leaf testsuites: a testsuite that holds testsuites contributes nothing
    itself, because producers that nest suites write the children's totals on the parent. Returns (counts, None) or
    (None, why it is unreadable).
    A DOCTYPE or ENTITY is refused before parsing, so no entity is ever expanded; the text must be UTF-8 so that
    check cannot be dodged by another encoding."""
    if len(raw) > MAX_JUNIT_BYTES:
        return None, "it is larger than %d bytes" % MAX_JUNIT_BYTES
    try:
        content = raw.decode("utf-8")
    except UnicodeError:
        return None, "it is not UTF-8"
    upper = content.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        return None, "it has a DOCTYPE or ENTITY declaration"
    try:
        root = ElementTree.fromstring(content)
    except (ElementTree.ParseError, ValueError):
        return None, "it is not well-formed XML"
    if root.tag not in ("testsuites", "testsuite"):
        return None, "its root is %s, not testsuites or testsuite" % str(root.tag)[:64]
    sums = dict.fromkeys(JUNIT_COUNTS, 0)
    for suite in root.iter("testsuite"):
        if suite.find("testsuite") is not None:
            continue
        for name in JUNIT_COUNTS:
            value = suite.get(name, "0")
            if re.fullmatch(r"[0-9]{1,12}", value) is None:
                return None, "testsuite attribute %s is not a non-negative integer" % name
            sums[name] += int(value)
    passed = sums["tests"] - sums["failures"] - sums["errors"] - sums["skipped"]
    if passed < 0:
        return None, "failures, errors and skipped exceed tests"
    return {"total": sums["tests"], "passed": passed, "failed": sums["failures"], "errors": sums["errors"],
            "skipped": sums["skipped"]}, None


def kept_junit(kept):
    """The counts from the kept copy of the report, and the reason a recipe that expects tests fails, if it does."""
    row = next((item for item in kept if item["path"] == JUNIT_KEEP), None)
    if row is None or row.get("error") == "missing":
        return None, "junit.xml is missing"
    if "error" in row:
        return None, "junit.xml is unreadable: " + row["error"]
    try:
        with open(row["copy"], "rb") as stream:
            raw = stream.read(MAX_JUNIT_BYTES + 1)
    except OSError as exc:
        return None, "junit.xml is unreadable: " + str(exc)[:256]
    counts, problem = junit_counts(raw)
    if problem:
        return None, "junit.xml is unreadable: " + problem
    if not counts["total"]:
        return counts, "the run reported no tests"
    # Every test skipped is still exit 0 for pytest, and proves nothing about the commit.
    return counts, None if counts["passed"] else "the run passed no tests"


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
        # A merge names no paths at all, so even an empty value is refused, as expected_tree is for a command recipe.
        require(recipe["kind"] != "merge" or "paths" not in packet, "a merge recipe takes no paths key, not even an empty one")
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


def refuse_paths_outside_commit(checkout, commit, paths):
    """For a require_clean recipe: every path is in the packet's commit. The job runs on an export of that commit, where
    any other path would be missing, so this only turns a confusing run over nothing into a clear refusal. Ignored files
    under a named folder need no check of their own: the export does not hold them."""
    refuse_partial_clone(checkout)
    for path in paths:
        name = path.partition("::")[0]
        # `<commit>:` names the root tree; `<commit>:.` is refused by git, so "." would never pass.
        inside = "" if name.rstrip("/") in ("", ".") else name.rstrip("/")
        # Replace refs are ignored as in the export, so a replaced tree cannot make a path look present.
        found = object_git(checkout, "cat-file", "-e", "%s:%s" % (commit, inside))
        require(found.returncode == 0, "path %s is not in commit %s" % (name, commit[:12]))


def refuse_partial_clone(checkout):
    """A partial clone fetches a missing object on read, running whatever its remote config names, so its commit is not
    read at all. Read with includes, as Git itself reads them."""
    partial = object_git(checkout, "config", "--local", "--includes", "--get", "extensions.partialClone")
    promisors = object_git(checkout, "config", "--local", "--includes", "--type=bool", "--get-regexp",
                           r"^remote\..*\.promisor$")
    # Exit 1 is "not set"; anything else, such as a promisor value that is no boolean, is refused as unreadable.
    require(partial.returncode in (0, 1) and promisors.returncode in (0, 1),
            "could not read the local config of " + str(checkout))
    require(partial.returncode == 1 and not any(line.endswith(b" true") for line in promisors.stdout.splitlines()),
            "a partial clone cannot be exported: its missing objects would be fetched")


def plain_entry(path):
    """A tree path that stays inside the export: relative, no '..', no empty or '.' part, and no .git in any case, which
    would make a folder of the export a repository whose config Git runs."""
    return bool(path) and all(part not in (b"", b".", b"..") and part.lower() != b".git" for part in path.split(b"/"))


EXPORT_MODES = {"100644": 0o444, "100755": 0o555, "120000": None}


def commit_entries(checkout, commit, tree):
    """The commit's blobs and symlinks in tree order, as (path, mode, id). A gitlink is refused: its content is not in
    the commit. Replace refs are ignored here and in the export, so the ids are the commit's own."""
    refuse_partial_clone(checkout)
    found = object_git(checkout, "rev-parse", "--verify", "--quiet", commit + "^{tree}")
    actual = found.stdout.decode().strip() if found.returncode == 0 else "nothing readable"
    require(actual == tree, "commit %s has tree %s, not the packet's tree %s" % (commit[:12], actual[:12], tree[:12]))
    listed = object_git(checkout, "ls-tree", "-r", "-z", "-l", "--full-tree", tree)
    require(listed.returncode == 0, "could not list the tree of commit " + commit[:12])
    entries, size = [], 0
    for row in listed.stdout.split(b"\0"):
        if not row:
            continue
        meta, _, path = row.partition(b"\t")
        mode, kind, oid, length = meta.decode().split()
        name = os.fsdecode(path)[:256]
        require(kind != "commit", "a submodule cannot be exported, because its content is not in the commit: " + name)
        require(all(part.lower() != b".git" for part in path.split(b"/")), "the commit holds a .git entry: " + name)
        require(plain_entry(path), "the commit holds an unsafe entry name: " + name)
        require(kind == "blob" and mode in EXPORT_MODES, "the commit holds %s with mode %s, which cannot be exported" % (name, mode))
        entries.append((path, mode, oid))
        require(len(entries) <= MAX_EXPORT_ENTRIES, "the commit has more than %d entries to export" % MAX_EXPORT_ENTRIES)
        # Refused before a byte is written; the sizes git reports while writing are checked again below.
        # ls-tree prints "-" (or garbage) as the size of an object the repository does not have.
        require(length.isdigit(), "the commit lacks the object of %s: %s" % (name, oid))
        size += int(length)
        require(size <= MAX_EXPORT_BYTES, "the export is larger than its limit of %d bytes" % MAX_EXPORT_BYTES)
    return entries


def read_exactly(stream, length, name):
    data = stream.read(length)
    require(len(data) == length, "git cat-file stopped before the end of " + name)
    return data


def write_entry(source, root, folders, path, mode, length):
    """Write one entry of `length` bytes from cat-file below root. Every folder on the way is made here, so nothing is
    written through a symlink, and the entry itself is created afresh, never opened through one."""
    name = os.fsdecode(path)[:256]
    parent = b""
    for part in path.split(b"/")[:-1]:
        parent = parent + b"/" + part if parent else part
        if parent not in folders:
            # A file or symlink already there means the tree names this path twice; mkdir refuses that too.
            require(not os.path.lexists(os.path.join(root, parent)), "the commit names %s both as a file and a folder" % name)
            os.mkdir(os.path.join(root, parent), 0o700)
            folders.add(parent)
    target = os.path.join(root, path)
    require(path not in folders and not os.path.lexists(target), "the commit names %s more than once" % name)
    if mode == "120000":
        require(length <= 4096, "the commit has a symlink with a target longer than 4096 bytes: " + name)
        os.symlink(read_exactly(source, length, name), target)
        return
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, EXPORT_MODES[mode])
    with os.fdopen(descriptor, "wb") as out:
        left = length
        while left:
            chunk = source.read(min(left, 1048576))
            require(chunk, "git cat-file stopped before the end of " + name)
            out.write(chunk)
            left -= len(chunk)


def resolved_link(path, deadline):
    """Where the link at path resolves, as realpath would, or None past MAX_LINK_HOPS links on the way, as the kernel
    gives ELOOP. A part that does not exist is taken lexically, as realpath does, so '..' after it is never trusted."""
    pending, current, hops = path.split(b"/")[::-1], b"", 0
    while pending:
        part = pending.pop()
        require(time.monotonic() < deadline, "the export took longer than %s seconds" % EXPORT_SECONDS)
        if part in (b"", b"."):
            continue
        if part == b"..":
            current = current.rpartition(b"/")[0]
            continue
        candidate = current + b"/" + part
        try:
            is_link = stat.S_ISLNK(os.lstat(candidate).st_mode)
        except OSError:
            is_link = False
        if not is_link:
            current = candidate
            continue
        hops += 1
        if hops > MAX_LINK_HOPS:
            return None
        target = os.readlink(candidate)
        if target.startswith(b"/"):
            current = b""
        pending.extend(target.split(b"/")[::-1])
    return current or b"/"


def refuse_leaving_links(root, deadline):
    """A link whose resolved target leaves the export would reach the live filesystem, which is outside the commit.
    Resolved, not read lexically, so a chain such as `d -> .` and `esc -> d/d/../..` is caught too. Each link is resolved
    with a bounded number of hops, and the walk shares the export's deadline, so a tree of costly links cannot stall it."""
    for current, folders, files in os.walk(root):
        for child in sorted(folders + files):
            require(time.monotonic() < deadline, "the export took longer than %s seconds" % EXPORT_SECONDS)
            path = os.path.join(current, child)
            if not os.path.islink(path):
                continue
            shown = (os.fsdecode(os.path.relpath(path, root))[:256], os.fsdecode(os.readlink(path))[:256])
            resolved = resolved_link(path, deadline)
            require(resolved is not None, "the commit has a symlink that loops or passes more than %d links: %s -> %s"
                    % ((MAX_LINK_HOPS,) + shown))
            require(resolved == root or resolved.startswith(root + b"/"), "the commit has a symlink that leaves it: %s -> %s"
                    % shown)


# A build script such as stormheir's crates/sim/build.rs asks git for HEAD and panics outside a repository. These are all
# Git needs to find one and resolve a detached HEAD: no objects, refs, hooks, alternates or info, so nothing it reads can
# name a command, a path outside the export, or content other than the commit's id.
GIT_STUB_CONFIG = b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n"


def write_git_stub(root, commit):
    """<root>/.git naming commit as a detached HEAD, read-only. Not counted in the export's entries or bytes."""
    stub = os.path.join(root, b".git")
    os.mkdir(stub, 0o700)
    for name in (b"objects", b"refs"):
        os.mkdir(os.path.join(stub, name), 0o555)
    for name, data in ((b"HEAD", commit.encode() + b"\n"), (b"config", GIT_STUB_CONFIG)):
        descriptor = os.open(os.path.join(stub, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
        with os.fdopen(descriptor, "wb") as out:
            out.write(data)
    os.chmod(stub, 0o555)


def export_commit(checkout, commit, tree, target, git_stub=False):
    """Materialise exactly the packet's commit at target, read-only, and return its record for the result.

    The entries come from `ls-tree` of the commit's tree and their bytes from one `git cat-file --batch`, which applies
    no attribute: no filter (LFS and the like) runs, and eol, export-subst and export-ignore change nothing, so the
    export holds exactly the committed bytes. A symlink that resolves outside the export is refused, not run."""
    # One deadline for the whole export, from the tree listing to the last link checked.
    deadline = time.monotonic() + EXPORT_SECONDS
    entries = commit_entries(checkout, commit, tree)
    os.mkdir(target, 0o700)
    root = os.fsencode(os.path.realpath(target))
    folders, size, expired = {b""}, 0, []
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(object_read_argv("cat-file", "--batch"), cwd=checkout, env=object_read_env(),
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
        # The kill ends any read or write that waits on git once the deadline passes.
        timer = threading.Timer(max(0, deadline - time.monotonic()), lambda: (expired.append(True), process.kill()))
        timer.start()
        try:
            for path, mode, oid in entries:
                process.stdin.write(oid.encode() + b"\n")
                process.stdin.flush()
                header = process.stdout.readline().split()
                require(len(header) == 3 and header[:2] == [oid.encode(), b"blob"] and header[2].isdigit(),
                        "git cat-file did not return the blob of " + os.fsdecode(path)[:256])
                length = int(header[2])
                size += length
                require(size <= MAX_EXPORT_BYTES, "the export is larger than its limit of %d bytes" % MAX_EXPORT_BYTES)
                write_entry(process.stdout, root, folders, path, mode, length)
                require(process.stdout.read(1) == b"\n", "git cat-file stopped before the end of " + os.fsdecode(path)[:256])
            process.stdin.close()
            code = process.wait(timeout=max(0, deadline - time.monotonic()))
        except BaseException as exc:
            process.kill()
            process.wait()
            # The final wait can run out a moment before the timer fires; either way the deadline passed.
            if expired or isinstance(exc, subprocess.TimeoutExpired):
                raise ValueError("the export took longer than %s seconds" % EXPORT_SECONDS) from None
            raise
        finally:
            timer.cancel()
            for stream in (process.stdin, process.stdout):
                try:
                    stream.close()
                except OSError:
                    pass
        require(not expired, "the export took longer than %s seconds" % EXPORT_SECONDS)
        errors.seek(0)
        require(code == 0, "git cat-file exited %d: %s"
                % (code, errors.read(512).decode("utf-8", "replace").strip()))
    refuse_leaving_links(root, deadline)
    if git_stub:
        # After the link check, which it would pass anyway, and before the root turns read-only. The commit cannot
        # already hold a .git: commit_entries refused that before a byte was written.
        write_git_stub(root, commit)
    # Folders last, read-only like the files, so even sandbox none cannot change what the steps run.
    for folder in sorted(folders, key=len, reverse=True):
        os.chmod(os.path.join(root, folder) if folder else root, 0o555)
    record = {"commit": commit, "tree": tree, "entries": len(entries), "bytes": size}
    if git_stub:
        record["git_stub"] = True
    return record


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
    listed = object_git(checkout, "ls-files", "--stage", "-z")
    require(listed.returncode == 0, "could not read the index of " + str(checkout))
    gitlinks = [entry.partition(b"\t")[2] for entry in listed.stdout.split(b"\0") if entry.startswith(b"160000 ")]
    for revision in revisions:
        tree = object_git(checkout, "ls-tree", "-r", "-z", "--full-tree", revision)
        require(tree.returncode == 0, "could not read the tree of " + revision)
        gitlinks += [entry.partition(b"\t")[2] for entry in tree.stdout.split(b"\0") if entry.startswith(b"160000 ")]
    require(not gitlinks, "submodules are not supported, because their content cannot be witnessed byte for byte: "
            + ", ".join(sorted({os.fsdecode(path) for path in gitlinks}))[:1024])


def object_git(checkout, *args):
    """Raw object reads; these must never inherit the mutation runner's Git policy."""
    return subprocess.run(object_read_argv(*args), cwd=checkout, env=object_read_env(), capture_output=True, timeout=120)


def pinned_git(checkout, *args, stdin=None, env=PINNED_GIT_ENV):
    """A read with the config the merge steps see, so what admit refuses and what the merge does agree."""
    return subprocess.run(object_read_argv(*args), cwd=checkout, input=stdin,
                          env=object_read_env(env), capture_output=True, timeout=120)


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


def head_ref(checkout):
    """The branch HEAD points at, or None when HEAD is detached: what a merge's swap would move."""
    found = pinned_git(checkout, "symbolic-ref", "-q", "HEAD")
    require(found.returncode in (0, 1), "could not read which branch HEAD points at")
    return found.stdout.decode().strip() or None


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
    status = subprocess.run(object_read_argv("status", "--porcelain=v1", "-z", "--untracked-files=all"),
                            cwd=checkout, env=object_read_env(view, inherit_config=True), capture_output=True, timeout=120)
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


def source_identity(checkout, *arguments):
    """The mailbox witness contract, with the job reader's no-fetch/no-replacement policy."""
    try:
        result = subprocess.run(object_read_argv(*arguments), cwd=checkout, capture_output=True, text=True,
                                env=object_read_env(inherit_config=True), timeout=5)
    except subprocess.TimeoutExpired as exc:
        raise ValueError("git identity check timed out") from exc
    require(result.returncode == 0, "git identity check failed")
    return result.stdout.rstrip("\r\n")


def source_state(mailbox, checkout, view=None):
    # Keep the persisted mailbox witness fields and its ordinary ignore view; only the content digest uses `view`.
    # The pinned, standalone mailbox implementation cannot depend on the shared Git policy module.
    checkout = safe_path(checkout)
    try:
        status = subprocess.run(object_read_argv("status", "--porcelain=v1", "-z", "--untracked-files=all"),
                                cwd=checkout, capture_output=True, env=object_read_env(inherit_config=True),
                                timeout=GIT_STATUS_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise ValueError("git identity check timed out") from exc
    require(status.returncode == 0, "git identity check failed")
    return {"worktree": str(checkout), "source_revision": source_identity(checkout, "rev-parse", "HEAD"),
            "source_tree": source_identity(checkout, "rev-parse", "HEAD^{tree}"),
            "dirty_state_sha256": hashlib.sha256(status.stdout).hexdigest(), "dirty_entries": status_entries(status.stdout),
            "dirty_content_sha256": uncommitted_content(checkout, view)[0]}


def source_digest(checkout):
    """What an orchestrator needs for a packet. A lane with a shell can run this and report it."""
    path = safe_path(text(checkout, "checkout"))
    digest, count = uncommitted_content(path)
    return 0, {"commit": source_identity(path, "rev-parse", "HEAD"), "tree": source_identity(path, "rev-parse", "HEAD^{tree}"),
               "dirty_content_sha256": digest, "dirty_entries": count}


def derive_host_plan(initiative):
    """Provision registers <base>/mailbox, so the team plan needs no new store field or CLI option."""
    path = Path(initiative["mailbox_root"]).parent / "host-plan.json"
    reason = "derive is for shell-less teams"
    try:
        raw = read_bytes(path)
        plan = strict_json(raw.decode("utf-8"))
    except ERRORS as exc:
        raise ValueError(reason + ": could not read host plan " + str(path)) from exc
    require(isinstance(plan, dict) and plan.get("schema") == "aegis.hierarchy-host-plan/v1"
            and plan.get("hierarchy") == initiative["id"] and plan.get("team") == "claude-code", reason)
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "team": plan["team"]}


class DependencyPending(ValueError):
    """No dependent effect was admitted; keep the original request available for reconciliation."""

    def __init__(self, detail, reason="dependency_pending"):
        super().__init__(detail)
        self.reason = reason

    def row(self, job):
        return {"job": job.id, "state": "waiting", "reason": self.reason, "detail": str(self)[:2048]}


def check_dependency(store, initiative, message, packet, recipes):
    """Require exact completed evidence, never a loop/status summary. This does not settle or publish anything."""
    try:
        require(packet["recipes_sha256"] == recipes["recipes_sha256"], "dependent recipe file changed")
        mailbox = Mailbox(initiative["mailbox_root"])
        mailbox.fence(message)
        records = mailbox.messages()
        previous = records.get(packet["after"]["message_id"])
        if previous is None:
            raise DependencyPending("predecessor request is not present")
        require(file_sha256(safe_path(previous["path"])) == packet["after"]["sha256"],
                "predecessor request hash mismatch")
        parent = previous["message"]
        require(parent["type"] == "job_request" and parent["from"] == message["from"]
                and parent["to"] == message["to"], "predecessor must have the same requester and recipient")
        raw = mailbox.brief(parent["brief"])
        original = strict_json(packet_text(raw))
        require(isinstance(original, dict) and original.get("schema") in (PACKET_SCHEMA, DEPENDENT_PACKET_SCHEMA),
                "invalid predecessor packet")
        require(all(original.get(key) == packet[key] for key in ("checkout", "commit", "tree"))
                and original.get("dirty_content_sha256", EMPTY_STATUS) == EMPTY_STATUS,
                "predecessor source differs from dependent source")
        require(isinstance(original.get("recipe"), str) and original["recipe"] in recipes["recipes"]
                and recipes["recipes"][original["recipe"]]["kind"] == "command",
                "predecessor must be a command check")
        job = Job(store.path, initiative, parent)
        result = job.result()
        if result is None:
            raise DependencyPending("predecessor has no validated terminal result")
        require(result["state"] == "completed", "predecessor did not complete successfully")
        require(result.get("recipe") == original["recipe"] and result.get("recipes_sha256") == packet["recipes_sha256"],
                "predecessor recipe provenance mismatch")
        claim = read_json(job.claim_path)
        require(isinstance(claim, dict) and claim.get("recipes_sha256") == packet["recipes_sha256"],
                "predecessor claim recipe provenance mismatch")
        require(read_bytes(job.folder / "packet.md") == raw, "predecessor retained packet mismatch")
        for name in ("before", "after"):
            witness = result.get(name)
            require(isinstance(witness, dict) and witness.get("worktree") == packet["checkout"]
                    and witness.get("source_revision") == packet["commit"]
                    and witness.get("source_tree") == packet["tree"]
                    and witness.get("dirty_content_sha256") == EMPTY_STATUS,
                    "predecessor source witness mismatch")
        check_settlement_processes(job, result)
        require(job.runner_alive() is False, "predecessor runner is still live or unknown")
        require(not any(r["holder"] == job.holder and r["state"] in ("queued", "granted")
                        for r in store.load().requests.values()), "predecessor reservation is not settled")
        receipt = {"state": "completed", "exit_code": 0, "evidence": job.evidence()}
        if result.get("reason") is not None:
            receipt["reason"] = result["reason"][:4096]
        prior = records.get(receipt_id(job, "completed"))
        if prior is None:
            raise DependencyPending("predecessor terminal receipt is not published")
        require(receipt_matches(job, prior["message"], receipt, result_body(job, result)),
                "predecessor terminal receipt does not match retained evidence")
    except DependencyPending:
        raise
    except ERRORS as exc:
        raise DependencyPending(str(exc), "dependency_held") from exc


def pending_dependency(store, job, exc, wait, recipes_sha256):
    """A reserved job needs a durable no-effect refusal, not an orphaned slot or release from absence."""
    try:
        if any(r["holder"] == job.holder and r["state"] in ("queued", "granted")
               for r in store.load().requests.values()):
            # refuse takes the exclusive claim first. A competing runner keeps its claim and capacity.
            return refuse(store, job, "dependency changed after capacity admission: " + str(exc), wait, recipes_sha256)
        return exc.row(job)
    except ERRORS as failure:
        return blocked_row(job, failure)


def admit(ledger, initiative, message, mailbox, recipes, store=None):
    """Everything a job must satisfy before it runs. A ValueError here becomes the refusal's reason."""
    raw = mailbox.brief(message["brief"])
    try:
        packet = strict_json(packet_text(raw))
    except UnicodeError as exc:
        raise ValueError("packet is not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("packet is not valid JSON") from exc
    dependent = isinstance(packet, dict) and packet.get("schema") == DEPENDENT_PACKET_SCHEMA
    fields(packet, {"schema", "recipe", "checkout", "commit", "tree"} |
           ({"after", "recipes_sha256"} if dependent else set()),
           {"dirty_content_sha256", "paths", "expected_tree", "message", "merge", "derive"})
    require(packet["schema"] in (PACKET_SCHEMA, DEPENDENT_PACKET_SCHEMA), "unsupported packet schema")
    name = packet["recipe"]
    require(isinstance(name, str) and name in recipes["recipes"], "unknown recipe: " + str(name)[:128])
    recipe = recipes["recipes"][name]
    kind = recipe["kind"]
    derive = "derive" in packet
    if derive:
        require(packet["derive"] == "runner", "derive must be runner")
        require(kind == "commit", "only a commit recipe takes derive")
        host_plan = derive_host_plan(initiative)
    checkout = absolute(packet["checkout"], "checkout")
    require(checkout in initiative["checkouts"], "checkout is not registered for this initiative: " + checkout)
    matching(packet["commit"], GIT_ID, "commit")
    matching(packet["tree"], GIT_ID, "tree")
    dirty = packet.get("dirty_content_sha256", EMPTY_STATUS)
    matching(dirty, SHA256, "dirty_content_sha256")
    # A test run over uncommitted bytes says nothing about any commit a Reviewer can read.
    require(not recipe.get("require_clean", False) or dirty == EMPTY_STATUS, clean_refusal(name))
    paths = checked_paths(packet, recipe, checkout)
    if dependent:
        require(kind == "command" and dirty == EMPTY_STATUS, "dependent jobs require command checks on clean source")
        fields(packet["after"], {"message_id", "sha256"})
        matching(packet["after"]["message_id"], SLUG, "predecessor message id")
        matching(packet["after"]["sha256"], SHA256, "predecessor sha256")
        matching(packet["recipes_sha256"], SHA256, "recipes sha256")
        require(packet["after"]["message_id"] != message["message_id"], "a job cannot depend on itself")
        require(store is not None, "dependent jobs require the workspace store")
        check_dependency(store, initiative, message, packet, recipes)
    if kind in ("commit", "merge"):
        require(("expected_tree" in packet or derive) and "message" in packet,
                "a %s recipe needs expected_tree and message" % kind)
        if "expected_tree" in packet:
            matching(packet["expected_tree"], GIT_ID, "expected_tree")
        text(packet["message"], "commit message", 65536)
    else:
        require("expected_tree" not in packet and "message" not in packet,
                "only a commit recipe or a merge recipe takes expected_tree or message")
    require(kind == "merge" or "merge" not in packet, "only a merge recipe takes merge")
    if kind == "commit":
        if "expected_tree" in packet:
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
    if derive and "dirty_content_sha256" not in packet:
        dirty = witness["dirty_content_sha256"]
    # Named before the plain mismatch, so a packet that claimed a clean checkout learns why it cannot run.
    require(not recipe.get("require_clean", False) or witness["dirty_content_sha256"] == EMPTY_STATUS, clean_refusal(name))
    require((witness["source_revision"], witness["source_tree"], witness["dirty_content_sha256"]) ==
            (packet["commit"], packet["tree"], dirty), "source does not match the packet")
    if recipe.get("require_clean", False):
        refuse_paths_outside_commit(checkout, packet["commit"], paths)
    admitted = {**packet, "dirty_content_sha256": dirty, "paths": paths}
    if derive:
        tree = derive_commit_tree(admitted, recipes, initiative, message)
        require(tree != packet["tree"], "this commit would make no change")
        require("expected_tree" not in packet or packet["expected_tree"] == tree,
                "the derived tree %s is not the expected tree %s" % (tree, packet.get("expected_tree")))
        admitted.update(expected_tree=tree, derived_by="runner", host_plan=host_plan)
    if kind == "merge":
        merge_refusals(checkout, packet["commit"], packet["merge"])
        # The witness binds the revision and tree, not the branch, so the branch is held here and checked again at run time.
        admitted["head_ref"] = head_ref(checkout)
    return admitted, raw


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


def process_scope():
    """An absent PID is meaningful only in the original boot and PID namespace."""
    try:
        own = Path("/proc/self/stat").read_text(encoding="ascii").split(" ", 1)[0]
        require(own == str(os.getpid()), "process table self witness does not match current pid")
        boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        namespace = os.readlink("/proc/self/ns/pid")
    except OSError as exc:
        raise ValueError("cannot establish process scope: " + str(exc)) from exc
    require(re.fullmatch(r"[0-9a-f-]{36}", boot) is not None and re.fullmatch(r"pid:\[\d+\]", namespace) is not None,
            "invalid process scope witness")
    return {"boot_id": boot, "pid_namespace": namespace}


def process_entries():
    """Unlike Path.glob, explicit enumeration does not suppress unreadable-root errors."""
    process_scope()
    try:
        with os.scandir("/proc") as entries:
            paths = [Path("/proc") / entry.name for entry in entries if entry.name.isdigit()]
    except OSError as exc:
        raise ValueError("cannot enumerate process table: " + str(exc)) from exc
    require(Path("/proc") / str(os.getpid()) in paths, "process table does not include its self witness")
    return paths


def process_start(pid):
    """Process start time, which tells a live process from a reused PID. None when it is gone or a zombie."""
    try:
        after_name = Path("/proc/%d/stat" % pid).read_text(encoding="ascii", errors="replace").rpartition(")")[2].split()
    except (FileNotFoundError, ProcessLookupError):
        return None
    except OSError as exc:
        raise ValueError("cannot observe process %s: %s" % (pid, exc)) from exc
    require(len(after_name) > 19, "malformed process stat: " + str(pid))
    return None if after_name[0] in ("Z", "X") else after_name[19]


def group_members(group):
    """Live members of a process group. Zombies cannot act, so they do not count."""
    members = []
    for process in process_entries():
        item = process / "stat"
        try:
            after_name = item.read_text(encoding="ascii", errors="replace").rpartition(")")[2].split()
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as exc:
            raise ValueError("cannot observe process group %s: %s" % (group, exc)) from exc
        require(len(after_name) > 2, "malformed process group stat: " + str(item))
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
    for process in process_entries():
        item = process / "cmdline"
        pid = int(item.parent.name)
        try:
            words = [word.decode(errors="replace") for word in item.read_bytes().split(b"\0") if word]
            parents[pid] = int((item.parent / "stat").read_text(encoding="ascii", errors="replace")
                               .rpartition(")")[2].split()[1])
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (OSError, ValueError, IndexError) as exc:
            raise ValueError("cannot census process %s: %s" % (pid, exc)) from exc
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
        result = strict_json(self.result_path.read_bytes().decode("utf-8"))
        require(isinstance(result, dict) and result.get("schema") == RESULT_SCHEMA, "invalid job result schema")
        require(result.get("job") == self.id, "result does not belong to job: " + self.id)
        require(result.get("state") in ("completed", "failed", "refused"), "invalid terminal job state")
        require(isinstance(result.get("steps"), list), "invalid job result steps")
        # A durable result can survive a lost writer. Validate the fields settlement reads before
        # publishing a receipt or releasing capacity; a malformed row leaves its effects uncertain.
        def valid(condition, field):
            require(condition, "invalid job result " + field)

        for index, step in enumerate(result["steps"]):
            field = "steps[%d]" % index
            valid(isinstance(step, dict), field)
            argv = step.get("argv")
            valid(isinstance(argv, list) and bool(argv) and all(isinstance(word, str) for word in argv), field + ".argv")
            valid("exit_code" in step and (step["exit_code"] is None or type(step["exit_code"]) is int), field + ".exit_code")
            if "stopped_leftovers" in step:
                valid(type(step["stopped_leftovers"]) is bool, field + ".stopped_leftovers")
        for field in ("reason", "commit"):
            valid(result.get(field) is None or isinstance(result[field], str), field)
        if "process_stopped_confirmed" in result:
            valid(type(result["process_stopped_confirmed"]) is bool, "process_stopped_confirmed")
        if result.get("tests") is not None:
            tests = result["tests"]
            valid(isinstance(tests, dict), "tests")
            for field in ("total", "passed", "failed", "errors", "skipped"):
                valid(type(tests.get(field)) is int and tests[field] >= 0, "tests." + field)
        if "kept" in result:
            valid(isinstance(result["kept"], list), "kept")
            for index, item in enumerate(result["kept"]):
                field = "kept[%d]" % index
                valid(isinstance(item, dict), field)
                valid(isinstance(item.get("path"), str), field + ".path")
                if "error" in item:
                    valid(isinstance(item["error"], str), field + ".error")
        code = result.get("exit_code")
        require((result["state"] == "refused" and code is None)
                or (result["state"] == "completed" and type(code) is int and code == 0)
                or (result["state"] == "failed" and type(code) is int and code != 0),
                "job result state and exit code disagree")
        return result

    def claim(self, packet_raw, recipes_sha256=None):
        """Exclusive, so two runners or a retry can never start the same job twice. The recipe file's hash is kept here so
        a later root resolution records the file the job was taken under, not whatever file exists by then."""
        self.folder.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.folder.mkdir(mode=0o700)
        except FileExistsError:
            return False
        ticks = process_start(os.getpid())
        publish_file(self.claim_path, encoded({"pid": os.getpid(), "start": ticks, "job": self.id, "at": timestamp(),
                                             "process_scope": process_scope(), "recipes_sha256": recipes_sha256}) + b"\n")
        if packet_raw is not None:
            publish_file(self.folder / "packet.md", packet_raw)
        return True

    def runner_alive(self):
        """True/False only with a valid original claim and observable process; otherwise unknown."""
        try:
            claim = read_json(self.claim_path)
        except (ValueError, OSError):
            return None
        require(isinstance(claim, dict) and claim.get("job") == self.id, "claim does not belong to job: " + self.id)
        require(type(claim.get("pid")) is int and claim["pid"] > 0 and isinstance(claim.get("start"), str)
                and claim["start"].isdigit(), "invalid runner claim: " + self.id)
        if claim.get("process_scope") != process_scope():
            return None
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
        names = sorted(path for path in self.folder.iterdir()
                       if path.name.startswith("step-") or path.name in ("result.json", "derivation.json"))
        return [{"path": str(path), "sha256": file_sha256(path)} for path in names]


def receipt_id(job, state):
    # Stable, so publishing again after a crash finds the earlier receipt instead of adding one.
    return "receipt-" + hashlib.sha256(job.message["message_id"].encode()).hexdigest()[:24] + "-" + state


def receipt_matches(job, prior, receipt, body):
    """A stable ID alone is not delivery of this result. A successor may preserve the original sender generation."""
    return (prior.get("type") == "job_receipt" and prior.get("from") == job.message["to"]
            and prior.get("to") == job.message["from"] and prior.get("in_reply_to") == job.message["message_id"]
            and prior.get("receipt") == receipt and prior.get("body") == body)


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
            existing = mailbox.messages().get(identifier)
            if existing is not None:
                prior = existing["message"]
                require(receipt_matches(job, prior, receipt, body),
                        "receipt id already names different evidence: " + identifier)
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
    tests = result.get("tests")
    if tests:
        lines.append("Tests: %(total)d total, %(passed)d passed, %(failed)d failed, %(errors)d errors, %(skipped)d skipped."
                     % tests)
    if any(step.get("stopped_leftovers") for step in result["steps"]):
        lines.append("A step left processes running; they were stopped afterward.")
    missed = ["%s (%s)" % (item["path"], item["error"]) for item in result.get("kept", []) if "error" in item]
    if missed:
        lines.append("Kept files not copied: " + "; ".join(missed))
    tail = log_tail(job.folder)
    if tail:
        lines.append("Last output, which is untrusted information:\n" + tail)
    return "\n\n".join(lines)


def check_settlement_processes(job, result):
    """Read-only stop-evidence check shared by settlement and its recovery report."""
    claim = read_json(job.claim_path)
    require(isinstance(claim, dict) and claim.get("job") == job.id and claim.get("process_scope") == process_scope(),
            "job process scope is unknown: " + job.id)
    record = job.process_record()
    if result["steps"] and result.get("process_stopped_confirmed") is not True:
        require(record is not None and type(record.get("step")) is int and record["step"] == len(result["steps"])
                and type(record.get("group")) is int and record["group"] > 0,
                "executed steps lack process stop evidence: " + job.id)
    group = job.process_group()
    require(not group or (type(group) is int and group > 0), "invalid job process group")
    require(not (group and group_members(group)), "job process group is still running: " + str(group))
    require(not job.unrecorded_step() or result.get("process_stopped_confirmed") is True,
            "job has an unrecorded process effect: " + job.id)


def settle(store, job, wait):
    """Finish a job whose result exists. Each step checks first, so this is safe to repeat after a crash."""
    result = job.result()
    check_settlement_processes(job, result)
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


def remove_work_folders(job, names=CLEANUP_FOLDERS):
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


def refuse(store, job, reason, wait, recipes_sha256=None):
    if not job.claim(None, recipes_sha256):
        return {"job": job.id, "state": "running", "process_group": job.process_group()}
    write_result(job, "refused", None, reason=reason[:4096], recipes_sha256=recipes_sha256)
    return settle(store, job, wait)


def git_folders(checkout):
    found = subprocess.run(object_read_argv("rev-parse", "--path-format=absolute", "--git-dir", "--git-common-dir"),
                            cwd=checkout, env=object_read_env(inherit_config=True), capture_output=True, text=True, timeout=30)
    require(found.returncode == 0, "could not locate the checkout's Git data")
    return sorted(set(found.stdout.splitlines()))


def sandbox_prefix(recipes, recipe, job, checkout, export=None):
    """export, for a require_clean job, is the folder the steps run in; the live checkout is then hidden, not bound."""
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
    if export is not None:
        # Empty tmpfs over the live checkout and its Git data, so not even an absolute path reaches an ignored file there.
        # Before the job folder's bind, so an export below either of them is mounted again on top.
        for folder in [checkout] + [path for path in git_folders(checkout) if not path.startswith(checkout + os.sep)]:
            argv += ["--tmpfs", folder]
    else:
        writes_git = recipe["kind"] in ("commit", "merge")
        # A merge brings the working tree forward itself, so it writes the checkout as well as the Git data.
        argv += ["--bind" if recipe.get("writable_checkout") or recipe["kind"] == "merge" else "--ro-bind", checkout, checkout]
        for folder in git_folders(checkout):
            argv += ["--bind" if writes_git else "--ro-bind", folder, folder]
    # The job folder itself stays read-only inside, so a job cannot write its own result, claim or logs, nor its export.
    argv += ["--ro-bind", str(job.folder), str(job.folder)]
    for name in WORK_FOLDERS:
        argv += ["--bind", str(job.folder / name), str(job.folder / name)]
    return argv + ["--chdir", export or checkout, "--"]


def scratch_argument(job):
    # Below the bound folder, because pytest removes and recreates --basetemp, and a mount point cannot be removed.
    return str(job.folder / "scratch" / "run")


def cargo_target(job):
    """One path for both CARGO_TARGET_DIR and $cargo_target, so a runner's --target-dir never splits the cache."""
    return str(job.folder / "cargo-target")


def job_environment(recipes, job, checkout, export=None):
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
    if export is not None:
        # The export has no .git, or only export_git's stub, so git must not walk up from it into whatever repository
        # holds the store. Discovery stops below the job folder, so it finds the stub or nothing.
        env["GIT_CEILING_DIRECTORIES"] = str(job.folder)
        # A committed folder holding HEAD, objects/ and refs/ is a bare repository to discovery, found before the stub,
        # with its own HEAD, config and alternates. Only protected config can refuse that, so it goes in as -c would.
        env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="safe.bareRepository", GIT_CONFIG_VALUE_0="explicit")
    tokens = {"$checkout": export or checkout, "$scratch": scratch_argument(job)}
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


class _LaunchFailure(Exception):
    """A particular step could not start; earlier steps may already have completed effects."""

    def __init__(self, number, argv, cause):
        super().__init__(str(cause))
        self.record = {"step": number, "argv": list(argv), "error": str(cause)[:2048]}


class _ExecutionResult:
    """Completed steps and a failed launch travel together through result publication."""

    def __init__(self, steps=(), reason=None, exit_code=0, created=None, failed_launch=None):
        self.steps, self.reason, self.exit_code = list(steps), reason, exit_code
        self.created, self.failed_launch = created, failed_launch


def stop_for_certain(process):
    try:
        stop_group(process)
        if group_members(process.pid):
            raise StillRunning(process.pid, "members were left after the stop")
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise StillRunning(process.pid, str(exc)[:512]) from exc


def command_steps(recipe, packet, recipes, job, checkout):
    tokens = {"$python": [recipes["python"]], "$paths": packet["paths"], "$scratch": [scratch_argument(job)],
              "$checkout": [checkout], "$cargo_target": [cargo_target(job)]}
    for step in recipe["steps"]:
        yield Step([part for word in step for part in tokens.get(word, [scratch_argument(job) + word[len("$scratch"):]]
                                                                     if scratch_word(word) else [word])])
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


def commit_git(recipes):
    identity = recipes["identity"]
    return ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false",
            "-c", "user.name=" + identity["name"], "-c", "user.email=" + identity["email"]]


def stage_commit_tree(packet, recipes, job):
    """Admission and execution stage the same paths, with the same Git config and a private index."""
    git = commit_git(recipes)
    temporary = {"GIT_LITERAL_PATHSPECS": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                 "GIT_INDEX_FILE": str(job.folder / "scratch" / "index")}
    yield Step(git + ["read-tree", packet["commit"]], temporary)
    yield Step(git + ["add", "--", *packet["paths"]], temporary)
    return (yield Step(git + ["write-tree"], temporary, capture=True))


def derive_commit_tree(packet, recipes, initiative, message):
    """Use the recipe's sandbox, PATH, prefix and environment before taking any execution claim."""
    folder = Path(tempfile.mkdtemp(prefix="hierarchy-derive-"))
    job = Job(folder, initiative, message)
    job.folder.mkdir(parents=True, mode=0o700)
    try:
        result = execute(job, recipes["recipes"][packet["recipe"]], packet, recipes, lambda: None, {},
                         plan=stage_commit_tree(packet, recipes, job))
    except StillRunning as exc:
        # Do not erase the process record or report a confirmed stop if the existing process guard cannot prove one.
        raise ValueError("derivation process stop is unknown; evidence kept at %s: %s" % (folder, exc)) from exc
    except BaseException:
        shutil.rmtree(folder)
        raise
    shutil.rmtree(folder)
    require(result.reason is None, "could not derive expected_tree: " + str(result.reason))
    matching(result.created, GIT_ID, "derived expected_tree")
    return result.created


def commit_steps(packet, recipes, job, details):
    """Built on a throwaway index, so a wrong tree leaves the checkout's index, HEAD and files as they were."""
    git = commit_git(recipes)
    plain = {"GIT_LITERAL_PATHSPECS": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    message_file = job.folder / "scratch" / "commit-message"
    message_file.parent.mkdir(mode=0o700, exist_ok=True)
    message_file.write_text(packet["message"], encoding="utf-8")
    tree = yield from stage_commit_tree(packet, recipes, job)
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
    # The git the steps run, found on the recipe's PATH inside the sandbox, so a prediction can name the same one.
    details["git_version"] = yield Step(["git", "--version"], plain, capture=True)
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
    process = None
    try:
        record_process(job, launch, ".intent")
        with open(log_path, "xb") as log, open(out_path, "xb") if step.capture else open(os.devnull, "wb") as out:
            process = subprocess.Popen(argv, cwd=checkout, env={**env, **step.env}, stdin=subprocess.DEVNULL,
                                       stdout=out if step.capture else log, stderr=log, start_new_session=True)
    except BaseException as exc:
        # Even closing a parent log handle can fail after Popen succeeded. Such a failure must not be
        # mistaken for an unstarted child, and uncertainty about its stop still holds the job's resources.
        if process is not None:
            stop_for_certain(process)
            raise
        if isinstance(exc, ERRORS):
            raise _LaunchFailure(number, step.argv, exc) from exc
        raise
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


def execute(job, recipe, packet, recipes, on_start, details, export=None, *, plan=None):
    """export, for a require_clean job, replaces the checkout as the steps' folder and $checkout."""
    env = job_environment(recipes, job, packet["checkout"], export)
    sandbox = sandbox_prefix(recipes, recipe, job, packet["checkout"], export)
    checkout = export or packet["checkout"]
    prefix = list(recipes.get("prefix", []))
    deadline = time.monotonic() + recipe["timeout_seconds"]
    if plan is None:
        if recipe["kind"] == "commit":
            plan = commit_steps(packet, recipes, job, details)
        elif recipe["kind"] == "merge":
            plan = merge_steps(packet, recipes, job, details)
        else:
            plan = command_steps(recipe, packet, recipes, job, checkout)
    rows, reason, exit_code, created, output = [], None, 0, None, None
    failed_launch = None
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
    except _LaunchFailure as exc:
        reason, exit_code = "the job could not run: " + str(exc)[:2048], NO_VERDICT_EXIT
        failed_launch = exc.record
    except ERRORS as exc:
        # run_step confirms a started process stopped before propagating an error. StillRunning deliberately
        # escapes this handler, so no terminal result or resource release follows an uncertain stop.
        reason, exit_code = "the job could not run: " + str(exc)[:2048], NO_VERDICT_EXIT
    return _ExecutionResult(rows, reason, exit_code, created, failed_launch)


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
    if packet["schema"] == DEPENDENT_PACKET_SCHEMA:
        # Capacity may have delayed this request. Revalidate before taking an irreversible execution claim.
        try:
            with writer_lock(Path(job.initiative["mailbox_root"])):
                check_dependency(store, job.initiative, job.message, packet, recipes)
                claimed = job.claim(packet_raw, recipes["recipes_sha256"])
        except DependencyPending as exc:
            return pending_dependency(store, job, exc, wait, recipes["recipes_sha256"])
    else:
        claimed = job.claim(packet_raw, recipes["recipes_sha256"])
    if not claimed:
        return {"job": job.id, "state": "running", "process_group": job.process_group()}
    mailbox = Mailbox(job.initiative["mailbox_root"])
    checkout = packet["checkout"]
    view = MERGE_VIEW_ENV if recipe["kind"] == "merge" else None
    provenance = {"recipes_sha256": recipes["recipes_sha256"]}
    if packet.get("derived_by") == "runner":
        derivation = {key: packet[key] for key in ("derived_by", "dirty_content_sha256", "expected_tree", "host_plan")}
        # The original, hash-bound packet omits these values. Persist them before any execution so a lost runner's
        # resolution can still publish evidence of what was admitted, even when no normal result was written.
        publish_file(job.folder / "derivation.json", encoded(derivation) + b"\n")
        provenance.update(derivation)
    try:
        before = source_state(mailbox, checkout, view)
        branch = head_ref(checkout) if recipe["kind"] == "merge" else None
    except ERRORS as exc:
        write_result(job, "refused", None, reason="could not witness the source: " + str(exc)[:2048], **provenance)
        return settle(store, job, wait)
    if recipe.get("require_clean", False) and before["dirty_content_sha256"] != EMPTY_STATUS:
        write_result(job, "refused", None, reason=clean_refusal(packet["recipe"]), **provenance)
        return settle(store, job, wait)
    if (before["source_revision"], before["source_tree"], before["dirty_content_sha256"]) != (
            packet["commit"], packet["tree"], packet["dirty_content_sha256"]):
        # The job may have waited hours for a slot, so the exact source is checked again here.
        write_result(job, "refused", None, reason="source does not match the packet: it changed while the job waited",
                     **provenance)
        return settle(store, job, wait)
    if recipe.get("require_clean", False):
        # An ignored file changes no status, so one added while the job waited is looked for again here.
        try:
            refuse_paths_outside_commit(checkout, packet["commit"], packet["paths"])
        except ERRORS as exc:
            write_result(job, "refused", None, reason=str(exc)[:2048], **provenance)
            return settle(store, job, wait)
    if recipe["kind"] == "merge" and branch != packet["head_ref"]:
        write_result(job, "refused", None, reason="HEAD points at %s now, not %s as at admit, so the swap would move another "
                     "branch" % (branch or "no branch", packet["head_ref"] or "no branch"), **provenance)
        return settle(store, job, wait)
    if recipe["kind"] == "commit":
        # Admission can precede a capacity wait or claim publication. A lease acquired
        # in between still owns its paths, even though the source bytes did not move.
        try:
            code, overlap = check_paths(store.load(), job.initiative["id"], packet["paths"])
            require(code == 0, json.dumps(overlap, sort_keys=True)[:2048])
        except ERRORS as exc:
            write_result(job, "refused", None, reason="path ownership changed before execution: " + str(exc)[:2048],
                         **provenance)
            return settle(store, job, wait)

    def announce():
        publish_receipt(job, "started", "Job %s started." % job.id, wait)

    # Before the steps and outside their deadline, so a slow probe never eats a recipe's own time.
    provenance["python"] = python_info(recipes) if recipe["kind"] == "command" else None
    export, extra = None, {}
    if recipe.get("require_clean", False):
        # The steps run on exactly the commit, so nothing Git ignores in the checkout can run in its name.
        export = str(job.folder / EXPORT_FOLDER)
        try:
            remove_work_folders(job, (EXPORT_FOLDER,))
            extra["source_export"] = export_commit(checkout, packet["commit"], packet["tree"], export,
                                                   git_stub=recipe.get("export_git", False))
        except ERRORS as exc:
            try:
                remove_work_folders(job, (EXPORT_FOLDER,))
            except OSError:
                pass
            write_result(job, "refused", None, reason="could not export commit %s: %s" % (packet["commit"][:12], str(exc)[:2048]),
                         **provenance)
            return settle(store, job, wait)
    details = {}
    try:
        execution = execute(job, recipe, packet, recipes, announce, details, export)
    except StillRunning as exc:
        # Without a confirmed stop there is no honest result, so the job keeps its slot until root resolves it.
        row = {"job": job.id, "state": "abandoned", "process_group": exc.group, "process_alive": True, "error": str(exc)}
        if details.get("new_commit"):
            row["checkout_state"] = checkout_state(checkout, packet["commit"], details["new_commit"], view)
        return row
    except ERRORS as exc:
        execution = _ExecutionResult(reason="the job could not run: " + str(exc)[:2048], exit_code=NO_VERDICT_EXIT)
    rows, reason, exit_code, created = execution.steps, execution.reason, execution.exit_code, execution.created
    if execution.failed_launch is not None:
        extra["failed_launch"] = execution.failed_launch
    cleanup_error = None
    if export is not None:
        # Removed whatever the outcome: the logs and kept files are the evidence, and a full tree per job would fill the
        # disk. An abandoned job above keeps it, because its processes may still read it; clean removes it then.
        try:
            remove_work_folders(job, (EXPORT_FOLDER,))
            extra["source_export"]["removed"] = True
        except OSError as exc:
            extra["source_export"]["removed"] = False
            cleanup_error = str(exc)[:512]
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
    if recipe.get("keep"):
        extra["kept"] = keep_evidence(job, recipe["keep"])
    extra["tests"] = None
    if recipe.get("expects_tests", False):
        extra["tests"], problem = kept_junit(extra["kept"])
        # An exit 0 over no tests, or over a report nobody can read, proves nothing. A step's own failure keeps its reason.
        if problem and not reason:
            reason, exit_code = problem, NO_VERDICT_EXIT
    if recipe["kind"] == "merge":
        # Every input and the pinned config, so the receipt binds them and anyone can predict the tree again.
        extra["merge"] = {"commit": packet["commit"], "merge": packet["merge"], "merge_bases": details.get("merge_bases"),
                          "expected_tree": packet["expected_tree"], "tree": details.get("tree"),
                          "new_commit": details.get("new_commit"), "config": list(MERGE_CONFIG),
                          "head_ref": packet["head_ref"], "git_version": details.get("git_version")}
    # run_step guards every launched process with stop_for_certain, including a failed
    # process-record write. Unknown stop evidence raises StillRunning above and cannot
    # reach this result. Preserve that confirmation when the last group record is absent.
    write_result(job, "failed" if reason else "completed", exit_code if reason else 0, reason=reason, recipe=packet["recipe"],
                 steps=rows, before=before, after=after, commit=commit, process_stopped_confirmed=True, **provenance, **extra)
    # A build cache is never evidence, and a cargo job's can be gigabytes, so Heavy-Tests leaves nothing behind. Other
    # failed jobs keep the rest of their work for diagnosis until root runs clean.
    names = WORK_FOLDERS if not reason or recipe.get("heavy_tests", False) else ("cargo-target",)
    removed = []
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
    runner = job.runner_alive()
    if runner is None:
        return {"job": job.id, "state": "abandoned", "process_group": group, "process_alive": None,
                "reason": "runner visibility is unknown; retain the original claim and reservation"}
    if runner:
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
                packet, raw = admit(ledger, initiative, message, mailbox, recipes, store)
            except DependencyPending as exc:
                rows.append(pending_dependency(store, job, exc, wait, recipes["recipes_sha256"]))
                continue
            except ERRORS as exc:
                try:
                    rows.append(refuse(store, job, str(exc), wait, recipes["recipes_sha256"]))
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
                record = read_json(claim)
                require(isinstance(record, dict) and record.get("job") == request["holder"][4:]
                        and type(record.get("pid")) is int and record["pid"] > 0
                        and isinstance(record.get("start"), str) and record["start"].isdigit(),
                        "invalid runner claim: " + request["holder"][4:])
                if record.get("process_scope") == process_scope() and process_start(record["pid"]) == record["start"]:
                    owners.add(record["pid"])
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
    runner = job.runner_alive()
    require(runner is not None, "runner visibility is unknown: " + identifier)
    require(not runner, "its runner is still running: " + identifier)
    group = job.process_group()
    require(not (group and group_members(group)), "its process group %s is still running; stop it first" % group)
    unrecorded = job.unrecorded_step()
    if unrecorded:
        require(process_stopped, "step %d started but its process was never recorded, and an earlier step's stopped group "
                "proves nothing about it; check by hand that it stopped, then pass --process-stopped" % unrecorded)
    # runner_alive above has read and checked this claim. A claim written before the hash was stored records null.
    recipes_sha256 = read_json(job.claim_path).get("recipes_sha256")
    require(recipes_sha256 is None or (isinstance(recipes_sha256, str) and SHA256.fullmatch(recipes_sha256) is not None),
            "invalid recipes_sha256 in the claim of job: " + identifier)
    write_result(job, "failed", NO_VERDICT_EXIT, reason="Resolved by root: " + reason, resolved_by_root=True,
                 process_stopped_confirmed=process_stopped, recipes_sha256=recipes_sha256)
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
    for name in CLEANUP_FOLDERS:
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


def recovery_source(job, mailbox, result):
    """Observe the original packet and current source without admitting or running it."""
    if mailbox is None or "brief" not in job.message:
        return {"state": "unavailable", "reason": "original mailbox request is unavailable"}
    packet = strict_json(packet_text(mailbox.brief(job.message["brief"])))
    require(isinstance(packet, dict) and packet.get("schema") in (PACKET_SCHEMA, DEPENDENT_PACKET_SCHEMA),
            "invalid recovery packet")
    checkout = absolute(packet["checkout"], "checkout")
    require(checkout in job.initiative["checkouts"], "checkout is no longer registered for this initiative")
    view = MERGE_VIEW_ENV if "merge" in packet else None
    observed = source_state(mailbox, checkout, view)
    expected = {"source_revision": packet["commit"], "source_tree": packet["tree"],
                "dirty_content_sha256": packet.get("dirty_content_sha256", EMPTY_STATUS)}
    # A completed commit/merge changes source intentionally. Its after-witness, not the old packet,
    # is the reference for later incoming-work revalidation; the original packet remains untouched.
    if result is not None and isinstance(result.get("after"), dict):
        expected = {key: result["after"].get(key) for key in expected}
    return {"state": "match" if all(observed.get(key) == value for key, value in expected.items()) else "changed",
            "expected": expected, "observed": observed}


def recovery_job(store, ledger, initiative, message, records, mailbox):
    job = Job(store.path, initiative, message)
    reservations = [dict(r) for r in ledger.requests.values() if r["holder"] == job.holder]
    held = any(r["state"] in ("queued", "granted") for r in reservations)
    row = {"job": job.id, "owner": initiative["id"] + "/orchestrator", "reservations": reservations,
           "claim": None, "runner_alive": None, "process_alive": None, "receipt": "not_published",
           "source": {"state": "unavailable"}, "next_action": "Revalidate the original source and admission before run-open."}
    result = None
    try:
        if job.folder.exists():
            if job.claim_path.exists():
                row["claim"] = read_json(job.claim_path)
            result = job.result()
            if result is None:
                row["runner_alive"] = job.runner_alive()
                group = job.process_group()
                row["process_group"] = group
                row["process_alive"] = bool(group_members(group)) if group else None
                row["state"] = "running" if row["runner_alive"] is True else "unknown_effect"
                row["next_action"] = "Retain the original reservation; a qualified operator must reconcile process effects."
            else:
                # Historical evidence remains useful when the original process scope
                # cannot be observed. Record it before the independent stop check;
                # a matching receipt alone never promotes or settles the job.
                row["result"] = {"path": str(job.result_path), "sha256": file_sha256(job.result_path),
                                 "state": result["state"], "exit_code": result["exit_code"]}
                row["retained_outputs"] = result.get("kept", [])
                receipt = {"state": result["state"]}
                if result["exit_code"] is not None:
                    receipt["exit_code"] = result["exit_code"]
                if result["state"] != "refused":
                    receipt["evidence"] = job.evidence()
                if result.get("reason") is not None:
                    receipt["reason"] = result["reason"][:4096]
                prior = records.get(receipt_id(job, result["state"]))
                if prior is not None:
                    row["receipt"] = ("match" if "from" in message and receipt_matches(
                        job, prior["message"], receipt, result_body(job, result)) else "mismatch")
                check_settlement_processes(job, result)
                row["state"] = "finished" if row["receipt"] == "match" and not held else "settle_pending"
                row["next_action"] = ("Retain evidence for independent acceptance." if row["state"] == "finished" else
                                      "Reconcile the exact receipt and result; run-open may settle without rerunning the job.")
        else:
            row["state"] = "reserved_not_started" if held else "pending"
        row["source"] = recovery_source(job, mailbox, result)
        if row["source"]["state"] == "changed":
            row["next_action"] = "Revalidate incoming source before dependent work; retain the historical result and claim."
    except ERRORS as exc:
        row.update(state="evidence_error", error=str(exc)[:2048],
                   next_action="Preserve all evidence and capacity; reconcile the unavailable or inconsistent record.")
    return row


def recovery_status(store_path, chosen=()):
    """Read-only, replayable inventory; observations never grant, release, resolve or transfer ownership."""
    require(isinstance(chosen, (tuple, list)) and all(isinstance(item, str) for item in chosen), "invalid initiatives")
    store = Store(store_path)
    ledger = store.load()
    for identifier in chosen:
        ledger.initiative(identifier)
    initiatives = sorted((i for i in ledger.initiatives.values() if not chosen or i["id"] in chosen),
                         key=lambda i: (i["priority"], i["id"]))
    rows, blockers, teams, process_census = [], [], [], {}
    for kind in HEAVY_KINDS:
        try:
            observed = census(store.path, ledger, None, kind)
            process_census[kind] = {**observed, "state": "observed", "admission_free": max(
                0, observed["limit"] - observed["held"] - len(observed["external_roots"]))}
        except ERRORS as exc:
            process_census[kind] = {"state": "unavailable", "admission_free": None, "error": str(exc)[:512]}
            blockers.append({"kind": kind, "owner": "qualified operator", "reason": "census_unavailable",
                             "next_action": "Restore process visibility in the original scope; do not admit or release work."})
    for initiative in initiatives:
        owner = initiative["id"] + "/orchestrator"
        team = initiative_view(ledger, initiative["id"])
        teams.append(team)
        if team["blocked_by"] or team["base_moved"] or team["state"] != "active":
            blockers.append({"initiative": initiative["id"], "owner": owner, "reason": "initiative_pending",
                             "next_action": "Resolve dependencies/state and revalidate the exact incoming source."})
        records, mailbox = {}, None
        if "mailbox_root" in initiative:
            try:
                mailbox = Mailbox(initiative["mailbox_root"])
                records = mailbox.messages()
            except ERRORS as exc:
                blockers.append({"initiative": initiative["id"], "owner": owner, "reason": "mailbox_unavailable",
                                 "error": str(exc)[:512], "next_action": "Restore visibility; retain all reservations."})
        messages = {identifier: record["message"] for identifier, record in records.items()
                    if record["message"]["type"] == "job_request"}
        prefix = "job:" + initiative["id"] + "/"
        for request in ledger.requests.values():
            if request["initiative"] != initiative["id"]:
                continue
            if request["holder"].startswith(prefix):
                identifier = request["holder"][len(prefix):]
                matching(identifier, SLUG, "job message id")
                messages.setdefault(identifier, {"message_id": identifier})
            elif request["state"] in ("granted", "queued"):
                blockers.append({"initiative": initiative["id"], "request_id": request["request_id"],
                                 "holder": request["holder"], "owner": owner, "reason": "retained_reservation",
                                 "next_action": "Correlate original actor/source and terminal evidence; TTL is not release evidence."})
        base = safe_path(store.path / "jobs" / initiative["id"])
        for folder in sorted(base.iterdir()) if base.is_dir() else []:
            safe_path(folder)
            require(folder.is_dir() and SLUG.fullmatch(folder.name) is not None, "unexpected job directory: " + str(folder))
            messages.setdefault(folder.name, {"message_id": folder.name})
        for message in messages.values():
            row = recovery_job(store, ledger, initiative, message, records, mailbox)
            rows.append(row)
            if row["state"] != "finished" or row["source"]["state"] == "changed":
                blockers.append({"job": row["job"], "owner": owner, "reason": row["state"],
                                 "next_action": row["next_action"]})
        if initiative["touched_paths"]:
            _, team["paths"] = check_paths(ledger, initiative["id"], initiative["touched_paths"])
            if team["paths"]["conflict"]:
                blockers.append({"initiative": initiative["id"], "owner": owner, "reason": "path_conflict",
                                 "next_action": "Agree path ownership with the retaining team before admission."})
    return (3 if blockers else 0), {"schema": RECOVERY_SCHEMA, "read_only": True, "seq": ledger.seq,
                                   "capacity": capacity_view(ledger), "capacity_scope": "ledger_only",
                                   "process_census": process_census, "initiatives": teams, "jobs": rows,
                                   "blockers": blockers, "native_qualification": "not_established"}


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
    recovery = commands.add_parser("recovery-status", help="Read retained reservations, source and unknown job effects")
    recovery.add_argument("--initiative", action="append", default=[])
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
        elif args.command == "recovery-status":
            code, result = recovery_status(args.store, args.initiative)
        elif args.command == "resolve":
            # --recipes is accepted but not read: the result records the hash the job's claim stored, the file it ran under.
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
                code, result = 0, {"recipes_sha256": recipes["recipes_sha256"],
                                   "recipes": {name: {"kind": recipe["kind"], "heavy": is_heavy(recipe),
                                                      "heavy_tests": recipe.get("heavy_tests", False),
                                                      "sandbox": recipe["sandbox"],
                                                      "require_clean": recipe.get("require_clean", False),
                                                      "expects_tests": recipe.get("expects_tests", False),
                                                      "export_git": recipe.get("export_git", False)}
                                               for name, recipe in recipes["recipes"].items()}}
            else:
                code, result = run_open(args.store, args.recipes, args.initiative, args.max_jobs, args.census_fixture, args.lock_wait)
    except ERRORS as exc:
        code, result = 2, {"error": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
