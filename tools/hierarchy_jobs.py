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

A heavy job takes a ledger slot, and by default processes the
census finds outside the ledger count against the same limit. Recipes reviewed through check-recipes can instead
report or ignore outside load with census_outside_policy for this pass's own jobs. Pass run-open
--expect-recipes-sha256 to enforce the reviewed recipes hash before admission. A slot is freed only with evidence: a
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
import errno
from collections import namedtuple
from contextlib import ExitStack, contextmanager
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
import uuid
import xml.etree.ElementTree as ElementTree

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hierarchy_git import object_read_argv, object_read_env  # noqa: E402
import hierarchy_hosts  # noqa: E402
from hierarchy_mailbox import (GIT_ID, GIT_STATUS_TIMEOUT_SECONDS, MAX_BYTES, SHA256, SLUG, Mailbox, encoded, fields, integer, matching,  # noqa: E402
                               parse_time, publish_file, read_bytes, read_json, require, safe_path, strict_json, strings, text, timestamp,
                               status_entries, writer_lock)
from hierarchy_wake import stop_group  # noqa: E402
from hierarchy_workspace import (KINDS as LEDGER_KINDS, MAX_HEAVY, MAX_HEAVY_TESTS, Store, absolute, capacity_view,  # noqa: E402
                                 check_paths, grant_next, initiative_view, verify_evidence)


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
FENCE_VERIFIED, FENCE_UNCERTAIN = "verified", "uncertain"
ClaimObservation = namedtuple("ClaimObservation", "state value present parsed read_error")
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
# Outside observations are a bounded, PID-only view; counting always uses the full list.
MAX_OUTSIDE_ROWS = 64
MAX_CENSUS_RECORD_BYTES = 8192
CENSUS_REQUEST_ID = re.compile(r"req-[0-9]{8}")
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
    recipes = validate_recipes(raw)
    # Hash the exact captured bytes, without injecting defaults or reserializing parsed data.
    recipes["recipes_sha256"] = hashlib.sha256(raw).hexdigest()
    return recipes


def validate_recipes(data):
    """Validate captured UTF-8 JSON bytes or an already parsed object, without reopening the input path.

    Return the validated object without adding defaults or a hash. Only the byte reader can bind the file's exact
    recipes_sha256; callers retaining bytes can hash those bytes themselves. Parsed objects are not modified.
    """
    recipes = strict_json(data.decode("utf-8")) if isinstance(data, bytes) else data
    fields(recipes, {"schema", "python", "path", "recipes"},
           {"identity", "env", "hide", "ro_binds", "prefix", "min_free_gigabytes", "census_outside_policy"})
    if "min_free_gigabytes" in recipes:
        integer(recipes["min_free_gigabytes"], "min_free_gigabytes", minimum=0)
    if "census_outside_policy" in recipes:
        policy = recipes["census_outside_policy"]
        require(isinstance(policy, str) and policy in ("count", "report", "ignore"),
                "invalid census_outside_policy: expected count, report or ignore")
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


# The explicit opt-outs of holder_requests. No ledger row can carry one of these objects as a value.
ANY_KIND = object()
ANY_HOLDER = object()
ANY_INITIATIVE = object()
OPEN_STATES = ("queued", "granted")
REQUEST_STATES = ("queued", "granted", "released", "withdrawn")
REQUEST_FIELDS = ("request_id", "initiative", "kind", "holder", "state")


def holder_requests(requests, holder, *, kind, initiative, states):
    """The ledger rows of `holder`, `kind` and `initiative` in one of `states`. Every caller names all three.

    A row is this job's only when it matches every named value exactly. The workspace accepts any holder string from
    any initiative, so a row that carries the job's holder for another initiative, another kind, an unknown kind or a
    malformed row never matches a named kind: it can neither stand in for a grant nor suppress a request. Exact
    lookups skip malformed rows because they match nothing. ANY_KIND and ANY_HOLDER are for deliberately wide safety,
    settlement and reporting scans; there a malformed row raises ValueError instead, because a scan that cannot read a
    row cannot prove the row is not open. ANY_INITIATIVE is only for naming another initiative's conflicting row,
    detecting an ambiguous audit and mirroring grant_next's queue; a permission or audit decision still requires the
    job's own initiative.
    """
    require(kind is ANY_KIND or (isinstance(kind, str) and kind in LEDGER_KINDS),
            "invalid ledger kind filter: use one of %s, or ANY_KIND for a deliberately kind-independent check"
            % ", ".join(LEDGER_KINDS))
    require(holder is ANY_HOLDER or (isinstance(holder, str) and holder),
            "invalid holder filter: pass a holder string, or ANY_HOLDER for a deliberately holder-independent scan")
    require(initiative is ANY_INITIATIVE or (isinstance(initiative, str) and initiative),
            "invalid initiative filter: pass the job's initiative id, or ANY_INITIATIVE to name another "
            "initiative's conflicting row")
    require(isinstance(states, tuple) and states and all(isinstance(state, str) and state in REQUEST_STATES
                                                         for state in states),
            "invalid states filter: pass a non-empty tuple of " + ", ".join(REQUEST_STATES))
    wide = kind is ANY_KIND or holder is ANY_HOLDER
    # A wide scan needs every field readable. An exact lookup needs the fields it compares; any other gap matches nothing.
    needed = REQUEST_FIELDS if wide else ("holder", "kind", "state") + (() if initiative is ANY_INITIATIVE else ("initiative",))
    found = []
    for request in requests:
        if not (isinstance(request, dict) and all(isinstance(request.get(key), str) for key in needed)
                and (not wide or (request["kind"] in LEDGER_KINDS and request["state"] in REQUEST_STATES))):
            # Never echo the row: its values may be attacker-written.
            require(not wide, "malformed ledger request row: stop and inspect the workspace store's event log; "
                              "no reservation is released, granted or reported from an unreadable ledger")
            continue
        if ((holder is ANY_HOLDER or request["holder"] == holder) and (kind is ANY_KIND or request["kind"] == kind)
                and (initiative is ANY_INITIATIVE or request["initiative"] == initiative)
                and request["state"] in states):
            found.append(request)
    return found


def request_summary(request):
    """A bounded, validated name for a ledger row in a refusal, a waiting row or recovery output."""
    initiative = request.get("initiative")
    return {"request_id": census_request_id(request.get("request_id")),
            "initiative": initiative if isinstance(initiative, str) and SLUG.fullmatch(initiative) else "invalid_initiative",
            "kind": request["kind"] if request.get("kind") in LEDGER_KINDS else "invalid_kind",
            "state": request["state"] if request.get("state") in REQUEST_STATES else "invalid_state"}


def foreign_rows(requests, job, *, kind, states=OPEN_STATES):
    """Rows that carry this job's holder but were filed by another initiative. They are never this job's."""
    return [request for request in holder_requests(requests, job.holder, kind=kind, initiative=ANY_INITIATIVE,
                                                   states=states) if request.get("initiative") != job.initiative["id"]]


def foreign_reason(request):
    summary = request_summary(request)
    return ("request %s of initiative %s holds this job's holder for %s; root must check who filed it, then "
            "withdraw or release it" % (summary["request_id"], summary["initiative"], summary["kind"]))


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
    """Only the canonical mailbox of a provisioned Claude base can use its fully validated plan."""
    root = safe_path(Path(initiative["mailbox_root"]))
    base = root.parent
    path = base / hierarchy_hosts.PLAN_FILE
    reason = "derive is for shell-less teams"
    try:
        require(root == base / "mailbox", "registered mailbox is not <base>/mailbox")
        setup = read_json(base / "provision.json")
        require(setup["mailbox_root"] == str(root) and setup["initiative"] == initiative["id"],
                "registered mailbox does not match provision.json")
        plan = hierarchy_hosts.base_plan(base, initiative["id"])
        require(plan is not None and plan["team"] == hierarchy_hosts.CLAUDE, reason)
        raw = read_bytes(path)
        require(strict_json(raw.decode("utf-8")) == plan, "host plan changed while reading")
    except ERRORS as exc:
        raise ValueError(reason + ": " + str(exc)) from exc
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "team": plan["team"]}


class AdmissionHeld(Exception):
    """Another runner already has custody; observing it never grants a second admission writer."""


def admitted_derivation(job, raw, recipes_sha256):
    """The first successful admission is immutable and bound to both the original packet and recipe bytes."""
    reference = read_json(job.folder / "admitted.json")
    fields(reference, {"packet_sha256", "recipes_sha256", "derivation_sha256"})
    saved = read_bytes(job.folder / "packet.md")
    require(saved == raw and reference["packet_sha256"] == hashlib.sha256(raw).hexdigest(),
            "admitted packet does not match the original request")
    require(reference["recipes_sha256"] == recipes_sha256, "recipes changed after admission")
    require(reference["derivation_sha256"] == file_sha256(job.folder / "derivation.json"),
            "admitted derivation evidence changed")
    derived = read_json(job.folder / "derivation.json")
    matching(derived["dirty_content_sha256"], SHA256, "admitted dirty_content_sha256")
    matching(derived["expected_tree"], GIT_ID, "admitted expected_tree")
    require(derived["derived_by"] == "runner", "invalid admitted derivation")
    job.validated_admission()
    return derived


def derivation_provenance(job):
    path = job.folder / "derivation.json"
    if not path.exists():
        return {}
    derived = read_json(path)
    return {key: derived[key] for key in ("derived_by", "dirty_content_sha256", "expected_tree", "host_plan", "changed_paths")}


class DependencyPending(ValueError):
    """No dependent effect was admitted; keep the original request available for reconciliation."""

    def __init__(self, detail, reason="dependency_pending", fields=None):
        super().__init__(detail)
        self.reason = reason
        self.fields = dict(fields or {})

    def row(self, job):
        return {"job": job.id, "state": "waiting", "reason": self.reason, "detail": str(self)[:2048], **self.fields}


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
        # Deliberately kind-independent: any open reservation under the predecessor's one-use holder means its
        # settlement is unfinished, whichever kind it is. Fail closed on another initiative's row under that holder
        # too, but name it: the predecessor's settlement can never free it, so only root can.
        requests = list(store.load().requests.values())
        require(not holder_requests(requests, job.holder, kind=ANY_KIND, initiative=job.initiative["id"],
                                    states=OPEN_STATES), "predecessor reservation is not settled")
        foreign = foreign_rows(requests, job, kind=ANY_KIND)
        if foreign:
            # Held, never refused: another initiative must not be able to end the dependent by filing this row.
            summary = request_summary(foreign[0])
            raise DependencyPending("predecessor " + foreign_reason(foreign[0]), "foreign_reservation",
                                    {"request_id": summary["request_id"], "initiative": summary["initiative"]})
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


def pending_dependency(store, job, exc, wait, recipes_sha256, *, outside_policy=None):
    """A reserved job needs a durable no-effect refusal, not an orphaned slot or release from absence."""
    try:
        if exc.reason == "foreign_reservation":
            # A foreign actor cannot end this job. Withdraw its own queue entries before any grant pass can
            # charge capacity for work that cannot start. Grants still require terminal evidence to settle.
            def withdraw_queued():
                with store.lock():
                    ledger = store.load()
                    own = holder_requests(ledger.requests.values(), job.holder, kind=ANY_KIND,
                                          initiative=job.initiative["id"], states=OPEN_STATES)
                    for request in own:
                        if request["state"] == "queued":
                            store.append(ledger, "withdraw", {"request_id": request["request_id"], "source": "job runner"})
                    return [request_summary(request) for request in own if request["state"] == "granted"]

            retained = patient(withdraw_queued, wait)
            row = exc.row(job)
            action = ("Root: reconcile predecessor reservation %s owned by %s; withdraw it if queued, "
                      "or settle it with its owner's terminal evidence if granted. Run run-open again "
                      "after it clears; this dependent's queued requests were withdrawn."
                      % (exc.fields["request_id"], exc.fields["initiative"]))
            if retained:
                action += (" Retained dependent grants still charge capacity: %s. Repair the predecessor "
                           "blocker so this job can run, or reconcile and settle these grants with "
                           "correlated terminal evidence; do not release them from absence."
                           % ", ".join(r["request_id"] + " (" + r["kind"] + ")" for r in retained))
            return planned_action(row, job.initiative, action)
        # Deliberately kind-independent: a reservation of any kind this job's initiative holds for it is retained,
        # and only the terminal no-effect refusal lets settlement free it; a pending row would strand it. Bound to
        # the initiative: another initiative's row under this holder is not this job's, settlement would not free
        # it, and it must not let that initiative end this job (recovery-status names it).
        if holder_requests(store.load().requests.values(), job.holder, kind=ANY_KIND, initiative=job.initiative["id"],
                           states=OPEN_STATES):
            # refuse takes the exclusive claim first. A competing runner keeps its claim and capacity.
            return refuse(store, job, "dependency changed after capacity admission: " + str(exc), wait, recipes_sha256,
                          outside_policy=outside_policy)
        return exc.row(job)
    except ERRORS as failure:
        return execution_error_row(job, None, failure)


def admit(ledger, initiative, message, mailbox, recipes, store=None, job=None):
    """Everything a job must satisfy before it runs. A ValueError here becomes the refusal's reason."""
    if job is not None and job.planned:
        require(not job.metadata_uncertain, "job metadata observation unverified")
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
    if job is not None:
        job.census_kind = job_kind(recipe) if is_heavy(recipe) else "none"
        job.census_policy = recipes.get("census_outside_policy")
    kind = recipe["kind"]
    derive = "derive" in packet
    if derive:
        require(packet["derive"] == "runner", "derive must be runner")
        require(kind == "commit", "only a commit recipe takes derive")
        host_plan = derive_host_plan(initiative)
        require(store is not None, "derivation requires the workspace store")
        job = job or Job(store.path, initiative, message)
        marker = job.metadata_kind("admitted.json") if job.planned else (
            "regular" if (job.folder / "admitted.json").exists() else "absent")
        require(marker in ("absent", "regular"), "admission marker unverified")
        saved = admitted_derivation(job, raw, recipes["recipes_sha256"]) if marker == "regular" else None
        if saved is not None:
            require(saved["host_plan"] == host_plan, "host plan changed after admission")
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
        dirty = saved["dirty_content_sha256"] if saved is not None else witness["dirty_content_sha256"]
    # Named before the plain mismatch, so a packet that claimed a clean checkout learns why it cannot run.
    require(not recipe.get("require_clean", False) or witness["dirty_content_sha256"] == EMPTY_STATUS, clean_refusal(name))
    require((witness["source_revision"], witness["source_tree"], witness["dirty_content_sha256"]) ==
            (packet["commit"], packet["tree"], dirty), "source does not match the packet")
    if recipe.get("require_clean", False):
        refuse_paths_outside_commit(checkout, packet["commit"], paths)
    admitted = {**packet, "dirty_content_sha256": dirty, "paths": paths}
    if derive:
        if saved is not None:
            admitted.update({key: saved[key] for key in ("expected_tree", "derived_by", "host_plan", "changed_paths")})
            return admitted, raw
        if not job.claim(raw, recipes["recipes_sha256"]):
            raise AdmissionHeld()
        job.admission_owned = True
        derived = derive_commit_tree(admitted, recipes, job, host_plan)
        tree = derived["expected_tree"]
        require(source_state(mailbox, checkout) == witness, "source changed during derivation")
        require(tree != packet["tree"], "this commit would make no change")
        require("expected_tree" not in packet or packet["expected_tree"] == tree,
                "the derived tree %s is not the expected tree %s" % (tree, packet.get("expected_tree")))
        outside = [name for name in derived["changed_paths"] if name not in paths]
        require(not outside, "derive staged files outside paths: " + ", ".join(outside))
        admitted.update({key: derived[key] for key in ("expected_tree", "derived_by", "host_plan", "changed_paths")})
        publish_file(job.folder / "admitted.json", encoded({"packet_sha256": hashlib.sha256(raw).hexdigest(),
                     "recipes_sha256": recipes["recipes_sha256"],
                     "derivation_sha256": file_sha256(job.folder / "derivation.json")}) + b"\n")
        job.validated_admission()
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
    parents, starts, heavy = {}, {}, set()
    for process in process_entries():
        item = process / "cmdline"
        pid = int(item.parent.name)
        try:
            words = [word.decode(errors="replace") for word in item.read_bytes().split(b"\0") if word]
            observed = (item.parent / "stat").read_text(encoding="ascii", errors="replace").rpartition(")")[2].split()
            parents[pid] = int(observed[1])
            starts[pid] = None if observed[0] in ("Z", "X") else observed[19]
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (OSError, ValueError, IndexError) as exc:
            raise ValueError("cannot census process %s: %s" % (pid, exc)) from exc
        if census_command(words, kind):
            heavy.add(pid)
    # Revalidate the step's birth in this census snapshot; a reused PID is never an exemption.
    owners = {pid for pid, start in owners if starts.get(pid) == start}
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
        self.execution_path = self.folder / "execution.json"
        self.admission_owned = False
        self.execution_owned = False
        self.execution_fence = None
        self.execution_published = False
        self.planned = has_host_plan(initiative)
        self.execution_claim_name = "claim.json"
        self.fence_observations = {}
        self.claim_candidates = set()
        self.execution_boundary_crossed = False
        self.metadata_uncertain = False
        self.result_observed = False
        self.attempt_observations = {"result": set(), "execution_nodes": set()}
        self.admission_validated = False
        self.admission_unverified = False
        self.terminal_observed = False
        self.settlement_attempted = False
        self.census_capacity = None
        self.census_request_id = None
        self.census_kind = None
        self.census_policy = None
        self.census_publication = None
        self.census_requests = None
        self.written_result = None

    def recorded_execution_fence(self):
        if self.planned and (self.result_decision() == "unknown" or self.metadata_uncertain
                             or self.admission_unverified):
            return None
        observation = self.fence_observations.get(self.execution_claim_name)
        if observation is not None and observation.state == FENCE_VERIFIED:
            return True
        if (self.admission_unverified or self.execution_boundary_crossed or self.metadata_uncertain
                or self.execution_claim_name in self.claim_candidates):
            return None
        return False if observation is None or observation.present is False else None

    @contextmanager
    def directory_descriptor(self, *, legacy_result=False):
        """Hold the exact job directory beneath an anchored, no-follow parent."""
        from hierarchy_fresh_brief import directory_flags, open_directory, require_secure_publication

        require_secure_publication()
        with ExitStack() as owned:
            try:
                parent = open_directory(self.folder.parent)
            except ValueError as exc:
                if legacy_result and isinstance(exc.__cause__, OSError):
                    raise exc.__cause__
                if isinstance(exc.__cause__, FileNotFoundError):
                    raise FileNotFoundError("job directory absent") from exc
                raise ValueError("job directory unavailable") from exc
            owned.callback(os.close, parent)
            before = os.stat(self.folder.name, dir_fd=parent, follow_symlinks=False)
            if legacy_result and not stat.S_ISDIR(before.st_mode):
                raise NotADirectoryError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), str(self.result_path))
            require(stat.S_ISDIR(before.st_mode), "job directory is not a directory")
            directory = os.open(self.folder.name, directory_flags(), dir_fd=parent)
            owned.callback(os.close, directory)
            after = os.fstat(directory)
            require(stat.S_ISDIR(after.st_mode) and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
                    "job directory changed")
            yield directory

    def observe_fence(self, name=None, directory=None):
        """The sole producer of VERIFIED fence evidence; every other outcome is UNCERTAIN."""
        name = self.execution_claim_name if name is None else name
        value, present, parsed = None, None, False
        try:
            require(name in ("claim.json", "execution.json"), "invalid claim filename")
            with ExitStack() as owned:
                if directory is None:
                    directory = owned.enter_context(self.directory_descriptor())
                try:
                    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    before = None
                    present = False
                require(before is not None, "claim absent")
                present = True
                self.claim_candidates.add(name)
                require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_BYTES, "claim is not a bounded regular file")
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
                owned.callback(os.close, descriptor)
                after = os.fstat(descriptor)
                require(stat.S_ISREG(after.st_mode) and after.st_size <= MAX_BYTES
                        and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), "claim changed")
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    raw = stream.read(MAX_BYTES + 1)
                require(len(raw) <= MAX_BYTES, "claim exceeds its limit")
            value = strict_json(raw.decode("utf-8"))
            parsed = True
            required = {"job", "pid", "start", "at", "process_scope", "recipes_sha256"}
            optional = {"census_kind"} if name == "claim.json" else set()
            require(isinstance(value, dict) and required <= set(value) <= required | optional,
                    "invalid claim fields")
            require(isinstance(value["job"], str) and value["job"] == self.id, "invalid claim job")
            require(type(value["pid"]) is int and value["pid"] > 0, "invalid claim pid")
            require(isinstance(value["start"], str) and re.fullmatch(r"[0-9]+", value["start"]) is not None,
                    "invalid claim start")
            parse_time(value["at"])
            scope = value["process_scope"]
            require(isinstance(scope, dict) and set(scope) == {"boot_id", "pid_namespace"}, "invalid process scope")
            require(isinstance(scope["boot_id"], str)
                    and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", scope["boot_id"]) is not None,
                    "invalid boot id")
            require(isinstance(scope["pid_namespace"], str)
                    and re.fullmatch(r"pid:\[[0-9]+\]", scope["pid_namespace"]) is not None, "invalid pid namespace")
            require(value["recipes_sha256"] is None or (isinstance(value["recipes_sha256"], str)
                    and SHA256.fullmatch(value["recipes_sha256"]) is not None), "invalid recipe digest")
            if "census_kind" in value:
                require(isinstance(value["census_kind"], str) and value["census_kind"] in ("none", *HEAVY_KINDS),
                        "invalid census kind")
            observation = ClaimObservation(FENCE_VERIFIED, value, True, True, None)
        except Exception as exc:
            observation = ClaimObservation(FENCE_UNCERTAIN, value if parsed else None, present, parsed,
                                           None if parsed else exc)
        if self.planned and observation.state == FENCE_UNCERTAIN and name in self.claim_candidates:
            self.metadata_uncertain = True
        if self.planned and name == "execution.json" and observation.present is not False:
            self.attempt_observations["execution_nodes"].add(name)
        previous = self.fence_observations.get(name)
        if previous is None or previous.state != FENCE_VERIFIED or observation.state == FENCE_VERIFIED:
            self.fence_observations[name] = observation
        return observation

    def metadata_kind(self, name):
        try:
            with self.directory_descriptor() as directory:
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                kind = "regular" if stat.S_ISREG(info.st_mode) else "other"
        except FileNotFoundError:
            kind = "absent"
        except Exception:
            kind = "uncertain"
            if self.planned:
                self.metadata_uncertain = True
        if self.planned and name == "admitted.json":
            retained = self.attempt_observations["execution_nodes"]
            if kind != "absent":
                retained.add(name)
                self.execution_claim_name = "execution.json"
                if not self.admission_validated or kind != "regular":
                    self.admission_unverified = True
            elif name in retained:
                self.metadata_uncertain = True
        return kind

    def observe_result(self, directory=None, *, info=None):
        """Accumulate result probes, including a failed enclosing directory acquisition, for this attempt."""
        def record(result):
            self.attempt_observations["result"].add(result)
            if result == "regular":
                self.result_observed = True
            elif result in ("other", "uncertain"):
                self.metadata_uncertain = True
            return result

        try:
            if isinstance(directory, Exception):
                # A failed enclosing acquisition is also an unavailable result observation.
                raise directory
            with ExitStack() as owned:
                if directory is None:
                    directory = owned.enter_context(self.directory_descriptor())
                try:
                    if info is None:
                        info = os.stat(self.result_path.name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    return record("absent")
                # Record before context cleanup: a close error cannot erase this stat observation.
                return record("regular" if stat.S_ISREG(info.st_mode) else "other")
        except FileNotFoundError:
            if (self.planned and not isinstance(directory, Exception)
                    and (self.attempt_observations["execution_nodes"] or self.claim_candidates)):
                self.metadata_uncertain = True
            return record("absent")
        except Exception:
            return record("uncertain")

    def result_decision(self):
        """One attempt-wide decision: observed nodes settle; unresolved probes retain unknown custody."""
        results = self.attempt_observations["result"]
        if self.terminal_observed or results.intersection(("regular", "other")):
            return "settle"
        if "uncertain" in results:
            return "unknown"
        return "absent"

    def observe_existing_fence(self):
        """Classify every metadata node without following links, then use the one claim verifier."""
        nodes = {"folder": "uncertain", "result": "uncertain", "admitted": "uncertain",
                 "execution": "uncertain", "observation": None}
        try:
            with self.directory_descriptor() as directory:
                nodes["folder"] = "directory"
                nodes["result"] = self.observe_result(directory)
                retained = self.attempt_observations["execution_nodes"] if self.planned else set()
                for key, name in (("admitted", "admitted.json"), ("execution", "execution.json")):
                    try:
                        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    except FileNotFoundError:
                        nodes[key] = "absent"
                    except Exception:
                        nodes[key] = "uncertain"
                        if self.planned:
                            self.metadata_uncertain = True
                    else:
                        nodes[key] = "regular" if stat.S_ISREG(info.st_mode) else "other"
                    if self.planned:
                        if nodes[key] != "absent":
                            retained.add(name)
                        elif name in retained:
                            self.metadata_uncertain = True
                if nodes["execution"] != "absent" or "execution.json" in retained:
                    self.execution_claim_name = "execution.json"
                    if self.planned:
                        self.claim_candidates.add("execution.json")
                elif (self.admission_validated or nodes["admitted"] == "regular"
                      or "admitted.json" in retained
                      or (self.planned and (nodes["admitted"] != "absent"
                                           or self.execution_claim_name == "execution.json"))):
                    self.execution_claim_name = "execution.json"
                    self.admission_unverified = (not self.admission_validated
                        or (self.planned and nodes["admitted"] not in ("absent", "regular")))
                else:
                    self.execution_claim_name = "claim.json"
                    self.execution_boundary_crossed = True
                nodes["observation"] = self.observe_fence(directory=directory)
        except FileNotFoundError:
            nodes.update(folder="absent", admitted="absent", execution="absent")
            if self.planned:
                if self.attempt_observations["execution_nodes"] or self.claim_candidates:
                    self.metadata_uncertain = True
            else:
                nodes["result"] = "absent"
        except Exception as exc:
            self.metadata_uncertain = True
            if self.planned:
                nodes["result"] = self.observe_result(exc)
            else:
                nodes["observation"] = self.observe_fence()
        return nodes

    def validated_admission(self):
        self.admission_validated = True
        self.admission_unverified = False
        self.execution_claim_name = "execution.json"
        self.execution_boundary_crossed = False
        if self.planned:
            self.attempt_observations["execution_nodes"].add("admitted.json")

    def runner_alive(self, observation=None):
        """Planned liveness uses the verified snapshot; legacy labels and refusal codes stay compatible."""
        if self.planned:
            if observation is None:
                nodes = self.observe_existing_fence()
                observation = nodes["observation"]
                if self.metadata_uncertain or self.result_decision() == "unknown":
                    return None
                if (nodes["folder"] == "directory" and nodes["execution"] == "absent"
                        and self.execution_claim_name == "execution.json"):
                    # Admission-only jobs still have a staging runner, but its claim is not an execution fence.
                    observation = self.observe_fence("claim.json")
            if observation is None or observation.state != FENCE_VERIFIED:
                return None
        else:
            name = self.execution_path.name if self.execution_path.exists() else self.claim_path.name
            observation = self.observe_fence(name)
            if not observation.parsed:
                if isinstance(observation.read_error, ERRORS) and not isinstance(observation.read_error, (ValueError, OSError)):
                    # The old reader let these reach main's documented refusal handler. This is serialization
                    # compatibility only: the common verifier still returned UNCERTAIN and recorded no fence.
                    raise observation.read_error
                return None
        claim = observation.value

        def inspect():
            require(isinstance(claim, dict) and claim.get("job") == self.id, "claim does not belong to job: " + self.id)
            require(type(claim.get("pid")) is int and claim["pid"] > 0 and isinstance(claim.get("start"), str)
                    and claim["start"].isdigit(), "invalid runner claim: " + self.id)
            if claim.get("process_scope") != process_scope():
                return None
            return process_start(claim["pid"]) == claim["start"]

        if not self.planned:
            return inspect()
        try:
            return inspect()
        except Exception:
            return None

    def result(self):
        """Read with the same limit it was written with, or a valid large result could never be settled."""
        if not self.planned and not self.result_path.exists():
            return None
        try:
            with ExitStack() as owned:
                directory = owned.enter_context(self.directory_descriptor(legacy_result=not self.planned))
                before = os.stat(self.result_path.name, dir_fd=directory, follow_symlinks=False)
                if self.planned:
                    self.observe_result(directory, info=before)
                require(stat.S_ISREG(before.st_mode), "result is not a readable file within its limit")
                if not self.planned:
                    self.result_observed = True
                require(before.st_size <= MAX_RESULT_BYTES, "result is not a readable file within its limit")
                descriptor = os.open(self.result_path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                     dir_fd=directory)
                owned.callback(os.close, descriptor)
                after = os.fstat(descriptor)
                require(stat.S_ISREG(after.st_mode) and after.st_size <= MAX_RESULT_BYTES
                        and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
                        "result is not a readable file within its limit")
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    raw = stream.read(MAX_RESULT_BYTES + 1)
                require(len(raw) <= MAX_RESULT_BYTES, "result is not a readable file within its limit")
        except (OSError, ValueError) as exc:
            if not self.planned:
                # Any failed component belongs to this read; retain its type/errno and the legacy result path.
                if isinstance(exc, OSError) and exc.filename is not None:
                    exc.filename = str(self.result_path)
                raise
            self.observe_result(exc)
            if isinstance(exc, FileNotFoundError):
                require(self.result_decision() != "settle", "job has no validated terminal result")
                return None
            if isinstance(exc, OSError):
                raise ValueError("result is not a readable file within its limit") from exc
            raise
        try:
            result = strict_json(raw.decode("utf-8"))
        except (ValueError, UnicodeError, RecursionError) as exc:
            if not self.planned:
                raise
            raise ValueError("invalid job result schema") from exc
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
        self.terminal_observed = True
        return result

    def claim(self, packet_raw, recipes_sha256=None, *, for_execution=False):
        """The directory excludes competing writers; only its validated claim proves a fence."""
        if self.planned:
            if (self.result_decision() != "absent" or self.attempt_observations["execution_nodes"]
                    or self.claim_candidates or self.execution_boundary_crossed):
                return False
            require(not self.metadata_uncertain, "job metadata observation unverified")
        self.folder.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.folder.mkdir(mode=0o700)
        except FileExistsError:
            if for_execution:
                self.observe_existing_fence()
            return False
        self.execution_claim_name = "claim.json"
        self.execution_boundary_crossed = True
        self.execution_fence = self.folder
        extra = ({"census_kind": self.census_kind}
                 if self.census_policy is not None and self.census_kind is not None else {})
        claim = {"pid": os.getpid(), "start": process_start(os.getpid()), "job": self.id, "at": timestamp(),
                 "process_scope": process_scope(), "recipes_sha256": recipes_sha256, **extra}
        publish_file(self.claim_path, encoded(claim) + b"\n")
        observation = self.observe_fence()
        require(observation.state == FENCE_VERIFIED and observation.value == claim, "claim publication unverified")
        if packet_raw is not None:
            publish_file(self.folder / "packet.md", packet_raw)
        return True


    @contextmanager
    def disposition(self):
        """Serialize execution claims and root resolution; a crashed holder cannot leave a stale file lock."""
        import fcntl  # Linux-only runner; keep recipe inspection importable on other platforms.

        with open(safe_path(self.folder / "disposition.lock"), "a+b") as lock:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError("job disposition is busy: " + self.id) from exc
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def execution_publication_matches(self, claim=None, directory=None):
        """Compatibility predicate; all positive evidence comes from observe_fence."""
        observation = self.observe_fence("execution.json", directory)
        if observation.state == FENCE_VERIFIED:
            return claim is None or observation.value == claim
        return False if observation.present is False else None

    def publish_execution_claim(self, raw):
        """Publish without replacement, and validate the linked file before recording its evidence."""
        require(len(raw) <= MAX_BYTES, "record exceeds %d bytes" % MAX_BYTES)
        from hierarchy_fresh_brief import require_secure_publication

        require_secure_publication()
        pending = ".pending-" + uuid.uuid4().hex
        self.execution_claim_name = "execution.json"
        with ExitStack() as owned:
            try:
                directory = owned.enter_context(self.directory_descriptor())
            except (ValueError, OSError) as exc:
                raise ValueError("execution claim directory unavailable") from exc
            created = False
            try:
                descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     0o600, dir_fd=directory)
                created = True
                try:
                    with os.fdopen(descriptor, "wb", closefd=False) as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
                finally:
                    os.close(descriptor)
                try:
                    os.link(pending, self.execution_path.name, src_dir_fd=directory, dst_dir_fd=directory,
                            follow_symlinks=False)
                except FileExistsError:
                    self.observe_fence(directory=directory)
                    raise
                self.execution_published = True
                self.execution_boundary_crossed = True
                self.execution_fence = self.execution_path
                observation = self.observe_fence(directory=directory)
                require(observation.state == FENCE_VERIFIED and observation.value == strict_json(raw.decode("utf-8")),
                        "execution claim publication unverified")
            finally:
                if created:
                    os.unlink(pending, dir_fd=directory)

    def take_execution(self, packet_raw, recipes_sha256):
        """Successful derivation admission and the separate execution claim have distinct custody."""
        if self.planned:
            if self.result_decision() == "settle":
                return False
            require(not self.metadata_uncertain, "job metadata observation unverified")
            if "execution.json" in self.attempt_observations["execution_nodes"]:
                return False
        self.execution_fence = None
        self.execution_published = False
        self.execution_boundary_crossed = False
        if self.planned:
            marker = self.metadata_kind("admitted.json")
            require(marker in ("absent", "regular"), "admission marker unverified")
            admitted = marker == "regular"
        else:
            admitted = (self.folder / "admitted.json").exists()
        if not admitted:
            return self.claim(packet_raw, recipes_sha256, for_execution=True)
        self.execution_claim_name = "execution.json"
        with self.disposition():
            raw = read_bytes(self.folder / "packet.md") if packet_raw is None else packet_raw
            admitted_derivation(self, raw, recipes_sha256)
            check_settlement_processes(self, {"steps": []})
            claim = {"pid": os.getpid(), "start": process_start(os.getpid()), "job": self.id, "at": timestamp(),
                     "process_scope": process_scope(), "recipes_sha256": recipes_sha256}
            try:
                self.publish_execution_claim(encoded(claim) + b"\n")
            except Exception as exc:
                if self.execution_published:
                    # The boundary was crossed even if the linked file could not be verified.
                    raise ValueError("execution claim was published; custody requires recovery") from exc
                if isinstance(exc, FileExistsError):
                    return False
                if isinstance(exc, OSError):
                    observation = self.observe_fence()
                    if observation.state == FENCE_VERIFIED:
                        if observation.value == claim:
                            self.execution_boundary_crossed = True
                            self.execution_fence = self.execution_path
                    elif observation.present is not False:
                        self.execution_fence = self.execution_path
                raise
            self.execution_fence = self.execution_path
            if not self.planned:
                if self.result_path.exists():
                    return False
            else:
                self.observe_result()
                decision = self.result_decision()
                if decision == "settle":
                    return False
                require(decision == "absent", "result publication unverified")
            observation = self.observe_fence()
            require(observation.state == FENCE_VERIFIED and observation.value == claim
                    and self.runner_alive(observation) is True, "execution claim ownership changed: " + self.id)
            return True

    def process_record(self):
        try:
            record = read_json(self.process_path)
        except (ValueError, OSError):
            return None
        return record if isinstance(record, dict) else None

    def process_group(self):
        return (self.process_record() or {}).get("group")

    def staging_process_group(self):
        """An optional diagnostic never follows a replaced node or falls back to a path read."""
        from hierarchy_fresh_brief import _read_reference, _reference_descriptors

        try:
            require(_reference_descriptors(), "staging process metadata requires directory descriptor support")
            _, raw = _read_reference(self.process_path, limit=MAX_BYTES, capture=True)
            record = strict_json(raw.decode("utf-8"))
        except ERRORS:
            return None
        group = record.get("group") if isinstance(record, dict) else None
        return group if type(group) is int and group > 0 else None

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
    # Settlement of another runner's result is known execution custody, not a partial claim of this attempt.
    job.settlement_attempted = True
    result = job.result()
    if job.planned:
        require(result is not None, "job has no validated terminal result")
    check_settlement_processes(job, result)
    state = result["state"]
    evidence = job.evidence() if state != "refused" or (job.folder / "derivation.json").exists() else None
    publish_receipt(job, state, result_body(job, result), wait, exit_code=result["exit_code"], evidence=evidence,
                    reason=result.get("reason"))
    reference = {"path": str(job.result_path), "sha256": file_sha256(job.result_path)}

    def release():
        with store.lock():
            ledger = store.load()
            # Deliberately kind-independent, bound to the initiative: the job's terminal result is the correlated
            # evidence for every row its own initiative holds under its one-use holder (a retained kind would be
            # stranded for good), and is no evidence at all about another initiative's row (recovery-status names it).
            for request in holder_requests(list(ledger.requests.values()), job.holder, kind=ANY_KIND,
                                           initiative=job.initiative["id"], states=OPEN_STATES):
                if request["state"] == "granted":
                    verify_evidence(reference)
                    store.append(ledger, "release", {"request_id": request["request_id"], "evidence": reference})
                elif request["state"] == "queued":
                    store.append(ledger, "withdraw", {"request_id": request["request_id"], "source": "job runner"})

    # Most jobs hold no slot, and a job that holds nothing should not wait on the store's lock. Same scope as release.
    if holder_requests(store.load().requests.values(), job.holder, kind=ANY_KIND, initiative=job.initiative["id"],
                       states=OPEN_STATES):
        patient(release, wait)
    row = {"job": job.id, "state": state, "exit_code": result["exit_code"], "result": str(job.result_path)}
    if result.get("reason"):
        row["reason"] = result["reason"]
    return census_result_row(row, job)


def write_result(job, state, exit_code, *, reason=None, recipe=None, steps=(), before=None, after=None, commit=None, **extra):
    if job.census_capacity is not None:
        extra["capacity"] = job.census_capacity
    result = {"schema": RESULT_SCHEMA, "job": job.id, "state": state, "exit_code": exit_code, "reason": reason,
              "recipe": recipe, "steps": list(steps), "before": before, "after": after, "commit": commit,
              "finished_at": timestamp(), **extra}
    publish_file(job.result_path, encoded(result) + b"\n", limit=MAX_RESULT_BYTES)
    job.written_result = result


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


def refuse(store, job, reason, wait, recipes_sha256=None, *, outside_policy=None):
    job.census_policy = outside_policy
    if not job.admission_owned and not job.take_execution(None, recipes_sha256):
        if job.planned:
            return taken_execution_row(store, job, None, wait)
        return {"job": job.id, "state": "running", "process_group": job.process_group()}
    job.execution_owned = True
    if job.admission_owned:
        check_settlement_processes(job, {"steps": []})
    job.census_capacity = job_grant_census(store, job, policy=outside_policy)
    write_result(job, "refused", None, reason=reason[:4096], recipes_sha256=recipes_sha256, **derivation_provenance(job))
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
    def __init__(self, argv, env=None, capture=False, verdict=False, raw=False):
        # A verdict step's exit is the plan's to judge: it receives (exit code, output), so a non-zero exit can halt the
        # job with a reason of its own, such as the conflicted paths, instead of a bare exit code. Its output is the
        # captured stdout, or else its log, so that reason can quote git's own error.
        self.argv, self.env, self.capture, self.verdict = argv, env or {}, capture, verdict
        self.raw = raw


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


def derive_commit_tree(packet, recipes, job, host_plan):
    """Stage under the job's durable claim: uncertain processes never become terminal admission refusals."""
    def plan():
        tree = yield from stage_commit_tree(packet, recipes, job)
        names = yield Step(commit_git(recipes) + ["diff-tree", "--no-commit-id", "--no-renames", "--name-only", "-r", "-z",
                                                packet["commit"], tree], capture=True, raw=True)
        return {"expected_tree": tree, "changed_paths": sorted(names.split("\0")[:-1])}

    def stopped():
        try:
            check_settlement_processes(job, {"steps": []})
        except ERRORS as exc:
            raise StillRunning(job.process_group() or 0, "staging stop is unconfirmed: " + str(exc)) from exc

    derived = {"derived_by": "runner", "dirty_content_sha256": packet["dirty_content_sha256"],
               "host_plan": host_plan, "expected_tree": None, "changed_paths": None}
    try:
        result = execute(job, recipes["recipes"][packet["recipe"]], packet, recipes, lambda: None, {}, plan=plan())
    except ERRORS:
        stopped()
        publish_file(job.folder / "derivation.json", encoded(derived) + b"\n")
        raise
    stopped()
    if result.reason is None:
        matching(result.created["expected_tree"], GIT_ID, "derived expected_tree")
        derived.update(result.created)
    publish_file(job.folder / "derivation.json", encoded(derived) + b"\n")
    require(result.reason is None, "could not derive expected_tree: " + str(result.reason))
    return derived


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
    output = source.read_text(encoding="utf-8", errors="replace") if source else None
    return row, output if step.raw or output is None else output.strip()


def execute(job, recipe, packet, recipes, on_start, details, export=None, *, plan=None, step_offset=0):
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
            row, output = run_step(job, step_offset + len(rows) + 1, step, sandbox, env, checkout, deadline, started_once, prefix)
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


def observed_result_action():
    return ("Root: repair store or audit access; retain the observed result and any reservation. Inspect "
            "recovery-status and validate terminal evidence before settlement; do not rerun execution.")



def taken_execution_row(store, job, packet, wait):
    """Record a peer's evidence without acquiring its execution custody."""
    job.observe_existing_fence()
    derived = job.admission_validated if packet is None else packet.get("derived_by") == "runner"
    if derived:
        job.observe_result()
    if job.planned:
        decision = job.result_decision()
        if decision == "settle":
            return settle(store, job, wait)
        if decision == "unknown" or job.recorded_execution_fence() is not True:
            return unknown_custody_row(job, job.staging_process_group())
    elif derived and job.result_path.exists():
        return settle(store, job, wait)
    return {"job": job.id, "state": "running", "process_group": job.process_group()}



def run_job(store, job, packet, packet_raw, recipes, wait):
    recipe = recipes["recipes"][packet["recipe"]]
    job.census_kind = job_kind(recipe) if is_heavy(recipe) else "none"
    job.census_policy = recipes.get("census_outside_policy")
    if packet["schema"] == DEPENDENT_PACKET_SCHEMA:
        # Capacity may have delayed this request. Revalidate before taking an irreversible execution claim.
        try:
            with writer_lock(Path(job.initiative["mailbox_root"])):
                check_dependency(store, job.initiative, job.message, packet, recipes)
                claimed = job.take_execution(packet_raw, recipes["recipes_sha256"])
        except DependencyPending as exc:
            return pending_dependency(store, job, exc, wait, recipes["recipes_sha256"],
                                      outside_policy=recipes.get("census_outside_policy"))
    else:
        claimed = job.take_execution(packet_raw, recipes["recipes_sha256"])
    if not claimed:
        return taken_execution_row(store, job, packet, wait)
    job.execution_owned = True
    job.census_capacity = job_grant_census(store, job, job.census_kind, job.census_policy)
    mailbox = Mailbox(job.initiative["mailbox_root"])
    checkout = packet["checkout"]
    view = MERGE_VIEW_ENV if recipe["kind"] == "merge" else None
    provenance = {"recipes_sha256": recipes["recipes_sha256"]}
    if packet.get("derived_by") == "runner":
        provenance.update(derivation_provenance(job))
        try:
            require(derive_host_plan(job.initiative) == packet["host_plan"], "host plan changed after admission")
        except ERRORS as exc:
            write_result(job, "refused", None, reason=str(exc)[:2048], **provenance)
            return settle(store, job, wait)
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
        # Derivation's logs/process records stay in this same folder; execution must append, never overwrite them.
        offset = max((int(path.name[5:-4]) for path in job.folder.glob("step-*.log")
                      if path.name[5:-4].isdigit()), default=0) if packet.get("derived_by") == "runner" else 0
        execution = execute(job, recipe, packet, recipes, announce, details, export, step_offset=offset)
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


def has_host_plan(initiative):
    """Reporting metadata only; admission validates the plan before derived work."""
    root = initiative.get("mailbox_root")
    return root is not None and os.path.lexists(Path(root).parent / hierarchy_hosts.PLAN_FILE)


def planned_action(row, initiative, action):
    """Additional operational guidance belongs to planned initiatives; retain existing legacy row bytes.

    This metadata check only selects reporting. Admission validates the plan separately before any derived work.
    """
    if has_host_plan(initiative):
        row["next_action"] = action
    return row


def blocked_row(job, exc):
    row = {"job": job.id, "state": "settle_pending", "error": str(exc)[:2048]}
    action = (observed_result_action() if job.planned and job.result_observed
              and job.recorded_execution_fence() is not True else
              "Run run-open again after repairing the reported mailbox, storage or "
              "settlement error; an existing claim is never executed twice.")
    return census_result_row(planned_action(row, job.initiative, action), job)


def unverified_custody_action():
    return ("Root: preserve any candidate claim and reservation; inspect recovery-status and establish execution "
            "custody before settlement or retry. Do not retry execution while custody is unknown.")


def unknown_custody_row(job, group=None, reason="execution_custody_unknown"):
    # Historical claim verification supplies preservation guidance, never present custody or execution permission.
    observation = job.fence_observations.get(job.execution_claim_name)
    if observation is not None and observation.state == FENCE_VERIFIED:
        action = ("Root: preserve the original execution fence and reservation; inspect recovery-status, "
                  "the original claim and process scope. Establish custody and stopped-process evidence "
                  "before recovery or settlement. Do not remove the fence or retry execution.")
    elif job.result_observed:
        action = observed_result_action()
    else:
        action = unverified_custody_action()
    return planned_action({"job": job.id, "state": "abandoned", "process_group": group, "process_alive": None,
                           "reason": reason}, job.initiative, action)



def execution_error_row(job, packet, exc):
    """Preserve observed evidence; a retained path never certifies its own publication."""
    if not job.execution_owned and not job.settlement_attempted:
        if job.planned and (job.metadata_uncertain or job.admission_unverified):
            return unknown_custody_row(job)
        if job.execution_boundary_crossed:
            return unknown_custody_row(job)
        if job.execution_fence is not None:
            observation = job.observe_fence()
            if observation.present is False:
                job.claim_candidates.discard(job.execution_claim_name)
            else:
                return unknown_custody_row(job)
    return blocked_row(job, exc)



def visit_existing(store, job, wait):
    """Rows for prior attempts. Planned liveness consumes the same validated snapshot as recovery."""
    observation = None
    if job.planned:
        nodes = job.observe_existing_fence()
        job.observe_result()
        decision = job.result_decision()
        if decision == "settle":
            try:
                return settle(store, job, wait)
            except ERRORS as exc:
                return blocked_row(job, exc)
        if decision == "unknown":
            return unknown_custody_row(job)
        if nodes["folder"] == "absent":
            return unknown_custody_row(job) if job.metadata_uncertain else None
        if nodes["folder"] != "directory":
            return unknown_custody_row(job)
        if nodes["admitted"] == "regular" and nodes["execution"] == "absent":
            if job.metadata_uncertain:
                return unknown_custody_row(job)
            try:
                check_settlement_processes(job, {"steps": []})
            except ERRORS as exc:
                return blocked_row(job, exc)
            return None
        if nodes["admitted"] not in ("absent", "regular") and nodes["execution"] == "absent":
            # A staging runner can be live even when its admission marker cannot be verified.
            # Its claim never becomes an execution fence, nor permits a stopped-runner receipt.
            group = job.staging_process_group()
            if job.runner_alive(job.observe_fence("claim.json")) is True:
                return {"job": job.id, "state": "running", "process_group": group}
            return unknown_custody_row(job, group)
        if job.admission_unverified and nodes["admitted"] == "absent":
            return unknown_custody_row(job, job.staging_process_group())
        observation = nodes["observation"]
        if observation is None or observation.state != FENCE_VERIFIED:
            return unknown_custody_row(job, job.process_group(),
                                       "runner visibility is unknown; retain the original claim and reservation")
        if job.metadata_uncertain:
            return unknown_custody_row(job, job.staging_process_group())
    else:
        # Compatibility selects the old labels; it cannot create positive fence evidence.
        if job.result_path.exists():
            job.observe_result()
            try:
                return settle(store, job, wait)
            except ERRORS as exc:
                return blocked_row(job, exc)
        if not job.folder.exists():
            return None
        job.observe_existing_fence()
        if (job.folder / "admitted.json").exists() and not job.execution_path.exists():
            try:
                check_settlement_processes(job, {"steps": []})
            except ERRORS as exc:
                return blocked_row(job, exc)
            return None
    group = job.process_group()
    runner = job.runner_alive(observation)
    if runner is None:
        return unknown_custody_row(job, group,
                                   "runner visibility is unknown; retain the original claim and reservation")
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
        row.update(process_alive=None, unrecorded_step=unrecorded)
    return row



def finish_closed_jobs(store, ledger, initiative, records, open_ids, wait, rows, admission=None):
    """A receipt can go out before a busy store lets the slot go. The request is closed by then, so the ledger is the record."""
    prefix = "job:" + initiative["id"] + "/"
    # Deliberately kind-independent, bound to the initiative: an open row of any kind that this initiative holds
    # under a closed job's holder is settled. Another initiative's row under that holder is not, or it would make
    # the finished job settle again on every pass; recovery-status names it as that initiative's retained reservation.
    # One settlement per job and pass: settle covers all of the job's own rows, however many there are.
    settled = set()
    for request in holder_requests(ledger.requests.values(), ANY_HOLDER, kind=ANY_KIND, initiative=initiative["id"],
                                   states=OPEN_STATES):
        identifier = request["holder"][len(prefix):] if request["holder"].startswith(prefix) else None
        if identifier and identifier not in open_ids and identifier in records and identifier not in settled:
            settled.add(identifier)
            job = Job(store.path, initiative, records[identifier]["message"])
            if admission is not None:
                admission.participate(job)
            job.observe_existing_fence()
            job.observe_result()
            decision = job.result_decision() if job.planned else None
            retained = decision == "settle" if job.planned else job.result_path.exists()
            if retained:
                try:
                    rows.append(settle(store, job, wait))
                except ERRORS as exc:
                    rows.append(blocked_row(job, exc))
            elif job.planned and decision == "unknown":
                rows.append(unknown_custody_row(job))


def admit_requests(store, ledger, initiatives, recipes, wait, rows, admission=None):
    """Settle what is finished and refuse what cannot run, in priority order. Returns the jobs ready to run."""
    ready = []
    for initiative in initiatives:
        try:
            mailbox = Mailbox(initiative["mailbox_root"])
            records = mailbox.messages()
            requests = mailbox.open_job_requests(records)
        except ERRORS as exc:
            if admission is not None:
                admission.remember_initiative(initiative)
            rows.append({"initiative": initiative["id"], "state": "mailbox_error", "error": str(exc)[:512]})
            continue
        finish_closed_jobs(store, ledger, initiative, records, {message["message_id"] for message in requests}, wait, rows,
                           admission=admission)
        for message in requests:
            job = Job(store.path, initiative, message)
            if admission is not None:
                admission.participate(job)
            existing = visit_existing(store, job, wait)
            if existing is not None:
                rows.append(existing)
                continue
            try:
                packet, raw = admit(ledger, initiative, message, mailbox, recipes, store, job)
            except AdmissionHeld:
                rows.append(visit_existing(store, job, wait) or {"job": job.id, "state": "waiting", "reason": "admission_busy"})
                continue
            except StillRunning as exc:
                rows.append({"job": job.id, "state": "abandoned", "process_group": job.process_group(),
                             "process_alive": None, "reason": str(exc)})
                continue
            except DependencyPending as exc:
                rows.append(pending_dependency(store, job, exc, wait, recipes["recipes_sha256"],
                                               outside_policy=recipes.get("census_outside_policy")))
                continue
            except ERRORS as exc:
                if job.execution_fence is not None and not job.admission_owned:
                    # A failed admission claim already crossed this attempt's exclusive fence. Retrying via
                    # refuse/take_execution would clear that custody marker and mistake our directory for a peer.
                    rows.append(execution_error_row(job, None, exc))
                    continue
                try:
                    rows.append(refuse(store, job, str(exc), wait, recipes["recipes_sha256"],
                                       outside_policy=recipes.get("census_outside_policy")))
                except ERRORS as failure:
                    rows.append(execution_error_row(job, None, failure))
                continue
            ready.append((job, packet, raw))
    return ready


def enqueue(store, job, kind, wait):
    """Withdraw queued other heavy kinds and keep the request for the `kind` the recipe needs. Returns None, or why not:

    ("stale_grant", row): the job's own initiative holds a granted row of another heavy kind but no grant of the current
    kind. Nothing is filed; the caller waits for root to reconcile and settle the stale slot with evidence. A grant of
    the current kind always permits execution; settlement releases additional grants with the job's result as evidence.
    ("holder_conflict", row): another initiative has an open `kind` row carrying this job's holder. The ledger
    de-duplicates on (kind, holder) across initiatives, so that row blocks the job's own request and is never its."""
    outcome = []

    def attempt():
        outcome.clear()
        with store.lock():
            ledger = store.load()
            own = job.initiative["id"]
            current = holder_requests(ledger.requests.values(), job.holder, kind=kind, initiative=own, states=OPEN_STATES)
            stale = [request for other in HEAVY_KINDS if other != kind for request in
                     holder_requests(ledger.requests.values(), job.holder, kind=other, initiative=own, states=OPEN_STATES)]
            matching, granted = reconcile_job_grant(store, ledger, job, kind)
            if granted is not None and matching is None:
                outcome.append(("stale_grant", granted))
                return
            # A queued row of a kind the job no longer needs would otherwise be granted a slot it never uses.
            for request in stale:
                if request["state"] == "queued":
                    store.append(ledger, "withdraw", {"request_id": request["request_id"], "source": "job runner"})
            # Kind- and initiative-aware: only an open request of this kind filed by the job's own initiative is the
            # job's place in this kind's queue. Another kind's reservation must not suppress it.
            if current:
                return
            conflict = foreign_rows(ledger.requests.values(), job, kind=kind)
            if conflict:
                outcome.append(("holder_conflict", conflict[0]))
                return
            store.append(ledger, "request", {"request_id": "req-%08d" % (ledger.seq + 1), "initiative": own,
                                             "kind": kind, "holder": job.holder, "reference": job.id})

    patient(attempt, wait)
    return outcome[0] if outcome else None


def stale_heavy_grant(ledger, job, kind):
    return next((request for request in holder_requests(
        ledger.requests.values(), job.holder, kind=ANY_KIND, initiative=job.initiative["id"], states=("granted",))
        if request["kind"] in HEAVY_KINDS and request["kind"] != kind), None)


def reconcile_job_grant(store, ledger, job, kind):
    """Under the grant lock, derive this job's grants and remove a stale-only job from its current kind's queue."""
    current = holder_requests(ledger.requests.values(), job.holder, kind=kind, initiative=job.initiative["id"],
                              states=OPEN_STATES)
    matching = next((request for request in current if request["state"] == "granted"), None)
    stale = stale_heavy_grant(ledger, job, kind)
    if matching is None and stale is not None:
        for request in current:
            if request["state"] == "queued":
                store.append(ledger, "withdraw", {"request_id": request["request_id"], "source": "job runner"})
    return matching, stale


def stale_grant_row(job, request, kind):
    summary = request_summary(request)
    return {"job": job.id, "state": "waiting", "kind": kind, "reason": "stale_grant",
            "request_id": summary["request_id"], "initiative": summary["initiative"],
            "next_action": ("Job %s now needs %s but holds granted request %s for %s. Root must reconcile and settle "
                            "that reservation with evidence before this job can request or run its current kind."
                            % (job.id, kind, summary["request_id"], summary["kind"]))}


def holder_conflict_row(job, kind, request):
    """Waiting, not refused: another initiative must not be able to end this job by filing a row under its holder."""
    summary = request_summary(request)
    return {"job": job.id, "state": "waiting", "kind": kind, "reason": "holder_conflict",
            "request_id": summary["request_id"], "initiative": summary["initiative"],
            "next_action": "The job has not started: " + foreign_reason(request)
            + ". The next run-open then files this job's own request."}


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


def census_owner(store_path, request):
    """The job's recorded live step (PID, birth) exempt from the outside census, or None.

    A held slot is held whoever filed it, but an exemption names whose live processes are ledger work, so it needs
    more: a canonical job:<initiative>/<id> holder filed by that same initiative, and that job's own claim from this
    process scope, still naming the same process. The job's process record binds its own step, never all later work
    of that reusable runner. Another initiative's row and a holder that is not canonical exempt
    nothing and never read a claim. For a canonical own-initiative row, a claim in the job's folder that is malformed or
    names another job still refuses the census, as before."""
    holder = request["holder"]
    identifier = holder[len("job:"):] if holder.startswith("job:") else None
    if identifier is None or JOB_ID.fullmatch(identifier) is None or identifier.split("/")[0] != request["initiative"]:
        return None
    claim = safe_path(Path(store_path) / "jobs" / identifier / "claim.json")
    if not claim.exists():
        return None
    # Only a canonical own-initiative row reaches its job's folder, so a claim there that names another job, or is
    # malformed, is corruption: refuse the census, as before, rather than count or exempt.
    execution = safe_path(claim.with_name("execution.json"))
    for path in ([claim, execution] if execution.exists() else [claim]):
        record = read_json(path)
        require(isinstance(record, dict) and record.get("job") == identifier
                and type(record.get("pid")) is int and record["pid"] > 0
                and isinstance(record.get("start"), str) and record["start"].isdigit(), "invalid runner claim: " + identifier)
    if record.get("process_scope") != process_scope() or process_start(record["pid"]) != record["start"]:
        return None
    process = safe_path(claim.with_name("process.json"))
    if not process.exists():
        return None
    step = read_json(process)
    if (isinstance(step, dict) and type(step.get("step")) is int and step["step"] > 0
            and type(step.get("group")) is int and step["group"] > 0
            and isinstance(step.get("start"), str) and step["start"].isdigit()
            and process_start(step["group"]) == step["start"]):
        return step["group"], step["start"]
    return None


def census(store_path, ledger, fixture, kind, outside_policy=None):
    """Observe a kind's capacity; absent policy keeps the raw count view, including recovery-status.

    check-recipes shows explicit policies and marks non-default values; job results record recipes_sha256.
    run-open can enforce the reviewed hash with --expect-recipes-sha256. Known gap: the team loop does not yet
    pass that flag, so reviewers must compare the init and result hashes there. The policy comes from recipes,
    including templates selected by team configuration, not env or job packets. Under the grant lock, run_kind
    applies report/ignore only when the next eligible holder belongs to this pass; otherwise it counts outside
    load. Relaxed admission knowingly accepts outside load, including another team's work or a container seeing
    only its own namespace (container spec amendment 7). Count stays the default.
    """
    held = ledger.held(kind)
    view = {"limit": ledger.limits[kind], "held": len(held), "external_roots": [],
            "census": "fixture" if fixture is not None else "proc"}
    if outside_policy == "ignore":
        # Do not read the fixture or walk /proc for outside roots under this reviewed policy.
        view["census"] = "none"
        return {**view, "outside_policy": "ignore"}
    if fixture is not None:
        roots = fixture_roots(fixture, kind)
    else:
        owners = set()
        # Only grants of the observed kind cover its processes. Another heavy kind cannot hide outside load here.
        # Every initiative's grants are read, but census_owner exempts only a job its own initiative granted.
        for request in holder_requests(ledger.requests.values(), ANY_HOLDER, kind=kind, initiative=ANY_INITIATIVE,
                                       states=("granted",)):
            owner = census_owner(store_path, request)
            if owner is not None:
                owners.add(owner)
        roots = outside_roots(owners, kind)
    view["external_roots"] = [] if outside_policy == "report" else roots
    if outside_policy is not None:
        require(all(type(pid) is int and pid > 0 for pid in roots), "invalid census fixture pid")
        view["outside_policy"] = outside_policy
        view["outside"] = [{"pid": pid, "class": "pytest" if kind == "heavy" else "cargo"}
                           for pid in sorted(roots)[:MAX_OUTSIDE_ROWS]]
        if len(roots) > MAX_OUTSIDE_ROWS:
            view["outside_truncated"] = len(roots) - MAX_OUTSIDE_ROWS
    return view


def run_heavy(store, heavy, recipes, wait, fixture, budget, rows, store_busy=False, admission=None):
    """Each kind is a slot class of its own, so one kind being full never holds the other. Returns the budget left."""
    for kind in HEAVY_KINDS:
        waiting = {holder: entry for holder, entry in heavy.items()
                   if job_kind(recipes["recipes"][entry[1]["recipe"]]) == kind}
        budget = run_kind(store, kind, waiting, recipes, wait, fixture, budget, rows, store_busy, everyone=heavy,
                          admission=admission)
    return budget


def census_request_id(value):
    return value if isinstance(value, str) and CENSUS_REQUEST_ID.fullmatch(value) else "invalid_request_id"


def census_record_path(store, request_id):
    # Ledger replay predates this file format and does not validate request IDs as path components.
    reference = census_request_id(request_id)
    require(reference != "invalid_request_id", "invalid census request id")
    return safe_path(store.path / "census" / (reference + ".json"))


def validate_census_record(record, request):
    fields(record, {"request_id", "holder", "kind", "capacity"})
    require(census_request_id(record["request_id"]) != "invalid_request_id", "invalid census request id")
    require(all(record[key] == request[key] for key in ("request_id", "holder", "kind")),
            "census record does not match its grant")
    require(record["kind"] in HEAVY_KINDS, "invalid census record kind")
    view = record["capacity"]
    fields(view, {"outside_policy", "census", "limit", "held", "external_roots"},
           {"outside", "outside_truncated", "outside_policy_applied"})
    policy = view["outside_policy"]
    require(isinstance(policy, str) and policy in ("count", "report", "ignore"), "invalid census record policy")
    if "outside_policy_applied" in view:
        require(view["outside_policy_applied"] == "count" and policy == "count", "invalid applied census record policy")
    limit = integer(view["limit"], "census limit", maximum=MAX_HEAVY if record["kind"] == "heavy" else MAX_HEAVY_TESTS)
    integer(view["held"], "census held", minimum=0, maximum=limit - 1)
    roots = view["external_roots"]
    require(isinstance(roots, list) and len(roots) < limit
            and all(type(pid) is int and pid > 0 for pid in roots) and roots == sorted(roots),
            "invalid census record roots")
    if policy == "ignore":
        require(view["census"] == "none" and roots == [] and "outside" not in view
                and "outside_truncated" not in view, "invalid ignored census record")
        return view
    require(view["census"] in ("fixture", "proc"), "invalid census record source")
    outside = view.get("outside")
    require(isinstance(outside, list) and len(outside) <= MAX_OUTSIDE_ROWS, "invalid census record outside rows")
    for row in outside:
        fields(row, {"pid", "class"})
        require(type(row["pid"]) is int and row["pid"] > 0
                and row["class"] == ("pytest" if record["kind"] == "heavy" else "cargo"),
                "invalid census record outside row")
    pids = [row["pid"] for row in outside]
    require(pids == sorted(pids), "unsorted census record outside rows")
    if "outside_truncated" in view:
        integer(view["outside_truncated"], "census truncation", maximum=2 ** 63 - 1)
        require(len(outside) == MAX_OUTSIDE_ROWS, "invalid census record truncation")
    if policy == "report":
        require(roots == [], "report census record counts outside roots")
    else:
        require(roots == pids and "outside_truncated" not in view and view["held"] + len(roots) < limit,
                "count census record does not match its roots")
    return view


def census_marker(request, policy, census="unrecorded", reason=None):
    marker = {"census": census, "request_id": census_request_id(request.get("request_id"))}
    if policy is not None:
        marker = {"outside_policy": policy, **marker}
    if reason is not None:
        marker["reason"] = reason
    if census == "publish_failed":
        marker["publish_failed"] = True
    return marker


def read_census_record_bytes(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(safe_path(path), flags)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_CENSUS_RECORD_BYTES,
                "census record is not a regular file within its limit")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_CENSUS_RECORD_BYTES + 1)
        require(len(raw) <= MAX_CENSUS_RECORD_BYTES, "census record exceeds size limit")
        return raw
    finally:
        os.close(descriptor)


def read_grant_census(store, request, policy=None):
    marker = census_marker(request, policy)
    if marker["request_id"] == "invalid_request_id":
        return {**marker, "census": "invalid_record", "reason": "invalid_request_id"}
    try:
        path = census_record_path(store, request["request_id"])
        try:
            raw = read_census_record_bytes(path)
        except FileNotFoundError:
            return marker if policy is not None else None
        return validate_census_record(strict_json(raw.decode("utf-8")), request)
    except ERRORS:
        # Do not echo attacker-written keys, values, filenames or parser excerpts into a result.
        return {**marker, "census": "invalid_record",
                "reason": "Grant census record failed strict validation; inspect census/<request_id>.json."}


def publish_grant_census(store, request, view):
    if census_request_id(request.get("request_id")) == "invalid_request_id":
        return census_marker(request, view["outside_policy"], "invalid_record", "invalid_request_id")
    try:
        record = {key: request[key] for key in ("request_id", "holder", "kind")}
        record["capacity"] = view
        validate_census_record(record, request)
        path = census_record_path(store, request["request_id"])
        raw = encoded(record) + b"\n"
        try:
            publish_file(path, raw, limit=MAX_CENSUS_RECORD_BYTES)
        except FileExistsError:
            # A retry must match bytes, not merely the record's shape. Preserve conflicting files untouched.
            if read_census_record_bytes(path) != raw:
                return census_marker(request, view["outside_policy"], "invalid_record", "conflict")
    except ValueError:
        return census_marker(request, view["outside_policy"], "invalid_record", "invalid_record")
    except ERRORS:
        # The grant is already durable. Audit I/O cannot abort the pass, and raw OS errors may contain paths.
        return census_marker(request, view["outside_policy"], "publish_failed", "publish_failed")
    return None


def job_grant_census(store, job, kind=None, policy=None):
    # Legacy stores pay no ledger replay for an optional feature they have never used. A retained grant record,
    # however, belongs to the grant even if an executor later changes or removes its recipes policy.
    try:
        if policy is None and not (store.path / "census").exists():
            return None
        kind = kind if kind is not None else job.census_kind
        if kind is None and job.claim_path.exists():
            kind = read_json(job.claim_path).get("census_kind")
        if kind not in HEAVY_KINDS:
            return None
        requests = job.census_requests
        if requests is None:
            requests = store.load().requests.values()
        # Every granted row of this kind under the holder, whoever filed it, so a partial match makes the audit
        # ambiguous instead of silently choosing; only a lone row of the job's own initiative is its grant (below).
        grants = holder_requests(requests, job.holder, kind=kind, initiative=ANY_INITIATIVE, states=("granted",))
        if not grants:
            return None
        if policy is None:
            # Only this job's records activate historical provenance; unrelated files never change legacy bytes.
            references = [census_request_id(r["request_id"]) for r in grants]
            if not any(reference != "invalid_request_id" and
                       os.path.lexists(store.path / "census" / (reference + ".json")) for reference in references):
                return None
        if len(grants) > 1:
            return census_marker({}, policy, "invalid_record", "ambiguous_grant")
        request = grants[0]
        if request.get("initiative") != job.initiative["id"]:
            # Another initiative's grant under this holder, and its census record, are never this job's audit.
            return None
        job.census_request_id = census_request_id(request["request_id"])
        if job.census_request_id == "invalid_request_id":
            return census_marker(request, policy, "invalid_record", "invalid_request_id")
        publication = job.census_publication
        if publication is not None:
            if census_request_id(publication.get("request_id")) == job.census_request_id:
                return publication
            return census_marker(request, policy, "invalid_record", "invalid_record")
        return read_grant_census(store, request, policy)
    except ERRORS:
        # An unavailable lookup does not prove that this job was granted or had an audit record.
        return None


def census_summary(view, request_id=None):
    # Sorts after every actionable row field in the loop's 512-character JSON prefix. No PID lists or free text.
    summary = {key: view[key] for key in ("outside_policy", "outside_policy_applied", "census", "limit", "held") if key in view}
    summary.update({"external_roots_count": len(view.get("external_roots", [])),
                    "outside_count": len(view.get("outside", [])) + view.get("outside_truncated", 0),
                    "outside_truncated": view.get("outside_truncated", 0)})
    if view["census"] in ("unrecorded", "invalid_record", "publish_failed"):
        summary.update({key: None for key in ("external_roots_count", "outside_count", "outside_truncated")})
    if view.get("publish_failed") is True:
        summary["publish_failed"] = True
    if view.get("reason") in ("publish_failed", "conflict", "ambiguous_grant", "invalid_request_id"):
        summary["reason"] = view["reason"]
    if request_id is not None:
        summary["request_id"] = census_request_id(request_id)
    return summary


def census_result_row(row, job):
    # Only a result atomically published by this Job instance can add a summary to this pass's row.
    result = job.written_result
    if result is not None and result.get("capacity") is not None:
        row["z_census"] = census_summary(result["capacity"], job.census_request_id)
    return row


def waiting_owner(waiting, request):
    """The waiting job a ledger row is for: its holder and filed by that job's own initiative. Otherwise None."""
    entry = waiting.get(request.get("holder")) if isinstance(request.get("holder"), str) else None
    if entry is None or request.get("initiative") != entry[0].initiative["id"]:
        return None
    return entry[0]


def is_stale_heavy_kind(owner_kind, granted_kind):
    return owner_kind in HEAVY_KINDS and owner_kind != granted_kind


def admission_outside_policy(ledger, kind, waiting, policy):
    if policy not in ("report", "ignore"):
        return policy
    # Match hierarchy_workspace.grant_next's eligibility and (priority, seq) ordering exactly, on its locked
    # snapshot. No public selection helper exists. Tied keys are ambiguous even if min() would pick one.
    eligible = []
    # Every holder and initiative: grant_next's own queue for this kind.
    for request in holder_requests(ledger.requests.values(), ANY_HOLDER, kind=kind, initiative=ANY_INITIATIVE,
                                   states=("queued",)):
        initiative = ledger.initiatives[request["initiative"]]
        blockers = ledger.unresolved(initiative)
        if initiative["state"] == "active" and not blockers:
            eligible.append(request)
    if not eligible:
        return "count"

    def order(request):
        return ledger.initiatives[request["initiative"]]["priority"], request["seq"]

    chosen = min(eligible, key=order)
    chosen_key = order(chosen)
    # Relax only for a row this pass's own job filed; another initiative's row under its holder counts.
    if sum(order(request) == chosen_key for request in eligible) != 1 or waiting_owner(waiting, chosen) is None:
        return "count"
    return policy


class PostGrantFailure(Exception):
    """The pass changed the ledger; preserve its rows and return the documented root-needed code, never refusal."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class GrantAdmission:
    """In-memory custody of this pass's acknowledged durable grants, independent of later ledger readability."""

    def __init__(self, store, recipes):
        self.store, self.recipes = store, recipes
        self.explicit = "census_outside_policy" in recipes
        self.records = []
        self.outcomes = []
        self.initiatives = {}
        self.participants = set()
        self.jobs = {}
        self.owners = {}
        self.row_facts = {}
        self.stage = "post_grant_step_failed"

    def remember_initiative(self, initiative):
        """Choose reporting compatibility once for this owner, never from another initiative's grant."""
        identifier = initiative["id"]
        if identifier not in self.initiatives:
            self.initiatives[identifier] = {"initiative": identifier, "planned": has_host_plan(initiative)}
        return self.initiatives[identifier]

    def participate(self, job):
        self.participants.add(job.initiative["id"])
        if job.id not in self.jobs:
            self.jobs[job.id] = {"job": job, **self.remember_initiative(job.initiative)}
            self.owners[(job.initiative["id"], job.holder)] = {"job": job, "kind": None}

    def admitted(self, job, packet):
        """Save the validated owner and required kind before any job can leave the scheduling maps."""
        key = (job.initiative["id"], job.holder)
        if self.owners[key]["kind"] is None:
            recipe = self.recipes["recipes"][packet["recipe"]]
            self.owners[key]["kind"] = job_kind(recipe) if is_heavy(recipe) else "none"

    def capture(self, row, job=None, scope=None, actual=True):
        """Freeze owner and custody facts with the outcome, without reading paths during recovery."""
        known = self.row_facts.get(id(row))
        if known is not None:
            return known
        if job is None and scope is not None:
            job = scope.get("owner_job") or scope.get("job") or scope.get("stale_job")
        participant = self.jobs.get(job.id if job is not None else row.get("job") or row.get("stale_job"))
        if participant is not None:
            job = participant["job"] if job is None else job
            scope = participant if scope is None else scope
        if scope is None:
            scope = self.initiatives[row["initiative"]]
        facts = {"row": row, "initiative": scope["initiative"], "planned": scope["planned"],
                 "job": job.id if job is not None else None,
                 "job_outcome": bool(job and actual and row.get("job") == job.id),
                 "fence": job.recorded_execution_fence() if job is not None else False,
                 "result_observed": bool(job and job.result_observed),
                 "execution_owned": bool(job and job.execution_owned),
                 "settlement_attempted": bool(job and job.settlement_attempted),
                 "terminal": row["state"] in ("completed", "failed", "refused")
                             or bool(job and (job.terminal_observed or job.written_result is not None))}
        self.row_facts[id(row)] = facts
        return facts

    def capture_rows(self, rows):
        for row in rows:
            self.capture(row)

    def candidate_owner(self, candidates, request):
        """The review-base owner selection, evaluated at the original grant and reporting boundaries."""
        owner = waiting_owner(candidates, request)
        kind = job_kind(self.recipes["recipes"][candidates[owner.holder][1]["recipe"]]) if owner is not None else None
        matching = owner is not None and kind == request["kind"]
        return {"job": owner if matching else None,
                "stale_job": owner if owner is not None and is_stale_heavy_kind(kind, request["kind"]) else None,
                "kind": kind}

    def serialization_owner(self, record, candidates=None):
        """Keep persistent ownership out of every legacy row, including recovery of an earlier grant."""
        if record["planned"]:
            return record["planned_owner"]
        return (self.candidate_owner(candidates, record["request"]) if candidates is not None
                else record["legacy_owner"])

    def remember(self, request, view, candidates, initiative):
        owner = self.owners.get((request["initiative"], request["holder"]))
        job = owner["job"] if owner is not None else None
        matching = owner is not None and owner["kind"] == request["kind"]
        self.participants.add(initiative["id"])
        record = {"request": dict(request), "view": dict(view), "publication": None, "attempted": False,
                  "handled": False, "failure": None,
                  "planned_owner": {"job": job if matching else None,
                                    "stale_job": job if owner is not None and is_stale_heavy_kind(owner["kind"], request["kind"]) else None,
                                    "kind": owner["kind"] if owner is not None else None},
                  "legacy_owner": self.candidate_owner(candidates, request), "owner_job": job,
                  **self.remember_initiative(initiative)}
        self.records.append(record)
        return record

    def publish(self, record):
        if not record["attempted"]:
            record["attempted"] = True
            if self.explicit:
                try:
                    record["publication"] = publish_grant_census(self.store, record["request"], record["view"])
                except Exception:
                    # Even an unexpected publication failure cannot erase the already acknowledged grant.
                    record["publication"] = census_marker(record["request"], record["view"].get("outside_policy",
                                                           self.recipes["census_outside_policy"]),
                                                           "publish_failed", "publish_failed")
        return record["publication"]

    def reason(self, exc):
        if isinstance(exc, ValueError) and str(exc).startswith("workspace store is busy;"):
            return "post_grant_store_busy"
        return self.stage

    def handled(self, record, row, job=None):
        if row is not None:
            # Execution can use an already granted replacement, with no acknowledged record in this iteration.
            self.outcomes.append(self.capture(row, job=job, scope=record, actual=job is not None))
        if record is not None:
            record["handled"], record["row"] = True, row

    def legacy_recovery_rows(self, rows, pending, reason):
        """Retain the original global arbitration decisions, so filtering by owner preserves legacy row bytes."""
        additions = []
        recovered = False
        for record in self.records:
            self.publish(record)
            if record["handled"]:
                continue
            request = record["request"]
            owner = self.serialization_owner(record)
            job = owner["job"]
            state = ("settle_pending" if job.execution_owned or job.settlement_attempted else "waiting") if job is not None else "granted_elsewhere"
            row = {"state": state,
                   "kind": request["kind"], "request_id": census_request_id(request["request_id"]), "reason": reason,
                   "next_action": "Root: preserve the reservation; repair store or audit access, then reconcile and "
                                  "settle with correlated terminal evidence."}
            if job is not None:
                row["job"] = job.id
            else:
                row["holder"] = request["holder"]
                if owner["stale_job"] is not None:
                    row.update(stale_job=owner["stale_job"].id, reason="stale_kind", failure_reason=reason)
            if self.explicit:
                row["z_census"] = census_summary(record["publication"] or record["view"], request["request_id"])
            self.handled(record, row)
            additions.append((row, self.row_facts[id(row)], "reservation"))
            recovered = True
        reported = {row.get("job") for row in rows}
        reported.update(row.get("job") for row, _, _ in additions)
        for job, packet, _ in pending.values():
            if job.id not in reported:
                row = {"job": job.id, "state": "waiting", "kind": job_kind(self.recipes["recipes"][packet["recipe"]]),
                       "reason": reason}
                additions.append((row, self.capture(row, job=job), "pending"))
                reported.add(job.id)
        if not recovered:
            # Terminal rows remain terminal. The loop raises holds from row states, not from run-open's exit alone.
            action = "Root: inspect and reconcile the store; retain terminal evidence and do not rerun completed work."
            record = self.records[-1]
            request = record["request"]
            owner = self.serialization_owner(record)
            job = owner["job"] or owner["stale_job"]
            row = {"state": "settle_pending" if job is not None else "granted_elsewhere",
                   "reason": reason, "next_action": action}
            row.update({"job": job.id} if job is not None else {"holder": request["holder"]})
            additions.append((row, self.capture(row, job=job, scope=record), "fallback"))
        return additions

    def recovery_contexts(self, rows, faults):
        contexts = {owner: {} for owner in faults}
        for source in (self.outcomes, (self.row_facts.get(id(row)) for row in rows)):
            for facts in source:
                if facts is None or facts["initiative"] not in contexts:
                    continue
                context = facts["row"]
                job = facts["job"]
                if job is not None:
                    owned = contexts[facts["initiative"]]
                    previous = owned.get(("job", job))
                    # Reservation rows describe capacity, not what the job's attempt did. A later stale-kind
                    # grant must never replace an actual waiting, running or terminal outcome for that job.
                    if previous is None or not previous["job_outcome"] or facts["job_outcome"]:
                        owned[("job", job)] = facts
                elif context.get("holder") is not None:
                    contexts[facts["initiative"]][("request_id", census_request_id(context.get("request_id")))] = facts
        return contexts

    def recovery_action(self, field, facts):
        context = facts["row"]
        action = "Root: repair store or audit access; "
        if field == "request_id":
            return action + "preserve the holder's reservation and reconcile it with correlated terminal evidence."
        if facts["terminal"]:
            if context["state"] in ("completed", "failed", "refused"):
                return "Root: inspect and reconcile the store; retain terminal evidence and do not rerun completed work."
            return (action + "retain terminal evidence. Run run-open again to retry settlement; "
                    "do not rerun completed work.")
        if facts["result_observed"] and facts["fence"] is not True:
            return observed_result_action()
        if context["state"] == "running" and facts["fence"] is not True:
            return (action + "preserve the running job's staging runner and reservation; inspect recovery-status "
                    "and establish execution custody before settlement or retry. Do not rerun it.")
        if facts["fence"] is False and not any(facts[key] for key in
                ("execution_owned", "settlement_attempted")):
            if context["state"] == "waiting":
                return action + "this job has not started. Preserve any reservation and reconcile its blockers before run-open."
            return (action + "this attempt has not started execution. Run run-open again after repairing the "
                    "reported error; existing claims are rechecked and never executed twice.")
        if facts["fence"] is True:
            if context["state"] == "running":
                return (action + "preserve the running job's custody and reservation; inspect recovery-status before "
                        "settlement. Do not rerun it.")
            return (action + "preserve execution custody, the original fence and any reservation; inspect "
                    "recovery-status and establish stopped-process evidence before settlement or retry.")
        return unverified_custody_action()

    def recover(self, rows, pending, reason):
        """Choose compatibility per recorded owner; never read the ledger or acquire new execution custody."""
        original_count = len(rows)
        faults = {}
        for owner, scope in self.initiatives.items():
            if owner in self.participants and scope["planned"]:
                # One fault point per planned owner, before looking up any outcome or retired reservation.
                fault = {"state": "mailbox_error", "reason": reason,
                         "next_action": "Root: repair store or audit access; preserve custody, reservation and terminal "
                                        "evidence before reconciliation. Do not infer permission to retry execution."}
                faults[owner] = fault
                rows.append(fault)
        for index in range(original_count):
            self.capture(rows[index])
        for row, facts, category in self.legacy_recovery_rows(rows, pending, reason):
            if facts["planned"]:
                if category == "fallback":
                    continue
                if row.get("reason") == reason:
                    del row["reason"]
                row.pop("failure_reason", None)
            rows.append(row)
        contexts = self.recovery_contexts(rows, faults)
        for owner, fault in faults.items():
            for index, ((field, identifier), facts) in enumerate(contexts[owner].items()):
                diagnostic = fault if index == 0 else {}
                diagnostic.update({field: identifier, "state": "settle_pending" if field == "job" else "granted_elsewhere",
                                   "next_action": self.recovery_action(field, facts)})
                if diagnostic is not fault:
                    rows.append(diagnostic)
            if not contexts[owner]:
                fault["initiative"] = owner


class GrantAdmissionStore(Store):
    """Reconcile immediately after the real grant event, inside grant_next's existing store lock."""

    def __init__(self, store, after_grant, remember):
        super().__init__(store.path)
        self.original, self.after_grant, self.remember = store, after_grant, remember
        self.last = None

    def append(self, ledger, kind, data):
        event = self.original.append(ledger, kind, data)
        if kind == "grant":
            # Record durability before any reconciliation can fail. Publication is attempted after unlocking, even
            # when this callback could not withdraw a stale queue row (e.g. the event history reached its limit).
            request = ledger.request(data["request_id"])
            self.last = self.remember(request, ledger.initiatives[request["initiative"]])
            try:
                self.after_grant(ledger)
            except Exception:
                self.last["failure"] = "post_grant_reconcile_failed"
        return event


class MatchingJobGrant(Exception):
    """Stop grant_next before it grants another row when its locked snapshot already grants this pass's job."""

    def __init__(self, holder, ledger, held):
        super().__init__("matching job grant found under the grant lock")
        self.holder, self.ledger, self.held = holder, ledger, held


def run_kind(store, kind, waiting, recipes, wait, fixture, budget, rows, store_busy, everyone=None, admission=None):
    """Grant in the ledger's own order, which applies the owner's priorities, until nothing more can start."""
    held_reason = "store_busy" if store_busy else None
    capacity = None
    minimum = recipes.get("min_free_gigabytes", 0)
    candidates = waiting if everyone is None else everyone
    admission = GrantAdmission(store, recipes) if admission is None else admission
    for job, packet, _ in candidates.values():
        admission.participate(job)
        admission.admitted(job, packet)
    held = {}
    seen = {}

    def reconcile(ledger):
        grants, blocked = {}, {}
        for holder, (job, packet, _) in candidates.items():
            current_kind = job_kind(recipes["recipes"][packet["recipe"]])
            matching, stale = reconcile_job_grant(store, ledger, job, current_kind)
            if matching is not None:
                grants[holder] = matching
            elif stale is not None:
                blocked[holder] = stale_grant_row(job, stale, current_kind)
        return grants, blocked

    def snapshot():
        with store.lock():
            ledger = store.load()
            grants, blocked = reconcile(ledger)
            return ledger, grants, blocked

    def remember(request, initiative):
        return admission.remember(request, seen, candidates, initiative)

    grant_store = None
    if waiting and budget > 0 and not store_busy:
        grant_store = GrantAdmissionStore(store, reconcile, remember)
    while waiting and budget > 0 and not store_busy:
        publication = None
        record = None
        seen = {}

        def outside(locked):
            nonlocal held
            # Re-derive under grant_next's lock: even a job previously found stale-only can now have its matching
            # grant. Do not grant a sibling instead or classify this job using an earlier waiting map.
            seen.clear()
            grants, held = reconcile(locked)
            existing = next((holder for holder in waiting if holder in grants), None)
            if existing is not None:
                raise MatchingJobGrant(existing, locked, held)
            active = {holder: entry for holder, entry in waiting.items() if holder not in held}
            policy = recipes.get("census_outside_policy")
            applied = admission_outside_policy(locked, kind, active, policy)
            seen.update(census(store.path, locked, fixture, kind, applied))
            if applied != policy:
                seen["outside_policy_applied"] = applied
            return seen["external_roots"]

        try:
            admission.stage = "post_grant_ledger_unreadable"
            ledger, grants, held = patient(snapshot, wait)
            admission.stage = "post_grant_step_failed"
            if shutil.disk_usage(store.path).free < minimum * 1000000000:
                held_reason = "low_disk"
                break
            granted = next((holder for holder in waiting if holder in grants), None)
            census_requests = ledger.requests.values()
            if granted is None:
                if all(holder in held for holder in waiting):
                    break
                code, answer = patient(lambda: grant_next(grant_store, kind, outside=outside), wait)
                capacity = dict(seen) or capacity
                if code != 0:
                    held_reason = answer.get("reason", "not_granted")
                    break
                request = answer["granted"]
                granted = request["holder"]
                census_requests = [request]
                request_id = census_request_id(request["request_id"])
                record = grant_store.last
                publication = admission.publish(record)
                if record["failure"] is not None:
                    raise PostGrantFailure(record["failure"])
                # The grant itself changed the state: withdraw any newly stale-only job's queued current-kind row
                # before a later grant in this pass can take it. All admitted jobs remain visible until attempted.
                admission.stage = "post_grant_ledger_unreadable"
                ledger, grants, held = patient(snapshot, wait)
                admission.stage = "post_grant_step_failed"
                ownership = admission.serialization_owner(record, candidates)
                owner = ownership["job"] or ownership["stale_job"]
                current_kind = ownership["kind"]
                if ledger.request(request["request_id"])["state"] == "released":
                    # Release is positive terminal evidence. Keep the audit record, but never recover it as reserved.
                    admission.handled(record, None)
                    if owner is None or current_kind != kind or granted in grants or granted not in waiting:
                        continue
                if owner is None or current_kind != kind or granted not in waiting:
                    row = planned_action({"state": "granted_elsewhere", "holder": granted, "request_id": request_id},
                           ledger.initiatives[request["initiative"]],
                           ("Root: re-admit the owning job through run-open for its initiative and "
                                           "clear its dependency or reservation blockers; a grant alone does not "
                                           "authorize job execution." if granted.startswith("job:") else
                                           "The holder may start its already authorized work; retain the reservation "
                                           "until correlated terminal evidence permits settlement."))
                    if ownership["stale_job"] is not None:
                        row.update(stale_job=ownership["stale_job"].id, reason="stale_kind", next_action=(
                            "Job %s now needs %s; this %s grant is additional capacity, not its execution grant. It runs "
                            "only on a matching grant; otherwise it waits for root to reconcile and settle this reservation. "
                            "Settlement releases additional grants with the job's result as evidence."
                            % (owner.id, current_kind, kind)))
                    if "census_outside_policy" in recipes:
                        row["z_census"] = census_summary(publication or seen, request_id)
                    rows.append(row)
                    admission.handled(record, row)
                    continue
                if granted not in grants:
                    # A competing executor can finish and settle this matching grant while its census is published.
                    # Preserve the exclusive-claim loser's outcome without attempting execution on a missing grant.
                    job, packet, _ = waiting[granted]
                    nodes = job.observe_existing_fence()
                    exists = (nodes["execution"] != "absent" if packet.get("derived_by") == "runner"
                              else nodes["folder"] != "absent")
                    if job.planned:
                        exists = exists or job.result_decision() != "absent"
                    else:
                        fence = job.execution_path if packet.get("derived_by") == "runner" else job.folder
                        exists = fence.exists()
                    if exists:
                        waiting.pop(granted)
                        if everyone is not None:
                            everyone.pop(granted, None)
                        budget -= 1
                        try:
                            row = taken_execution_row(store, job, packet, wait)
                        except ERRORS as exc:
                            row = blocked_row(job, exc)
                        rows.append(row)
                        admission.handled(record, row, job=job)
                    continue  # Without a claim, the next locked snapshot decides how the job waits.
        except MatchingJobGrant as existing:
            granted, ledger, held = existing.holder, existing.ledger, existing.held
            census_requests = ledger.requests.values()
        except ValueError as exc:
            if any(not record["handled"] for record in admission.records):
                raise PostGrantFailure(admission.reason(exc)) from exc
            if "busy" not in str(exc):
                raise
            held_reason, store_busy = "store_busy", True
            break
        job, packet, raw = waiting[granted]
        # The job has its matching grant, including if another kind was granted during this admission. That extra
        # reservation cannot block execution; settlement releases it with this job's result, and the row names it.
        admission.stage = "post_grant_ledger_unreadable"
        stale = stale_heavy_grant(ledger, job, kind)
        admission.stage = "post_grant_step_failed"
        job.census_publication = publication
        job.census_requests = census_requests
        budget -= 1
        try:
            row = run_job(store, job, packet, raw, recipes, wait)
        except ERRORS as exc:
            row = execution_error_row(job, packet, exc)
        admission.stage = "post_grant_step_failed"
        waiting.pop(granted)
        if everyone is not None:
            everyone.pop(granted, None)
        if stale is not None:
            detail = "Additional heavy-kind request %s requires this job's result as settlement evidence." % (
                request_summary(stale)["request_id"])
            row["detail"] = (row.get("detail", "") + " " + detail).strip()
        rows.append(row)
        admission.handled(record, row, job=job)
    for job, _, _ in waiting.values():
        if budget > 0 and not store_busy and job.holder in held:
            rows.append(held[job.holder])
            continue
        row = {"job": job.id, "state": "waiting", "kind": kind,
               "reason": "job_limit" if budget <= 0 else held_reason or "job_limit"}
        # A used budget stops further admission, but does not erase a census already observed in this pass.
        if capacity is not None:
            if "census_outside_policy" in recipes:
                row["z_census"] = census_summary(capacity)
            else:
                row["capacity"] = capacity
        rows.append(row)
    return budget


NEEDS_ROOT = {"waiting", "running", "abandoned", "settle_pending", "mailbox_error", "granted_elsewhere"}


def run_open(store_path, recipes_path, chosen, max_jobs, fixture, wait, expect_recipes_sha256=None):
    require(type(max_jobs) is int and max_jobs > 0, "invalid max-jobs")
    recipes = load_recipes(recipes_path)
    if expect_recipes_sha256 is not None:
        matching(expect_recipes_sha256, SHA256, "expected recipes sha256")
        require(recipes["recipes_sha256"] == expect_recipes_sha256,
                "recipes changed since team init; re-run the reviewed team init")
    require(Path("/proc/self/stat").exists(), "the job runner needs /proc")
    store = Store(store_path)
    ledger = store.load()
    for identifier in chosen:
        ledger.initiative(identifier)
    initiatives = sorted((i for i in ledger.initiatives.values() if i["state"] == "active" and "mailbox_root" in i
                          and (not chosen or i["id"] in chosen)), key=lambda i: (i["priority"], i["id"]))
    rows = []
    admission = GrantAdmission(store, recipes)
    ready = admit_requests(store, ledger, initiatives, recipes, wait, rows, admission=admission)
    for job, packet, _ in ready:
        admission.admitted(job, packet)
    admission.capture_rows(rows)
    budget = max_jobs
    heavy = {}
    store_busy = False
    for job, packet, raw in ready:
        recipe = recipes["recipes"][packet["recipe"]]
        if is_heavy(recipe):
            # Preserve legacy queue sequence even when earlier light work consumed the execution budget.
            # run_kind gates its grant snapshots and attempts on budget, after enqueue has retained that place.
            heavy[job.holder] = (job, packet, raw)
            try:
                outcome = enqueue(store, job, job_kind(recipe), wait)
            except ValueError as exc:
                # Nothing has started, so this job just waits. Other work still gets done and reported.
                if "busy" not in str(exc):
                    raise
                store_busy = True
                continue
            if outcome is None:
                continue
            reason, request = outcome
            if reason == "holder_conflict":
                del heavy[job.holder]
                rows.append(holder_conflict_row(job, job_kind(recipe), request))
                continue
            # A stale-only job remains admitted: a matching grant can appear later in this pass. run_kind derives its
            # final state under the grant lock, rather than freezing a waiting row from this enqueue snapshot.
        elif budget > 0:
            budget -= 1
            try:
                rows.append(run_job(store, job, packet, raw, recipes, wait))
            except ERRORS as exc:
                rows.append(execution_error_row(job, packet, exc))
        else:
            rows.append({"job": job.id, "state": "waiting", "reason": "job_limit"})
    admission.capture_rows(rows)
    try:
        run_heavy(store, heavy, recipes, wait, fixture, budget, rows, store_busy, admission=admission)
        if admission.records:
            # Empty kind passes need no Store construction. Still check the path boundary after acknowledged
            # effects, so a post-completion root swap is reported without replaying or changing any prior row.
            safe_path(store.path)
    except PostGrantFailure as exc:
        admission.recover(rows, heavy, exc.reason)
        return 3, {"rows": rows}
    except Exception as exc:
        if not admission.records:
            raise
        admission.recover(rows, heavy, admission.reason(exc))
        return 3, {"rows": rows}
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
    with job.disposition():
        require(not job.result_path.exists(), "job is already finished: " + identifier)
        runner = job.runner_alive()
        if job.planned:
            require(job.result_decision() != "settle", "job is already finished: " + identifier)
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
        job.census_capacity = job_grant_census(store, job)
        write_result(job, "failed", NO_VERDICT_EXIT, reason="Resolved by root: " + reason, resolved_by_root=True,
                     process_stopped_confirmed=process_stopped, recipes_sha256=recipes_sha256, **derivation_provenance(job))
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
    raw = mailbox.brief(job.message["brief"])
    packet = strict_json(packet_text(raw))
    require(isinstance(packet, dict) and packet.get("schema") in (PACKET_SCHEMA, DEPENDENT_PACKET_SCHEMA),
            "invalid recovery packet")
    checkout = absolute(packet["checkout"], "checkout")
    require(checkout in job.initiative["checkouts"], "checkout is no longer registered for this initiative")
    view = MERGE_VIEW_ENV if "merge" in packet else None
    observed = source_state(mailbox, checkout, view)
    expected = {"source_revision": packet["commit"], "source_tree": packet["tree"],
                "dirty_content_sha256": packet.get("dirty_content_sha256", EMPTY_STATUS)}
    if (job.folder / "admitted.json").exists():
        reference = read_json(job.folder / "admitted.json")
        derived = admitted_derivation(job, raw, reference["recipes_sha256"])
        expected["dirty_content_sha256"] = derived["dirty_content_sha256"]
    elif packet.get("derive") == "runner" and (job.folder / "derivation.json").exists():
        # A known staging failure or a crash before the successful-admission marker still has an observed digest.
        require(read_bytes(job.folder / "packet.md") == raw, "derivation packet does not match the original request")
        derived = read_json(job.folder / "derivation.json")
        matching(derived["dirty_content_sha256"], SHA256, "derived dirty_content_sha256")
        expected["dirty_content_sha256"] = derived["dirty_content_sha256"]
    # A completed commit/merge changes source intentionally. Its after-witness, not the old packet,
    # is the reference for later incoming-work revalidation; the original packet remains untouched.
    if result is not None and isinstance(result.get("after"), dict):
        expected = {key: result["after"].get(key) for key in expected}
    return {"state": "match" if all(observed.get(key) == value for key, value in expected.items()) else "changed",
            "expected": expected, "observed": observed}


def recovery_job(store, ledger, initiative, message, records, mailbox):
    job = Job(store.path, initiative, message)
    # Deliberately kind-independent and every state, bound to the initiative: recovery reports every row this job's
    # initiative filed under its holder, and any open one keeps it settle_pending/reserved_not_started. Another
    # initiative's open rows under the holder never hold or settle this job; they are named separately.
    requests = list(ledger.requests.values())
    reservations = [dict(r) for r in holder_requests(requests, job.holder, kind=ANY_KIND, initiative=initiative["id"],
                                                     states=REQUEST_STATES)]
    held = any(r["state"] in OPEN_STATES for r in reservations)
    row = {"job": job.id, "owner": initiative["id"] + "/orchestrator", "reservations": reservations,
           "claim": None, "runner_alive": None, "process_alive": None, "receipt": "not_published",
           "source": {"state": "unavailable"}, "next_action": "Revalidate the original source and admission before run-open."}
    foreign = foreign_rows(requests, job, kind=ANY_KIND)
    if foreign:
        # Also a retained_reservation blocker of the initiative that filed it.
        row["foreign_reservations"] = [request_summary(request) for request in foreign]
    result = None
    try:
        if job.folder.exists():
            if job.claim_path.exists():
                row["claim"] = read_json(job.claim_path)
            result = job.result()
            if result is None:
                row["runner_alive"] = job.runner_alive()
                if job.planned:
                    require(job.result_decision() != "settle", "job has no validated terminal result")
                group = job.process_group()
                row["process_group"] = group
                row["process_alive"] = bool(group_members(group)) if group else None
                if (job.folder / "admitted.json").exists() and not job.execution_path.exists():
                    check_settlement_processes(job, {"steps": []})
                    row["state"] = "admitted"
                    row["next_action"] = "Recheck the persisted admission with run-open; do not derive again."
                else:
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
                if result["state"] != "refused" or (job.folder / "derivation.json").exists():
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
    if foreign and row["state"] == "finished" and row["source"]["state"] != "changed":
        # Settled for its own initiative, but not clean while another initiative's row holds its dependents.
        row["next_action"] = "Retain evidence for independent acceptance; first " + foreign_reason(foreign[0]) + "."
    return row


def foreign_reservation_blocker(initiative_id, request):
    """A recovery blocker in the affected initiative's own report; the filing one reports retained_reservation."""
    summary = request_summary(request)
    identifier = request["holder"][len("job:"):] if request["holder"].startswith("job:") else ""
    canonical = JOB_ID.fullmatch(identifier) is not None
    return {"initiative": initiative_id, "job": identifier if canonical else "invalid_job",
            "holder": request["holder"] if canonical else "invalid_holder", "request_id": summary["request_id"],
            "filing_initiative": summary["initiative"], "kind": summary["kind"], "state": summary["state"],
            "owner": "root", "reason": "foreign_reservation",
            "next_action": "Root: " + foreign_reason(request) + ". Until then this job's dependents are held."}


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
        # Every holder, kind and state this initiative filed: its jobs' rows, and anything else it retains.
        for request in holder_requests(ledger.requests.values(), ANY_HOLDER, kind=ANY_KIND, initiative=initiative["id"],
                                       states=REQUEST_STATES):
            if request["holder"].startswith(prefix):
                identifier = request["holder"][len(prefix):]
                matching(identifier, SLUG, "job message id")
                messages.setdefault(identifier, {"message_id": identifier})
            elif request["state"] in ("granted", "queued"):
                blockers.append({"initiative": initiative["id"], "request_id": request["request_id"],
                                 "holder": request["holder"], "owner": owner, "reason": "retained_reservation",
                                 "next_action": "Correlate original actor/source and terminal evidence; TTL is not release evidence."})
        # Open rows another initiative filed under this initiative's job holders. They are never this initiative's to
        # settle, yet they hold its dependents (check_dependency), so a report scoped to it must not read as clean.
        for request in holder_requests(ledger.requests.values(), ANY_HOLDER, kind=ANY_KIND, initiative=ANY_INITIATIVE,
                                       states=OPEN_STATES):
            if request["initiative"] != initiative["id"] and request["holder"].startswith(prefix):
                blockers.append(foreign_reservation_blocker(initiative["id"], request))
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
    opened.add_argument("--expect-recipes-sha256", help="Refuse changed recipes; pass the reviewed init hash")
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
                if "census_outside_policy" in recipes:
                    result["census_outside_policy"] = recipes["census_outside_policy"]
                    if recipes["census_outside_policy"] != "count":
                        result["census_outside_policy_non_default"] = True
            else:
                code, result = run_open(args.store, args.recipes, args.initiative, args.max_jobs, args.census_fixture,
                                        args.lock_wait, args.expect_recipes_sha256)
    except ERRORS as exc:
        code, result = 2, {"error": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
