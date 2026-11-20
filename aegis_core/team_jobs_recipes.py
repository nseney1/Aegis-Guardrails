"""Job recipe and packet helpers, ported from the legacy jobs slice.

Pure validation has no queue or execution authority. Files are read below held,
no-follow roots; mailbox indexes, ledger kinds, host policy and the bounded
Python version probe are owner-injected ports. Refusals never contain input.
"""

from __future__ import annotations
from contextlib import contextmanager
from collections import deque
from functools import wraps
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from threading import Lock
import xml.etree.ElementTree as ElementTree
from aegis_core import storage_confined
from aegis_core.storage_confined import ConfinedFileError, confined_file
from aegis_core.primitives import sanitize_display
from aegis_core.redaction import guidance_value

__all__ = [
    "ANY_HOLDER",
    "EMPTY_STATUS",
    "JUNIT_KEEP",
    "JobRecipesRefusal",
    "MAX_BYTES",
    "PACKET_SCHEMA",
    "ProbeTimeout",
    "ProbeUnavailable",
    "RECIPES_SCHEMA",
    "Recipes",
    "confined_file",
]

MAX_BYTES = 262144
SLUG = re.compile("[a-z0-9][a-z0-9_-]{0,79}")
SHA256 = re.compile("[0-9a-f]{64}")
GIT_ID = re.compile("[0-9a-f]{40}")
RECIPES_SCHEMA = "aegis.hierarchy-job-recipes/v1"
PACKET_SCHEMA = "aegis.hierarchy-job-packet/v1"
DEPENDENT_PACKET_SCHEMA = "aegis.hierarchy-job-packet/v2"
RESULT_SCHEMA = "aegis.hierarchy-job-result/v1"
RECOVERY_SCHEMA = "aegis.hierarchy-recovery-status/v1"
COMMAND_TOKENS = {"$python", "$paths", "$scratch", "$checkout", "$cargo_target"}
ENV_TOKENS = {"$scratch", "$checkout"}
SANDBOXES = ("bwrap", "none")
CARGO_COMPILING = {
    "build",
    "b",
    "test",
    "t",
    "check",
    "c",
    "run",
    "r",
    "bench",
    "clippy",
    "doc",
    "d",
    "rustc",
    "install",
    "nextest",
    "miri",
}
EMPTY_STATUS = hashlib.sha256(b"").hexdigest()
MAX_PATHS = 256
MAX_PATHS_BYTES = 65536
MAX_CHECKOUT_COMPONENTS = 128
MAX_CHECKOUT_PATH_CHARS = 32768
MAX_CHECKOUT_LINKS = 40
MAX_STEPS = 20
MAX_TIMEOUT_SECONDS = 86400
MAX_KEEP = 16
MAX_JUNIT_BYTES = 8388608
JUNIT_KEEP = "run/junit.xml"
JUNIT_WORD = "$scratch/junit.xml"
JUNIT_COUNTS = ("tests", "failures", "errors", "skipped")
SCRATCH_WORD = "$scratch/"
PYTHON_PROBE_SECONDS = 30
PATH_ARGUMENT = re.compile("[A-Za-z0-9_.][A-Za-z0-9_./@+-]*(::[^\\x00-\\x1f]{1,512})?")
CENSUS_REQUEST_ID = re.compile("req-[0-9]{8}")
ANY_KIND = object()
ANY_HOLDER = object()
ANY_INITIATIVE = object()
OPEN_STATES = ("queued", "granted")
REQUEST_STATES = ("queued", "granted", "released", "withdrawn")
REQUEST_FIELDS = ("request_id", "initiative", "kind", "holder", "state")
_ACTIONS = {
    "invalid_recipe": "Correct the recipe against the job recipes schema, then retry.",
    "invalid_packet": "Correct the packet against the job packet schema, then retry.",
    "invalid_request": "Reconcile the ledger rows and explicit filters, then retry.",
    "invalid_input": "Supply a value matching the helper contract, then retry.",
    "invalid_json": "Supply bounded, unique-key UTF-8 JSON, then retry.",
    "unsupported_schema": "Use the supported job recipes or packet schema, then retry.",
    "unknown_key": "Remove fields outside the supported schema, then retry.",
    "unknown_recipe": "Select a recipe present in the owner-selected recipe table.",
    "too_large": "Reduce the input to the documented size limit, then retry.",
    "unsafe_path": "Use a plain path below the owner-selected no-follow root.",
    "missing": "Restore the required input under its trusted root, then retry.",
    "unsupported_platform": "Use a platform with descriptor-relative no-follow storage.",
    "io": "Check input storage availability, then retry.",
    "port_required": "Supply the owner-selected port or table, then retry.",
}


class ProbeTimeout(Exception):
    """The owner-side probe adapter exhausted its bounded execution time."""


class ProbeUnavailable(Exception):
    """The owner-side probe adapter could not execute the interpreter."""


class JobRecipesRefusal(ValueError):
    """Fixed refusal envelope; no supplied text is rendered."""

    def __init__(self, code):
        self.code = self.reason = code
        self.next_action = _ACTIONS[code]
        super().__init__("job recipes refused: " + code)

    def as_dict(self):
        return {"status": "refused", "code": self.code, "reason": self.reason, "next_action": self.next_action}


def guard(default="invalid_recipe"):
    """Bound JSON-shaped arguments before traversal and normalize refusal classes."""

    def decorate(function):
        @wraps(function)
        def call(self, *args, **kwargs):
            try:
                for value in (*args, *(v for k, v in kwargs.items() if k != "cache")):
                    if type(value) in (dict, list, tuple):
                        self.mailbox.bounded_tree(value)
                return function(self, *args, **kwargs)
            except JobRecipesRefusal:
                raise
            except self.mailbox.MailboxRefusal as error:
                code = error.reason if error.reason in _ACTIONS else default
                if code == "invalid_record":
                    code = default
                raise JobRecipesRefusal(code) from None
            except ConfinedFileError as error:
                code = {
                    "unsupported": "unsupported_platform",
                    "unsafe": "unsafe_path",
                    "invalid_path": "unsafe_path",
                }.get(error.reason, error.reason)
                raise JobRecipesRefusal(code if code in _ACTIONS else "io") from None
            except OSError as error:
                code = {errno.ENOENT: "missing", errno.ELOOP: "unsafe_path", errno.ENOTDIR: "unsafe_path"}.get(
                    error.errno, "io"
                )
                raise JobRecipesRefusal(code) from None
            except (ValueError, KeyError, UnicodeError, RecursionError, OverflowError):
                raise JobRecipesRefusal(default) from None

        return call

    return decorate


class Recipes:
    """Owner-bound mailbox helpers and storage; validation has no admission authority."""

    def __init__(self, *, mailbox_helpers, checkout_factory=None):
        required = ("bounded_tree", "integer", "matching", "safe_path", "strict_json", "strings", "text")
        if not all((callable(getattr(mailbox_helpers, name, None)) for name in required)):
            raise JobRecipesRefusal("port_required")
        error = getattr(mailbox_helpers, "MailboxRefusal", None)
        if not isinstance(error, type) or not issubclass(error, ValueError):
            raise JobRecipesRefusal("port_required")
        self.mailbox = mailbox_helpers
        self._probe_lock = Lock()
        if checkout_factory is not None and not callable(checkout_factory):
            raise JobRecipesRefusal("port_required")
        self.checkout_factory = self._checkout_root if checkout_factory is None else checkout_factory

    def require(self, condition, message="", *, code="invalid_recipe"):
        if not condition:
            raise JobRecipesRefusal(code)

    def fields(self, value, required, optional=(), *, code="invalid_recipe"):
        self.require(type(value) is dict, code=code)
        self.require(set(required) <= value.keys(), code=code)
        self.require(
            value.keys() <= set(required) | set(optional), code="unknown_key" if code == "invalid_recipe" else code
        )

    def _packet_checkout(self, value):
        """Compare registered spellings lexically; never resolve packet aliases."""
        try:
            return self.mailbox.safe_path(value.as_posix() if isinstance(value, Path) else value)
        except self.mailbox.MailboxRefusal:
            raise JobRecipesRefusal("invalid_packet") from None

    def _json(self, data):
        try:
            return self.mailbox.strict_json(data)
        except self.mailbox.MailboxRefusal as error:
            raise JobRecipesRefusal("too_large" if error.reason == "too_large" else "invalid_json") from None

    @contextmanager
    def _file(self, path, root=None):
        self.require(storage_confined.descriptor_supported(), code="unsupported_platform")
        path = self.mailbox.safe_path(path)
        base = self.mailbox.safe_path(root) if root is not None else Path(path.anchor)
        self.require(path != base and base in path.parents, code="unsafe_path")
        yield_from = path.relative_to(base).parts
        with confined_file(base, yield_from) as handle:
            yield handle

    @contextmanager
    def _checkout_root(self, checkout):
        """Bind an owner-selected root once; root aliases are trusted at binding."""
        supported = (
            storage_confined.descriptor_supported()
            and "readlink" in {fn.__name__ for fn in os.supports_dir_fd}
            and "stat" in {fn.__name__ for fn in os.supports_follow_symlinks}
        )
        self.require(supported, code="unsupported_platform")
        alias = self.mailbox.safe_path(checkout)
        try:
            root = self.mailbox.safe_path(alias.resolve(strict=True))
        except RuntimeError:
            raise JobRecipesRefusal("unsafe_path") from None
        descriptors = []
        fd = os.open(root.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        try:
            descriptors.append(fd)
            for component in root.parts[1:]:
                child = os.open(
                    component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=fd
                )
                try:
                    descriptors.append(child)
                except BaseException:
                    os.close(child)
                    raise
                fd = child
            yield root, alias, tuple(descriptors)
        finally:
            if not descriptors:
                os.close(fd)
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def _checkout_parts(self, value):
        self.require(type(value) is str and 0 < len(value) <= MAX_CHECKOUT_PATH_CHARS, code="unsafe_path")
        self.require(value.count("/") < MAX_CHECKOUT_COMPONENTS, code="unsafe_path")
        parts = value.split("/")
        for part in parts:
            self.require(
                len(part) <= 255 and "\x00" not in part and not any(0xD800 <= ord(c) <= 0xDFFF for c in part),
                code="unsafe_path",
            )
            self.require(len(part.encode("utf-8")) <= 255, code="unsafe_path")
        return parts

    def _checkout_link(self, binding, target):
        return self._checkout_parts(target), target.startswith("/")

    def _checkout_contains(self, binding, frames, leaf=None):
        root = os.fstat(binding[2][-1])
        identity = (root.st_dev, root.st_ino)
        if leaf is not None and stat.S_ISDIR(leaf.st_mode) and (leaf.st_dev, leaf.st_ino) == identity:
            return True
        for descriptor in frames:
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) == identity:
                return True
        return False

    def _checkout_pop(self, frames, owned):
        descriptor = frames.pop()
        if descriptor in owned:
            owned.remove(descriptor)
            os.close(descriptor)

    def _checkout_entry(self, descriptor, name):
        try:
            return os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except (FileNotFoundError, NotADirectoryError):
            return None

    def _checkout_exists(self, binding, name):
        """Resolve links through held parents; never ask the kernel to follow one."""
        parts = deque(self._checkout_parts(name))
        frames = list(binding[2])
        owned = set()
        followed = 0
        try:
            self.require(len(frames) + len(parts) <= MAX_CHECKOUT_COMPONENTS, code="unsafe_path")
            while parts:
                component = parts.popleft()
                if component in ("", "."):
                    continue
                if component == "..":
                    if len(frames) > 1:
                        self._checkout_pop(frames, owned)
                    continue
                info = self._checkout_entry(frames[-1], component)
                if info is None:
                    self.require(self._checkout_contains(binding, frames), code="unsafe_path")
                    return False
                if stat.S_ISLNK(info.st_mode):
                    followed += 1
                    self.require(
                        followed <= MAX_CHECKOUT_LINKS and info.st_size <= MAX_CHECKOUT_PATH_CHARS, code="unsafe_path"
                    )
                    target = os.readlink(component, dir_fd=frames[-1])
                    expanded, absolute = self._checkout_link(binding, target)
                    if absolute:
                        while len(frames) > 1:
                            self._checkout_pop(frames, owned)
                    self.require(
                        len(frames) + len(parts) + len(expanded) <= MAX_CHECKOUT_COMPONENTS, code="unsafe_path"
                    )
                    parts.extendleft(reversed(expanded))
                elif parts:
                    if not stat.S_ISDIR(info.st_mode):
                        self.require(self._checkout_contains(binding, frames), code="unsafe_path")
                        return False
                    child = os.open(
                        component,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=frames[-1],
                    )
                    try:
                        owned.add(child)
                        frames.append(child)
                    except BaseException:
                        owned.discard(child)
                        os.close(child)
                        raise
                else:
                    self.require(self._checkout_contains(binding, frames, info), code="unsafe_path")
                    return True
            self.require(self._checkout_contains(binding, frames), code="unsafe_path")
            return True
        except OSError:
            self.require(self._checkout_contains(binding, frames), code="unsafe_path")
            raise
        finally:
            for descriptor in owned:
                os.close(descriptor)

    @guard()
    def mailbox_reader(self, mailbox, *, index_factory):
        self.require(callable(index_factory), code="port_required")
        return index_factory(mailbox, mode="shadow")

    @guard("invalid_input")
    def plain_relative(self, path):
        self.require(type(path) is str)
        self.require(len(path) <= 32768, code="too_large")
        return all((part not in ("", ".", "..") for part in path.split("/")))

    @guard("invalid_input")
    def scratch_word(self, word):
        self.require(type(word) is str)
        self.require(len(word) <= 4096, code="too_large")
        rest = word[len(SCRATCH_WORD) :]
        return word.startswith(SCRATCH_WORD) and "$" not in rest and self.plain_relative(rest)

    @guard()
    def checked_words(self, words, allowed, label, scratch_paths=False):
        self.require(type(words) is list and type(allowed) in (set, frozenset))
        for word in words:
            self.require(type(word) is str and word and ("\x00" not in word))
            self.require("$" not in word or word in allowed or (scratch_paths and self.scratch_word(word)))

    @guard()
    def cargo_step(self, words):
        self.require(type(words) is list and all((type(word) is str for word in words)))
        if not words:
            return None
        name = Path(words[0]).name
        if name == "rustc":
            return name
        if name != "cargo":
            return None
        subcommand = next((word for word in words[1:] if not word.startswith(("-", "+"))), None)
        return name + " " + subcommand if subcommand in CARGO_COMPILING else None

    @guard()
    def validate_recipe(self, name, recipe):
        self.mailbox.matching(name, SLUG, "recipe name")
        self.require(isinstance(recipe, dict) and recipe.get("kind") in ("command", "commit", "merge"))
        self.mailbox.integer(recipe.get("timeout_seconds"), "timeout_seconds", maximum=MAX_TIMEOUT_SECONDS)
        self.require(recipe.get("sandbox") in SANDBOXES)
        if recipe["kind"] in ("commit", "merge"):
            self.fields(recipe, {"kind", "timeout_seconds", "sandbox"})
            return
        self.fields(
            recipe,
            {"kind", "timeout_seconds", "sandbox", "heavy", "steps"},
            {"writable_checkout", "heavy_tests", "keep", "require_clean", "expects_tests", "export_git"},
        )
        keep = recipe.get("keep", [])
        self.require(isinstance(keep, list) and len(keep) <= MAX_KEEP)
        for entry in keep:
            self.require(isinstance(entry, str) and "\x00" not in entry and self.plain_relative(entry))
        self.require(type(recipe["heavy"]) is bool)
        self.require(type(recipe.get("writable_checkout", False)) is bool)
        self.require(type(recipe.get("heavy_tests", False)) is bool)
        self.require(type(recipe.get("require_clean", False)) is bool)
        self.require(not (recipe.get("require_clean", False) and recipe.get("writable_checkout", False)))
        self.require(type(recipe.get("expects_tests", False)) is bool)
        self.require(type(recipe.get("export_git", False)) is bool)
        self.require(recipe.get("require_clean", False) or not recipe.get("export_git", False))
        self.require(not recipe.get("expects_tests", False) or JUNIT_KEEP in keep)
        self.require(recipe["heavy"] or not recipe.get("heavy_tests", False))
        steps = recipe["steps"]
        self.require(
            isinstance(steps, list)
            and 0 < len(steps) <= MAX_STEPS
            and all((isinstance(step, list) and step for step in steps))
        )
        for number, step in enumerate(steps, 1):
            self.checked_words(step, COMMAND_TOKENS, "recipe " + name, scratch_paths=True)
            compiles = self.cargo_step(step)
            self.require(not compiles or recipe.get("heavy_tests", False))
        self.require(not recipe.get("expects_tests", False) or any((JUNIT_WORD in step for step in steps)))

    @guard()
    def validate_recipes(self, data):
        """Validate captured UTF-8 JSON bytes or an already parsed object, without reopening the input path.

        Return the validated object without adding defaults or a hash. Only the byte reader can bind the file's exact
        recipes_sha256; callers retaining bytes can hash those bytes themselves. Parsed objects are not modified.
        """
        recipes = self._json(data) if type(data) is bytes else data
        self.fields(
            recipes,
            {"schema", "python", "path", "recipes"},
            {"identity", "env", "hide", "ro_binds", "prefix", "min_free_gigabytes", "census_outside_policy"},
        )
        if "min_free_gigabytes" in recipes:
            self.mailbox.integer(recipes["min_free_gigabytes"], "min_free_gigabytes", minimum=0)
        if "census_outside_policy" in recipes:
            policy = recipes["census_outside_policy"]
            self.require(isinstance(policy, str) and policy in ("count", "report", "ignore"))
        self.require(recipes["schema"] == RECIPES_SCHEMA, code="unsupported_schema")
        self.require(isinstance(recipes["python"], str) and Path(recipes["python"]).is_absolute())
        self.mailbox.strings(recipes["path"], "path", nonempty=True)
        self.require(all((Path(folder).is_absolute() for folder in recipes["path"])))
        self.existing_folders(recipes.get("hide", []), "hide")
        self.existing_folders(recipes.get("ro_binds", []), "ro_binds")
        prefix = recipes.get("prefix", [])
        self.mailbox.strings(prefix, "prefix")
        self.require(not prefix or Path(prefix[0]).is_absolute())
        env = recipes.get("env", {})
        self.require(isinstance(env, dict) and all((isinstance(value, str) for value in env.values())))
        for key, value in env.items():
            self.require(re.fullmatch("[A-Z_][A-Z0-9_]*", key) is not None)
            self.require("$" not in value or value in ENV_TOKENS)
        table = recipes["recipes"]
        self.require(isinstance(table, dict) and table)
        for name, recipe in table.items():
            self.validate_recipe(name, recipe)
        if any((recipe["kind"] in ("commit", "merge") for recipe in table.values())):
            identity = recipes.get("identity")
            self.require(isinstance(identity, dict))
            self.fields(identity, {"name", "email"})
            self.mailbox.text(identity["name"], "identity name", 256)
            self.mailbox.text(identity["email"], "identity email", 256)
        return recipes

    @guard("invalid_input")
    def junit_counts(self, raw):
        """Counts from a junit report, summed over the leaf testsuites: a testsuite that holds testsuites contributes nothing
        itself, because producers that nest suites write the children's totals on the parent. Returns (counts, None) or
        (None, why it is unreadable).
        A DOCTYPE or ENTITY is refused before parsing, so no entity is ever expanded; the text must be UTF-8 so that
        check cannot be dodged by another encoding."""
        self.require(type(raw) is bytes, code="invalid_input")
        if len(raw) > MAX_JUNIT_BYTES:
            return (None, "it is larger than %d bytes" % MAX_JUNIT_BYTES)
        try:
            content = raw.decode("utf-8")
        except UnicodeError:
            return (None, "it is not UTF-8")
        upper = content.upper()
        if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
            return (None, "it has a DOCTYPE or ENTITY declaration")
        try:
            root = ElementTree.fromstring(content)
        except (ElementTree.ParseError, ValueError):
            return (None, "it is not well-formed XML")
        if root.tag not in ("testsuites", "testsuite"):
            return (None, "its root is not testsuites or testsuite")
        sums = dict.fromkeys(JUNIT_COUNTS, 0)
        for suite in root.iter("testsuite"):
            if suite.find("testsuite") is not None:
                continue
            for name in JUNIT_COUNTS:
                value = suite.get(name, "0")
                if re.fullmatch("[0-9]{1,12}", value) is None:
                    return (None, "testsuite attribute %s is not a non-negative integer" % name)
                sums[name] += int(value)
        passed = sums["tests"] - sums["failures"] - sums["errors"] - sums["skipped"]
        if passed < 0:
            return (None, "failures, errors and skipped exceed tests")
        return (
            {
                "total": sums["tests"],
                "passed": passed,
                "failed": sums["failures"],
                "errors": sums["errors"],
                "skipped": sums["skipped"],
            },
            None,
        )

    @guard("invalid_request")
    def holder_requests(self, requests, holder, *, kind, initiative, states, ledger_kinds):
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
        self._request_require(type(requests) is list, code="invalid_request")
        self._kinds(ledger_kinds)
        self._request_require(kind is ANY_KIND or (isinstance(kind, str) and kind in ledger_kinds))
        self._request_require(holder is ANY_HOLDER or (isinstance(holder, str) and holder))
        self._request_require(initiative is ANY_INITIATIVE or (isinstance(initiative, str) and initiative))
        self._request_require(
            isinstance(states, tuple)
            and states
            and all((isinstance(state, str) and state in REQUEST_STATES for state in states))
        )
        wide = kind is ANY_KIND or holder is ANY_HOLDER
        needed = (
            REQUEST_FIELDS
            if wide
            else ("holder", "kind", "state") + (() if initiative is ANY_INITIATIVE else ("initiative",))
        )
        found = []
        for request in requests:
            if not (
                isinstance(request, dict)
                and all((isinstance(request.get(key), str) for key in needed))
                and (not wide or (request["kind"] in ledger_kinds and request["state"] in REQUEST_STATES))
            ):
                self._request_require(not wide)
                continue
            if (
                (holder is ANY_HOLDER or request["holder"] == holder)
                and (kind is ANY_KIND or request["kind"] == kind)
                and (initiative is ANY_INITIATIVE or request["initiative"] == initiative)
                and (request["state"] in states)
            ):
                found.append(request)
        return found

    def _request_require(self, condition, message="", *, code="invalid_request"):
        self.require(condition, code=code)

    @guard()
    def existing_folders(self, value, label):
        self.require(type(label) is str)
        self.mailbox.strings(value, label)
        for folder in value:
            self.require(storage_confined.descriptor_supported(), code="unsupported_platform")
            path = self.mailbox.safe_path(folder)
            with confined_file(path, ("_directory_probe",)) as handle:
                handle.parent_stat()

    @guard()
    def load_recipes(self, path):
        with self._file(path) as handle:
            raw = handle.read_bytes(MAX_BYTES)
        recipes = self.validate_recipes(raw)
        return {**recipes, "recipes_sha256": hashlib.sha256(raw).hexdigest()}

    @guard("invalid_input")
    def clean_refusal(self, name):
        self.mailbox.text(name, "recipe", MAX_BYTES)
        shown = guidance_value(name, limit=256, canonicalize=sanitize_display)
        return "recipe %s requires a clean checkout; commit or discard local changes" % shown

    @guard()
    def python_info(self, recipes, *, probe, cache=None):
        """The injected probe owns isolated execution, output bounds and timeout cleanup.

        It accepts (executable, path, timeout) and returns stdout bytes and returncode.
        The owner adapter maps execution timeouts to ProbeTimeout and other process
        failures to ProbeUnavailable. OSError remains supported for I/O failures.
        A cache is owned by one runner invocation; exception text is never displayed.
        """
        self.require(type(recipes) is dict)
        self.fields(recipes, {"python", "path"}, set(recipes) - {"python", "path"})
        self.mailbox.text(recipes["python"], "python")
        self.mailbox.strings(recipes["path"], "path", nonempty=True)
        self.require(callable(probe) and (cache is None or type(cache) is dict), code="port_required")
        executable = recipes["python"]
        with self._probe_lock:
            if cache is not None:
                self.mailbox.bounded_tree(cache)
            if cache is not None and executable in cache:
                self.require(type(cache[executable]) is dict)
                return dict(cache[executable])
            info = {
                "version": None,
                "executable": guidance_value(executable, limit=4096, canonicalize=sanitize_display),
            }
            try:
                result = probe(executable, recipes["path"], PYTHON_PROBE_SECONDS)
                stdout = getattr(result, "stdout", None)
                returncode = getattr(result, "returncode", None)
                self.require(type(stdout) is bytes and type(returncode) is int)
                self.require(len(stdout) <= MAX_BYTES, code="too_large")
                version = stdout.decode("utf-8", errors="replace").strip()
                if returncode != 0:
                    info["error"] = "the version probe exited %d" % returncode
                elif re.fullmatch("[0-9]+\\.[0-9]+\\.[0-9]+[A-Za-z0-9.+]*", version) is None:
                    info["error"] = "the version probe printed no version"
                else:
                    info["version"] = version
            except ProbeTimeout:
                info["error"] = "the version probe took longer than %s seconds" % PYTHON_PROBE_SECONDS
            except (OSError, ProbeUnavailable):
                info["error"] = "the version probe could not run"
            if cache is not None:
                cache[executable] = dict(info)
            return info

    @guard("invalid_input")
    def kept_junit(self, kept, *, root):
        self.require(type(kept) is list and all((type(item) is dict for item in kept)))
        row = next((item for item in kept if item.get("path") == JUNIT_KEEP), None)
        if row is None or row.get("error") == "missing":
            return (None, "junit.xml is missing")
        if "error" in row:
            return (None, "junit.xml is unreadable")
        self.require("copy" in row)
        try:
            with self._file(row["copy"], root) as handle:
                raw = handle.read_bytes(MAX_JUNIT_BYTES)
        except (ConfinedFileError, OSError) as error:
            if isinstance(error, ConfinedFileError) and error.reason in ("unsafe", "invalid_path", "unsupported"):
                raise
            return (None, "junit.xml is unreadable")
        counts, problem = self.junit_counts(raw)
        if problem:
            return (None, "junit.xml is unreadable: " + problem)
        if not counts["total"]:
            return (counts, "the run reported no tests")
        return (counts, None if counts["passed"] else "the run passed no tests")

    @guard()
    def is_heavy(self, recipe):
        self.require(type(recipe) is dict)
        return recipe.get("heavy", False)

    @guard()
    def job_kind(self, recipe):
        self.require(type(recipe) is dict)
        return "heavy-tests" if recipe.get("heavy_tests", False) else "heavy"

    @guard("invalid_request")
    def request_summary(self, request, *, ledger_kinds):
        self.require(type(request) is dict)
        self._kinds(ledger_kinds)
        initiative = request.get("initiative")
        request_id = request.get("request_id")
        values = {
            "request_id": request_id
            if type(request_id) is str and CENSUS_REQUEST_ID.fullmatch(request_id)
            else "invalid_request_id",
            "initiative": initiative
            if type(initiative) is str and SLUG.fullmatch(initiative)
            else "invalid_initiative",
            "kind": request["kind"] if request.get("kind") in ledger_kinds else "invalid_kind",
            "state": request["state"] if request.get("state") in REQUEST_STATES else "invalid_state",
        }
        return {key: guidance_value(value, limit=256, canonicalize=sanitize_display) for key, value in values.items()}

    def _kinds(self, ledger_kinds):
        self.require(
            type(ledger_kinds) in (tuple, list)
            and 0 < len(ledger_kinds) <= 256
            and all((type(kind) is str and kind for kind in ledger_kinds)),
            code="port_required",
        )

    @guard("invalid_request")
    def foreign_rows(self, requests, job, *, kind, ledger_kinds, states=OPEN_STATES):
        self.require(type(getattr(job, "initiative", None)) is dict and hasattr(job, "holder"))
        return [
            request
            for request in self.holder_requests(
                requests, job.holder, kind=kind, initiative=ANY_INITIATIVE, states=states, ledger_kinds=ledger_kinds
            )
            if request.get("initiative") != job.initiative["id"]
        ]

    @guard("invalid_request")
    def foreign_reason(self, request, *, ledger_kinds):
        summary = self.request_summary(request, ledger_kinds=ledger_kinds)
        return (
            "request %s of initiative %s holds this job's holder for %s; root must check who filed it, then withdraw or release it"
            % (summary["request_id"], summary["initiative"], summary["kind"])
        )

    @guard("invalid_packet")
    def packet_text(self, raw):
        self.require(type(raw) is bytes, code="invalid_packet")
        self.require(len(raw) <= MAX_BYTES, code="too_large")
        content = raw.decode("utf-8")
        if not content.startswith("---\n"):
            return content
        _, separator, body = content[4:].partition("\n---\n\n")
        self.require(bool(separator), code="invalid_packet")
        return body

    @guard("invalid_packet")
    def checked_paths(self, packet, recipe, checkout):
        self.require(type(packet) is dict and type(recipe) is dict, code="invalid_packet")
        self.require(recipe.get("kind") in ("command", "commit", "merge"), code="invalid_packet")
        paths = packet.get("paths")
        commit = recipe["kind"] == "commit"
        steps = recipe.get("steps", [])
        self.require(type(steps) is list and all((type(step) is list for step in steps)), code="invalid_packet")
        takes_paths = commit or (recipe["kind"] == "command" and any(("$paths" in step for step in steps)))
        if not takes_paths:
            self.require(not paths and (recipe["kind"] != "merge" or "paths" not in packet), code="invalid_packet")
            return []
        self.require(type(paths) is list and bool(paths), code="invalid_packet")
        self.require(len(paths) <= MAX_PATHS, code="invalid_packet")
        self.mailbox.bounded_tree(paths, limit=MAX_PATHS_BYTES, ascii_strings=True)
        self.require(len(json.dumps(paths)) <= MAX_PATHS_BYTES, code="invalid_packet")
        for path in paths:
            self.require(type(path) is str and PATH_ARGUMENT.fullmatch(path) is not None, code="invalid_packet")
            name, _, selector = path.partition("::")
            self.require(".." not in name.split("/") and (not (commit and selector)), code="invalid_packet")
        if not commit:
            with self.checkout_factory(checkout) as binding:
                for path in paths:
                    name = path.partition("::")[0]
                    self.require(self._checkout_exists(binding, name), code="invalid_packet")
        return paths

    @guard("invalid_packet")
    def validate_packet(self, data, recipes, *, registered_checkout=None):
        """Validate the packet's pure wire fields; this never admits or queues a job.

        The caller supplies an already-registered checkout spelling separately.
        Packet paths never choose a filesystem root. Host, lease, dependency,
        source witness and merge checks remain with admission.
        """
        packet = self._json(self.packet_text(data)) if type(data) is bytes else data
        self.require(type(packet) is dict and type(recipes) is dict, code="invalid_packet")
        dependent = packet.get("schema") == DEPENDENT_PACKET_SCHEMA
        self.fields(
            packet,
            {"schema", "recipe", "checkout", "commit", "tree"} | ({"after", "recipes_sha256"} if dependent else set()),
            {"dirty_content_sha256", "paths", "expected_tree", "message", "merge", "derive"},
            code="invalid_packet",
        )
        checkout = self._packet_checkout(registered_checkout)
        self.require(self._packet_checkout(packet["checkout"]) == checkout, code="invalid_packet")
        table = recipes.get("recipes")
        self.require(type(table) is dict, code="invalid_recipe")
        self.require(packet["schema"] in (PACKET_SCHEMA, DEPENDENT_PACKET_SCHEMA), code="unsupported_schema")
        name = packet["recipe"]
        self.require(type(name) is str and name in table, code="unknown_recipe")
        recipe = table[name]
        self.validate_recipe(name, recipe)
        self.mailbox.matching(packet["commit"], GIT_ID, "commit")
        self.mailbox.matching(packet["tree"], GIT_ID, "tree")
        dirty = packet.get("dirty_content_sha256", EMPTY_STATUS)
        self.mailbox.matching(dirty, SHA256, "dirty_content_sha256")
        kind = recipe["kind"]
        derive = "derive" in packet
        self.require(not derive or (packet["derive"] == "runner" and kind == "commit"), code="invalid_packet")
        self.require(not recipe.get("require_clean", False) or dirty == EMPTY_STATUS, code="invalid_packet")
        if dependent:
            self.require(kind == "command" and dirty == EMPTY_STATUS, code="invalid_packet")
            self.fields(packet["after"], {"message_id", "sha256"}, code="invalid_packet")
            self.mailbox.matching(packet["after"]["message_id"], SLUG, "predecessor")
            self.mailbox.matching(packet["after"]["sha256"], SHA256, "predecessor hash")
            self.mailbox.matching(packet["recipes_sha256"], SHA256, "recipes hash")
        if kind in ("commit", "merge"):
            self.require(("expected_tree" in packet or derive) and "message" in packet, code="invalid_packet")
            if "expected_tree" in packet:
                self.mailbox.matching(packet["expected_tree"], GIT_ID, "expected tree")
            self.mailbox.text(packet["message"], "commit message", 65536)
        else:
            self.require("expected_tree" not in packet and "message" not in packet, code="invalid_packet")
        self.require(kind == "merge" or "merge" not in packet, code="invalid_packet")
        if kind == "commit" and "expected_tree" in packet:
            self.require(packet["expected_tree"] != packet["tree"], code="invalid_packet")
        if kind == "merge":
            self.require("merge" in packet, code="invalid_packet")
            self.mailbox.matching(packet["merge"], GIT_ID, "merge")
            self.require(packet["merge"] != packet["commit"] and dirty == EMPTY_STATUS, code="invalid_packet")
        self.checked_paths(packet, recipe, checkout)
        return packet

    @guard("invalid_input")
    def read_environment(
        self, overrides=None, *, inherit_config=False, planned=None, object_read_env, child_environment
    ):
        """The caller supplies object-read and host policies; explicitly unplanned stays inherited."""
        self.require(callable(object_read_env) and callable(child_environment), code="port_required")
        self.require(overrides is None or type(overrides) is dict, code="invalid_input")
        if overrides is not None:
            self.require(
                all((type(key) is str and type(value) is str for key, value in overrides.items())), code="invalid_input"
            )
        self.require(type(inherit_config) is bool and (planned is None or type(planned) is bool), code="invalid_input")
        environment = object_read_env(overrides, inherit_config=inherit_config)
        return child_environment(environment, "no-host") if planned is not False else environment
