#!/usr/bin/env python3
"""The owner's one command for a team run: init, login, root, up, request, approve, turn, status and down.

One config, `team-run.json` (aegis.team-run/v1, template in hierarchy_templates/team-run.json), replaces the real
run's shell guide and its helpers. aegis.team-run/v2 adds `hosts`, ROOT's host and the one host of every role below it;
v1 means codex-cli for both. init writes them to <base>/host-plan.json, which provision add-role and handoff check
every binding against. Every subcommand checks path safety: CODEX_HOME is the run's codex_home and
never ~/.codex or a folder inside it (by realpath), and for a plan that uses claude-code, CLAUDE_CONFIG_DIR is the run's
claude_home. On a Claude plan both homes and the resolved run folder exclude ~/.claude and ~/.codex under HOME and
the password-database home. Commands that start work require free disk at least min_free_gb;
git, bwrap and each host's command the plan uses (codex, claude) are on
PATH, and cargo and cargo-nextest on the recipes' path when a kept recipe runs them. A command that spends model
turns (login, up, approve, turn) also refuses the billing variables of each host the plan uses.

The subcommands orchestrate the existing tools as child processes (`-I -B`), or call their public functions, and
re-check nothing those tools check: a tool's refusal is passed on with its own text. The run's records are files:
<run>/team-state.json says which steps are done, and every output lands in <run>/evidence with its sha256 in
evidence/index.json. `down` copies the rest there, writes the turn ledger and SHA256SUMS.

ROOT stays the owner's session. `root` binds an existing ROOT session with its decision connection; `approve` runs
one ROOT turn whose prompt names the request id, decision and owner's reason, so no hash is pasted, then checks the
journal; the loop never wakes ROOT. `request` publishes as the coordinator, never as ROOT.

Exit codes: 0 done; 2 refused (this command changed nothing); 3 failed (a step ran and did not succeed). The result is
one JSON object on the last line of stdout, except `status --text`.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
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
import time
import uuid

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
from hierarchy_mailbox import (GIT_ID, SLUG, Mailbox, endpoint_parts, fields, matching, read_json, require,  # noqa: E402
                               strict_json, text, timestamp)
import hierarchy_hosts  # noqa: E402
import hierarchy_lifecycle  # noqa: E402
import hierarchy_native  # noqa: E402
import hierarchy_provision  # noqa: E402
import hierarchy_roles  # noqa: E402
import hierarchy_router  # noqa: E402
import hierarchy_team_view  # noqa: E402


SCHEMA = "aegis.team-run/v1"
SCHEMA_V2 = "aegis.team-run/v2"
STATE_SCHEMA = "aegis.team-run-state/v1"
INDEX_SCHEMA = "aegis.team-evidence-index/v1"
STATUS_SCHEMA = "aegis.team-run-status/v1"
LEDGER_SCHEMA = "aegis.team-turn-ledger/v1"
OK, REFUSED, FAILED = 0, 2, 3
CODEX = hierarchy_provision.CODEX
CLAUDE = hierarchy_provision.CLAUDE
V1_HOSTS = {"root": CODEX, "team": CODEX}
CLAUDE_CREDENTIALS = ".credentials.json"
# Seconds, lowerable for CLI timeout tests; never extended past the normal 60-second status deadline.
CLAUDE_AUTH_STATUS_TIMEOUT = "AEGIS_CLAUDE_AUTH_STATUS_TIMEOUT"
TURN_TIMEOUT_SECONDS = 3600
TURN_TIMEOUT_VARIABLE = "AEGIS_TEAM_TURN_TIMEOUT"
ROOT_TOOLS = ("root_decide", "team_status", "team_pending", "team_request")
CHILD_ENVIRONMENT = frozenset(("PATH", "HOME", "LANG", "TERM", "TMPDIR", "USER", "LOGNAME"))
# Managed settings can set an apiKeyHelper that --restricted still reads; login records whether the file exists.
CLAUDE_MANAGED_SETTINGS = Path("/etc/claude-code/managed-settings.json")
# A stand-in binding that never runs a host; the host plan lists it so status can say so (spec rule 6).
FRONT_DOOR_HOST = hierarchy_provision.CLAUDE
HOME_PLACEHOLDER = "/REPLACE/WITH/your/home/folder"
PLACEHOLDER = re.compile(r"REPLACE|<[^<>]*>")
DEFAULT_RECIPES = HERE / "hierarchy_templates" / "job-recipes.json"
PACKET_SCHEMA = "aegis.hierarchy-job-packet/v1"
# Written into codex_home and claude_home by init: purge deletes only a folder that carries it.
OWNER_MARK = ".aegis-team-run"
LANE_KINDS = ("implementer", "reviewer")
OPTIONAL_ROLES = hierarchy_provision.OPTIONAL_ROLES
LEASE_LANE = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")
DEFAULT_LEASE_TTL = 21600
DEFAULT_MIN_FREE_GB = 8
DEFAULT_INTERVAL = 30
LOOP_WAIT_SECONDS = 15
API_KEYS = ("OPENAI_API_KEY", "CODEX_API_KEY")
SPENDS_TURNS = ("login", "up", "approve", "turn")
INIT_STEPS = ("codex-home", "recipes", "workspace", "provision", "front-door", "policy", "lifecycle", "slots",
              "worktrees", "leases", "checkouts", "preflight")
# What init makes in the run folder; any of them already there means the folder is not fresh.
MANAGED = ("store", "lifecycle", "initiatives", "evidence", "preflight", "recipes.json", "policy.json", "worktrees",
           "loop", "loop.pid", "loop.log", "requests", "events", "inputs", "starts")
ROOT_PROMPT = ("Call team_pending, find request %s, then call root_decide once with that row's root_decide arguments, "
               "decision=%s, reason=\"owner: %s\". Do nothing else.")
ROUTER_NOTE = "the Router runs at effort %s and tier %s from the role registry; team.json cannot change it"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
# The aegis team commands read these; the run names --workspace itself, so none may redirect them.
AEGIS_OVERRIDES = ("AEGIS_WORKSPACE", "AEGIS_MANAGER_CONFIG", "AEGIS_MANAGER_CONFIG_SHA256", "GITHUB_BASE_REF")
PUBLISH_ID = re.compile(r'message_id\\*"?\s*:\s*\\*"([^"\\]+)')


class Stop(Exception):
    """A refusal or a failure with the exit code it means; detail joins the printed result."""

    def __init__(self, code, message, *, record_command=True, **detail):
        super().__init__(message)
        self.code = code
        self.detail = detail
        self.record_command = record_command


def refuse(message, **detail):
    raise Stop(REFUSED, message, **detail)


def fail(message, **detail):
    raise Stop(FAILED, message, **detail)


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def write_atomic(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    temporary.write_bytes(raw)
    os.replace(temporary, path)


def as_json(value):
    return (json.dumps(value, indent=1, sort_keys=True) + "\n").encode("utf-8")


# -- config -------------------------------------------------------------------------------------------------------------

def placeholders(value, where=""):
    if isinstance(value, str):
        if PLACEHOLDER.search(value):
            refuse("team-run.json holds a placeholder at %s: %s" % (where or "the top", value[:160]))
    elif isinstance(value, dict):
        for key, item in value.items():
            placeholders(item, key if not where else where + "." + key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            placeholders(item, "%s[%d]" % (where, index))


def absolute(value, label):
    text(value, label)
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts, "%s must be an absolute path without ..: %s" % (label, value))
    return path


def part(where, check):
    """Runs a check on part of the config and names that part in its refusal."""
    try:
        return check()
    except ValueError as exc:
        raise ValueError("%s: %s" % (where, exc)) from exc


class Lane:
    def __init__(self, run, index, value):
        where = "lanes[%d]" % index
        part(where, lambda: fields(value, {"id", "kind"}, {"worktree", "paths", "branch", "tmpdir"}))
        require(value["kind"] in LANE_KINDS, where + ": kind must be implementer or reviewer")
        self.id = part(where, lambda: matching(value["id"], SLUG, "lane id"))
        self.kind = value["kind"]
        self.endpoint = "%s/lane/%s" % (run.id, self.id)
        if self.kind == "reviewer":
            require(not {"worktree", "paths", "branch", "tmpdir"} & value.keys(),
                    where + ": a reviewer lane takes no worktree, paths, branch or tmpdir")
            self.worktree = self.paths = self.branch = self.tmpdir = self.lease = None
            return
        self.paths = value.get("paths")
        part(where, lambda: require(isinstance(self.paths, list) and self.paths and
                                    all(isinstance(p, str) and p for p in self.paths), "an implementer needs paths"))
        self.worktree = part(where, lambda: absolute(value.get("worktree", str(run.run / "worktrees" / self.id)),
                                                     "worktree"))
        self.branch = part(where, lambda: text(value.get("branch", run.branch), "branch", 255))
        self.tmpdir = None
        if "tmpdir" in value:
            tmpdir = Path(part(where, lambda: text(value["tmpdir"], "tmpdir", 255)))
            require(not tmpdir.is_absolute() and ".." not in tmpdir.parts, where + ": tmpdir must be relative to the worktree")
            self.tmpdir = self.worktree / tmpdir
        self.lease = "%s-%s" % (run.id, self.id)
        require(LEASE_LANE.fullmatch(self.lease) is not None, where + ": lease name %s is not a valid lane" % self.lease)


class Run:
    """The parsed team-run.json and the paths it implies."""

    def __init__(self, path):
        self.config_path = absolute(path, "--config")
        try:
            value = read_json(self.config_path)
        except FileNotFoundError:
            refuse("no config at %s" % self.config_path)
        require(isinstance(value, dict), "team-run.json must be a JSON object")
        placeholders(value)
        fields(value, {"schema", "run", "project", "base", "branch", "initiative", "roles", "lanes", "recipes", "limits",
                       "preflight", "team"},
               {"codex_home", "source", "live_checkouts", "base_tree", "min_free_gb", "loop", "lease_ttl_seconds",
                "hosts", "claude_home"})
        require(value["schema"] in (SCHEMA, SCHEMA_V2), "unsupported team-run schema: " + str(value["schema"])[:80])
        self.raw = value
        self.hosts = self.check_hosts()
        require(value["schema"] == SCHEMA_V2 or "claude_home" not in value, "claude_home needs schema " + SCHEMA_V2)
        self.run = absolute(value["run"], "run")
        if self.uses(CLAUDE):
            # Before state reads or command logging, and before deriving paths passed to tools that reject symlinks.
            self.run = safe_run_folder(self)
        self.codex_home = absolute(value.get("codex_home", str(self.run / "codex-home")), "codex_home")
        # Made and checked only when the plan uses claude-code (ADR T2(a) section 3).
        self.claude_home = absolute(value.get("claude_home", str(self.run / "claude-home")), "claude_home")
        self.source = absolute(value.get("source", str(REPO)), "source")
        self.project = absolute(value["project"], "project")
        self.live = [absolute(item, "live_checkouts") for item in value.get("live_checkouts", [])]
        self.base_commit = matching(value["base"], GIT_ID, "base")
        self.base_tree = matching(value["base_tree"], GIT_ID, "base_tree") if "base_tree" in value else None
        self.branch = text(value["branch"], "branch", 255)
        self.initiative = value["initiative"]
        part("initiative", lambda: fields(self.initiative, {"id", "project", "repository", "priority", "target_branch"}))
        self.id = part("initiative", lambda: matching(self.initiative["id"], SLUG, "id"))
        self.roles = value["roles"]
        require(isinstance(self.roles, list) and len(self.roles) == len(set(self.roles)) and
                all(role in OPTIONAL_ROLES for role in self.roles), "roles may list only router and decider, once each")
        require(isinstance(value["lanes"], list) and value["lanes"], "lanes must list at least one lane")
        self.lanes = [Lane(self, index, lane) for index, lane in enumerate(value["lanes"])]
        names = [lane.id for lane in self.lanes]
        require(len(names) == len(set(names)), "lanes must have distinct ids")
        writers = [lane for lane in self.lanes if lane.kind == "implementer"]
        for index, lane in enumerate(writers):
            for other in writers[index + 1:]:
                require(lane.branch != other.branch, "lanes %s and %s share branch %s; give each implementer its own "
                        "branch" % (lane.id, other.id, lane.branch))
        self.recipes_config = value["recipes"]
        part("recipes", lambda: fields(self.recipes_config, {"keep", "python", "commit_identity"}, {"template"}))
        keep = self.recipes_config["keep"]
        require(isinstance(keep, list) and keep and len(keep) == len(set(keep)) and
                all(isinstance(name, str) and name for name in keep), "recipes.keep must list recipe names, once each")
        self.keep = keep
        self.python = str(absolute(self.recipes_config["python"], "recipes.python"))
        identity = self.recipes_config["commit_identity"]
        part("recipes.commit_identity", lambda: fields(identity, {"name", "email"}))
        part("recipes.commit_identity", lambda: (text(identity["name"], "name", 256), text(identity["email"], "email", 256)))
        self.template = absolute(self.recipes_config.get("template", str(DEFAULT_RECIPES)), "recipes.template")
        require(isinstance(value["limits"], dict), "limits must be a JSON object")
        self.limits = value["limits"]
        self.preflight = value["preflight"]
        self.check_preflight()
        self.min_free_gb = value.get("min_free_gb", DEFAULT_MIN_FREE_GB)
        require(type(self.min_free_gb) in (int, float) and self.min_free_gb > 0, "min_free_gb must be a positive number")
        loop = value.get("loop", {"interval": DEFAULT_INTERVAL})
        part("loop", lambda: fields(loop, set(), {"interval"}))
        self.interval = loop.get("interval", DEFAULT_INTERVAL)
        import hierarchy_loop
        low, high = hierarchy_loop.INTERVAL_RANGE
        require(type(self.interval) is int and low <= self.interval <= high,
                "loop.interval must be between %d and %d seconds" % (low, high))
        self.lease_ttl = value.get("lease_ttl_seconds", DEFAULT_LEASE_TTL)
        require(type(self.lease_ttl) is int and 60 <= self.lease_ttl <= 86400, "lease_ttl_seconds must be 60 to 86400")
        self.team = value["team"]
        self.check_team()
        self.base = self.run / "initiatives" / self.id
        self.mailbox_root = self.base / "mailbox"
        self.delivery = self.base / "delivery"
        self.store = self.run / "store"
        self.lifecycle = self.run / "lifecycle"
        self.evidence = self.run / "evidence"
        self.loop_state = self.run / "loop"
        self.recipes = self.run / "recipes.json"
        self.state_path = self.run / "team-state.json"
        self.pid_path = self.run / "loop.pid"
        self.log_path = self.run / "loop.log"
        self.commands_log = self.run / "team-commands.jsonl"
        self.inputs = self.run / "inputs"
        if self.uses(CLAUDE):
            self.validated_homes = {CODEX: safe_codex_home(self), CLAUDE: safe_claude_home(self)}

    def check_hosts(self):
        if self.raw["schema"] == SCHEMA:
            require("hosts" not in self.raw, "hosts needs schema " + SCHEMA_V2)
            return dict(V1_HOSTS)
        require("hosts" in self.raw, SCHEMA_V2 + " needs hosts: the root and team host kinds")
        hosts = self.raw["hosts"]
        part("hosts", lambda: fields(hosts, {"root", "team"}))
        for key in ("root", "team"):
            # Named apart from an unknown kind: provision knows native threads, and team runs start none.
            require(hosts[key] != hierarchy_hosts.NATIVE,
                    "hosts.%s is codex (native): team runs start no native threads" % key)
            require(isinstance(hosts[key], str) and hosts[key] in hierarchy_hosts.TEAM_HOSTS,
                    "hosts.%s must be claude-code or codex-cli, not %s" % (key, repr(hosts[key])[:80]))
        return {"root": hosts["root"], "team": hosts["team"]}

    def uses(self, kind):
        """Whether ROOT or the team runs on this host kind; a v1 config uses codex-cli alone."""
        return kind in self.hosts.values()

    def check_preflight(self):
        preflight = self.preflight
        part("preflight", lambda: fields(preflight, {"recipes", "expect"}, {"paths"}))
        recipes = preflight["recipes"]
        require(isinstance(recipes, list) and len(recipes) == len(set(recipes)), "preflight.recipes must list names once")
        for name in recipes:
            require(name in self.keep, "preflight recipe %s is not in recipes.keep" % name)
        require(isinstance(preflight["expect"], dict), "preflight.expect must be a JSON object")
        for name, expect in preflight["expect"].items():
            require(name in recipes, "preflight.expect names %s, which preflight.recipes does not list" % name)
            part("preflight.expect." + name, lambda: fields(expect, set(), {"state", "failed", "min_passed"}))
            require(expect.get("state", "completed") in ("completed", "failed"),
                    "preflight.expect.%s.state must be completed or failed" % name)
            for key in ("failed", "min_passed"):
                require(key not in expect or (type(expect[key]) is int and expect[key] >= 0),
                        "preflight.expect.%s.%s must be a whole number" % (name, key))
        paths = preflight.get("paths", {})
        require(isinstance(paths, dict), "preflight.paths must be a JSON object")
        for name, listed in paths.items():
            require(name in recipes and isinstance(listed, list) and listed and all(isinstance(p, str) for p in listed),
                    "preflight.paths.%s must list paths for a preflight recipe" % name)

    def check_team(self):
        team = self.team
        part("team", lambda: fields(team, {"model", "reasoning"}, {"reasoning_by_kind"}))
        text(team["model"], "team.model", 128)
        levels = ", ".join(hierarchy_provision.TEAM_LEVELS)
        require(team["reasoning"] in hierarchy_provision.TEAM_LEVELS, "team.reasoning must be one of " + levels)
        by_kind = team.get("reasoning_by_kind", {})
        require(isinstance(by_kind, dict), "team.reasoning_by_kind must be a JSON object")
        kinds = sorted(hierarchy_provision.TEAM_KINDS)
        for key, level in by_kind.items():
            require(key in kinds, "team.reasoning_by_kind: %s is not a team role kind (%s)" % (key, ", ".join(kinds)))
            require(level in hierarchy_provision.TEAM_LEVELS, "team.reasoning_by_kind.%s must be one of %s" % (key, levels))

    @property
    def implementers(self):
        return [lane for lane in self.lanes if lane.kind == "implementer"]

    @property
    def reviewers(self):
        return [lane for lane in self.lanes if lane.kind == "reviewer"]

    def endpoint(self, role):
        return "%s/%s" % (self.id, role)


# -- recipes --------------------------------------------------------------------------------------------------------------

def recipe_file(run):
    """The run's recipe file: the template with the home folder filled in, the configured python and commit identity,
    and only the kept recipes. The jobs tool validates the result (check-recipes)."""
    try:
        raw = run.template.read_text(encoding="utf-8")
    except FileNotFoundError:
        refuse("the recipe template is missing: %s" % run.template)
    home = json.dumps(str(Path.home()))[1:-1]
    value = strict_json(raw.replace(HOME_PLACEHOLDER, home))
    require(isinstance(value, dict) and isinstance(value.get("recipes"), dict),
            "the recipe template has no recipes: %s" % run.template)
    for name in run.keep:
        require(name in value["recipes"], "the recipe template has no recipe %s: %s" % (name, run.template))
    value["python"] = run.python
    value["identity"] = dict(run.recipes_config["commit_identity"])
    value["recipes"] = {name: value["recipes"][name] for name in run.keep}
    left = [word for word in json.dumps(value).split('"') if "REPLACE" in word]
    require(not left, "the recipes still hold a placeholder after filling the home folder: " + (left[0] if left else ""))
    return value


def current_recipes(run):
    return read_json(run.recipes) if run.recipes.is_file() else recipe_file(run)


def recipe_needs(recipes):
    """(a kept recipe that runs cargo, one that runs cargo nextest), each a name or None."""
    cargo = nextest = None
    for name, recipe in sorted(recipes.get("recipes", {}).items()):
        for step in recipe.get("steps", []) if isinstance(recipe, dict) else []:
            if not (isinstance(step, list) and step and isinstance(step[0], str)) or Path(step[0]).name != "cargo":
                continue
            cargo = cargo or name
            subcommand = next((word for word in step[1:] if isinstance(word, str) and not word.startswith(("-", "+"))),
                              None)
            if subcommand == "nextest":
                nextest = nextest or name
    return cargo, nextest


def recipe_path(recipes):
    return os.pathsep.join(item for item in recipes.get("path", []) if isinstance(item, str))


# -- the guard ----------------------------------------------------------------------------------------------------------

def nearest(path):
    while not path.exists() and path.parent != path:
        path = path.parent
    return path


def inside_owner(real, owner, check_identity):
    """Realpath containment, plus directory aliases such as bind mounts on Claude-bearing plans."""
    owner_real = os.path.realpath(owner)
    if real == owner_real or real.startswith(owner_real.rstrip(os.sep) + os.sep):
        return True
    if not check_identity:
        return False
    try:
        info = os.stat(owner)
    except (FileNotFoundError, NotADirectoryError):
        return False
    identity = (info.st_dev, info.st_ino)
    candidate = Path(real)
    for ancestor in (candidate, *candidate.parents):
        try:
            info = os.stat(ancestor)
        except (FileNotFoundError, NotADirectoryError):
            continue
        if (info.st_dev, info.st_ino) == identity:
            return True
    return False


def safe_home(run, home, label, variable, owners, apart=()):
    """The realpath of a run's host home, or a refusal: never an owner folder or inside one, never holding HOME, the run
    or an owner folder, apart from the run's other folders and from each (label, path) in `apart`, and no symlink."""
    real = os.path.realpath(home)
    for owner in owners:
        if inside_owner(real, owner, run.uses(CLAUDE)):
            refuse("%s %s is inside ~/%s (%s); a team run uses its own folder" % (variable, home, owner.name, owner))
    candidate = Path(real)
    def contains(parent, child):
        return parent == child or parent in child.parents
    for protected in (Path.home(), run.run, *owners):
        if contains(candidate, protected.resolve()):
            refuse("unsafe %s: it contains %s" % (label, protected))
    for protected in (run.project, run.source, run.evidence, *[run.run / name for name in MANAGED]):
        protected = protected.resolve()
        if contains(candidate, protected) or contains(protected, candidate):
            refuse("unsafe %s: it overlaps %s" % (label, protected))
    for other, path in apart:
        resolved = Path(os.path.realpath(path))
        if contains(candidate, resolved) or contains(resolved, candidate):
            refuse("unsafe %s: it overlaps %s %s" % (label, other, path))
    if home.is_symlink():
        refuse("unsafe %s: it is a symlink" % label)
    return real


def safe_codex_home(run):
    owners = owner_homes(CODEX) + owner_homes(CLAUDE)
    return safe_home(run, run.codex_home, "codex_home", "CODEX_HOME", owners)


def owner_homes(kind):
    """The owner's own folder for a host kind (~/.claude) under HOME and under the home the password database names,
    once each: a test or a shell that sets HOME must not hide the real one. It can move into the host registry later."""
    folder = hierarchy_hosts.entry(kind)["home"]["owner_folder"]
    try:
        import pwd  # POSIX only, as the rest of this command is
        real = pwd.getpwuid(os.getuid()).pw_dir
    except (ImportError, AttributeError, KeyError):
        refuse("cannot find this user's home folder in the password database, so ~/%s cannot be kept out" % folder)
    homes = []
    for home in (Path.home(), Path(real)):
        if home / folder not in homes:
            homes.append(home / folder)
    return homes


def safe_claude_home(run):
    return safe_home(run, run.claude_home, "claude_home", "CLAUDE_CONFIG_DIR", owner_homes(CLAUDE) + owner_homes(CODEX),
                     apart=[("codex_home", run.codex_home)])


def safe_run_folder(run):
    """Canonicalize safe run aliases, including /tmp on macOS, before any run write can follow them."""
    real = Path(os.path.realpath(run.run))
    for owner in owner_homes(CLAUDE) + owner_homes(CODEX):
        if inside_owner(str(real), owner, True):
            refuse("run folder %s is inside ~/%s (%s); a team run uses its own folder" %
                   (run.run, owner.name, owner))
    return real


def revalidate_homes(run):
    """Narrow accidental changes between the start-time checks, host spawns and login persistence (ADR section 3)."""
    if not run.uses(CLAUDE):
        return
    for kind, check, label in ((CODEX, safe_codex_home, "codex_home"), (CLAUDE, safe_claude_home, "claude_home")):
        if check(run) != run.validated_homes[kind]:
            refuse("%s changed since it was validated for this command" % label)


def revalidate_run(run):
    if run.uses(CLAUDE) and safe_run_folder(run) != run.run:
        refuse("run folder changed since it was validated for this command")


def guard(run, command):
    real = safe_codex_home(run)
    claude_real = safe_claude_home(run) if run.uses(CLAUDE) else None
    if command == "down":
        return {}
    ambient = os.environ.get("CODEX_HOME")
    if ambient and os.path.realpath(ambient) != real:
        refuse("CODEX_HOME in this shell is %s, not this run's codex_home %s; unset it or export the run's"
               % (ambient, run.codex_home))
    ambient = os.environ.get("CLAUDE_CONFIG_DIR") if claude_real else None
    if ambient and os.path.realpath(ambient) != claude_real:
        refuse("CLAUDE_CONFIG_DIR in this shell is %s, not this run's claude_home %s; unset it or export the run's"
               % (ambient, run.claude_home))
    if command == "status":
        return {}
    probe = nearest(run.run)
    free = shutil.disk_usage(str(probe)).free / 2 ** 30
    if free < run.min_free_gb:
        refuse("only %.1f GB free at %s; this run needs min_free_gb %g" % (free, probe, run.min_free_gb))
    tools = {}
    for name in ("git", "bwrap") + (("codex",) if run.uses(CODEX) else ()) + (("claude",) if run.uses(CLAUDE) else ()):
        found = shutil.which(name)
        if found is None:
            refuse("required tool not found on PATH: " + name)
        tools[name] = found
    recipes = current_recipes(run)
    cargo, nextest = recipe_needs(recipes)
    path = recipe_path(recipes)
    for name, recipe, what in (("cargo", cargo, "cargo"), ("cargo-nextest", nextest, "cargo nextest")):
        if recipe is not None:
            found = shutil.which(name, path=path)
            if found is None:
                refuse("required tool not found on the recipes' path: %s (kept recipe %s runs %s)" % (name, recipe, what))
            tools[name] = found
    if command in SPENDS_TURNS and run.uses(CODEX):
        # In API_KEYS order, so the message stays what it was before the registry listed them.
        keys = [key for key in API_KEYS if key in hierarchy_hosts.billing_set(CODEX, os.environ)]
        if keys:
            refuse("unset OPENAI_API_KEY and CODEX_API_KEY: codex could bill this run to the key instead of the run's "
                   "login (set: %s)" % ", ".join(keys))
    if command in SPENDS_TURNS and run.uses(CLAUDE):
        names = hierarchy_hosts.billing_set(CLAUDE, os.environ)
        if names:
            refuse("unset %s: claude could bill this run to them instead of the run's login" % ", ".join(names))
    return tools


# -- state, evidence and child processes ----------------------------------------------------------------------------------

def load_state(run):
    return read_json(run.state_path) if run.state_path.is_file() else None


def custody(run):
    value = {key: run.raw.get(key) for key in ("run", "project", "source", "codex_home", "base", "branch",
                                              "initiative", "lanes", "roles")}
    # Only when given, so a v1 run's recorded custody still matches. The plan is written once at init, and changing
    # hosts during a run is out of scope (ADR T2(a) §1).
    if "hosts" in run.raw:
        value["hosts"] = run.raw["hosts"]
    if "claude_home" in run.raw:
        value["claude_home"] = run.raw["claude_home"]
    return value


def save_state(run, state):
    write_atomic(run.state_path, as_json(state))


def update_state(run, mutate):
    """Reload/mutate/save in a short transaction; mutate must not run a child or wait for browser/model work."""
    if not run.uses(CLAUDE):
        state = load_state(run)
        mutate(state)
        save_state(run, state)
        return state
    # Lock order: .login.lock (when held), then .state.lock. Never acquire the login lock inside a transaction.
    revalidate_run(run)
    path = run.run / ".state.lock"
    require(not path.is_symlink(), "state lock must not be a symlink")
    descriptor = os.open(str(path), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    windows, locked = os.name == "nt", False
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                (not windows and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600))):
            refuse("state lock must be this user's regular file with one link and private permissions")
        if windows:
            import msvcrt
            os.lseek(descriptor, 0, os.SEEK_SET)
            # Windows permits locking a byte past EOF, so the empty lock file needs no unsynchronized seed write.
            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = True
        state = load_state(run)
        mutate(state)
        save_state(run, state)
        return state
    finally:
        try:
            if locked:
                if windows:
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def init_complete(state):
    return bool(state and state["init"].get("complete_at"))


def require_init(run, *, record_command=True, state=None):
    state = load_state(run) if state is None else state
    if not init_complete(state):
        refuse("init has not completed; run init first", record_command=record_command)
    if state.get("down", {}).get("started_at") or state.get("down", {}).get("done"):
        refuse("teardown has started; a new run needs a new run folder", record_command=record_command)
    return state


def index(run, *names):
    path = run.evidence / "index.json"
    value = read_json(path) if path.is_file() else {"schema": INDEX_SCHEMA, "files": {}}
    for name in names:
        value["files"][name] = {"sha256": sha_file(run.evidence / name), "at": timestamp()}
    write_atomic(path, as_json(value))


def save(run, name, value):
    path = run.evidence / name
    write_atomic(path, value if isinstance(value, bytes) else as_json(value))
    index(run, name)
    return {"path": str(path), "sha256": sha_file(path)}


def append_evidence(run, name, raw):
    path = run.evidence / name
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(path, "ab") as stream:
        stream.write(raw)
    index(run, name)
    return path


def child_env(run, path=None):
    revalidate_homes(run)
    # A host's home is the registry's only required ambient setting. Session tokens, agent settings, provider
    # credentials and SSH sockets must not cross this boundary, including on historical Codex-only runs.
    env = {name: value for name, value in os.environ.items()
           if name in CHILD_ENVIRONMENT or name.startswith("LC_")}
    env["CODEX_HOME"] = run.validated_homes[CODEX] if run.uses(CLAUDE) else str(run.codex_home)
    if run.uses(CLAUDE):
        env["CLAUDE_CONFIG_DIR"] = run.validated_homes[CLAUDE]
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if path is not None:
        env["PATH"] = path
    run.dropped_names = getattr(run, "dropped_names", set()) | (os.environ.keys() - env.keys())
    return env


def environment_evidence(run):
    names = getattr(run, "dropped_names", None)
    if names is not None:
        name = "child-environment.json"
        previous = read_json(run.evidence / name) if (run.evidence / name).is_file() else {}
        value = {"dropped_names": sorted(set(previous.get("dropped_names", [])) | names)}
        if value != previous:
            save(run, name, value)


def last_json(stdout):
    lines = [line for line in stdout.splitlines() if line.strip()]
    if not lines:
        return {}
    try:
        value = json.loads(lines[-1])
    except ValueError:
        return {"output": stdout[-2000:]}
    return value if isinstance(value, dict) else {"output": value}


def tool(run, name, *arguments):
    """(exit code, last JSON object of stdout, process) of one hierarchy tool run as a child."""
    argv = [sys.executable, "-I", "-B", str(HERE / ("hierarchy_%s.py" % name)), *map(str, arguments)]
    proc = subprocess.run(argv, capture_output=True, text=True, env=child_env(run), stdin=subprocess.DEVNULL)
    return proc.returncode, last_json(proc.stdout), proc


def checked(run, label, name, *arguments, ok=(0,)):
    code, answer, proc = tool(run, name, *arguments)
    if code not in ok:
        reason = answer.get("error") or proc.stderr.strip()[-800:] or "exit %d" % code
        (refuse if code == REFUSED else fail)("%s: %s" % (label, reason), result=answer)
    return answer


def request_file(run, name, value):
    path = run.inputs / name
    write_atomic(path, as_json(value))
    return path


def git(cwd, *arguments, ok=False):
    proc = subprocess.run(["git", "-C", str(cwd), *arguments], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL)
    if not ok and proc.returncode != 0:
        raise ValueError("git %s failed in %s: %s" % (arguments[0], cwd, proc.stderr.strip()[-400:]))
    return proc if ok else proc.stdout.strip()


def aegis(run, *arguments):
    """`aegis team ...` from this checkout, isolated (-I) with the package path named, and no AEGIS_* overrides."""
    code = ("import runpy, sys; sys.path.insert(0, %r); sys.argv = ['aegis'] + sys.argv[1:]; "
            "runpy.run_module('aegis_cli', run_name='__main__')" % str(REPO))
    env = child_env(run)
    for name in AEGIS_OVERRIDES:
        env.pop(name, None)
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", code, *arguments], cwd=str(REPO), capture_output=True,
                          text=True, env=env, stdin=subprocess.DEVNULL)
    try:
        answer = json.loads(proc.stdout)
    except ValueError:
        answer = {"output": proc.stdout[-2000:]}
    return proc.returncode, answer, proc


# -- init ---------------------------------------------------------------------------------------------------------------

def preconditions(run):
    """Checked on a fresh init only: the folders and the clone it may use. Nothing is written before these pass."""
    for name in MANAGED:
        if (run.run / name).exists():
            refuse("run folder already holds %s; init needs a fresh run folder" % name)
    if run.codex_home.exists():
        refuse("codex_home %s already exists; init needs a new folder" % run.codex_home)
    if run.uses(CLAUDE) and run.claude_home.exists():
        refuse("claude_home %s already exists; init needs a new folder" % run.claude_home)
    real = os.path.realpath(run.project)
    for live in run.live:
        mine = os.path.realpath(live)
        if real == mine or real.startswith(mine.rstrip(os.sep) + os.sep):
            refuse("project is the owner's live checkout %s; use a fresh clone" % live)
    top = git(run.project, "rev-parse", "--show-toplevel", ok=True)
    if top.returncode != 0 or os.path.realpath(top.stdout.strip()) != real:
        refuse("project %s is not the root of a git checkout" % run.project)
    head = git(run.project, "rev-parse", "HEAD")
    if head != run.base_commit:
        refuse("project HEAD is %s, not the configured base %s" % (head, run.base_commit))
    tree = git(run.project, "rev-parse", run.base_commit + "^{tree}")
    if run.base_tree is not None and tree != run.base_tree:
        refuse("base tree is %s, not the configured base_tree %s" % (tree, run.base_tree))
    if git(run.project, "status", "--porcelain", "--untracked-files=all"):
        refuse("project has uncommitted changes; a run starts from a clean clone")
    for lane in run.implementers:
        if git(run.project, "rev-parse", "--verify", "--quiet", "refs/heads/" + lane.branch, ok=True).returncode == 0:
            refuse("branch %s already exists in the project" % lane.branch)
    return tree


def once(run, state, key, action):
    """Persist intent before an external command; an uncertain result must never authorize a replay."""
    done = state["init"]["done"]
    if key not in done:
        pending = state["init"].get("pending")
        if pending:
            fail("init step %s has an unresolved outcome; inspect durable records before continuing" % pending)
        state["init"]["pending"] = key
        save_state(run, state)
        value = action()
        done[key] = value if isinstance(value, dict) else {"at": timestamp()}
        state["init"].pop("pending", None)
        save_state(run, state)
    return done[key]


def make_home(run, home, label):
    """A host home with this run's owner mark; one already there must carry the mark (a resumed init)."""
    run.run.mkdir(parents=True, exist_ok=True, mode=0o700)
    if home.exists():
        ownership(run, home, label)
        return
    home.mkdir(parents=True, mode=0o700)
    os.chmod(home, 0o700)
    mark = {"run": str(run.run), "initiative": run.id, "created_at": timestamp()}
    write_atomic(home / OWNER_MARK, as_json(mark))


def step_codex_home(run, state):
    """Named for Codex, as runs already past it recorded it: it makes each home the plan uses."""
    detail = {}
    if run.uses(CODEX):
        safe_codex_home(run)
        make_home(run, run.codex_home, "codex_home")
        detail["codex_home"] = str(run.codex_home)
    if run.uses(CLAUDE):
        safe_claude_home(run)
        make_home(run, run.claude_home, "claude_home")
        detail["claude_home"] = str(run.claude_home)
    return detail


def step_recipes(run, state):
    write_atomic(run.recipes, as_json(recipe_file(run)))
    answer = checked(run, "check-recipes", "jobs", "--store", run.store, "--recipes", run.recipes, "check-recipes")
    if answer.get("recipes_sha256") != sha_file(run.recipes):
        fail("check-recipes hashed %s, but recipes.json is %s" % (answer.get("recipes_sha256"), sha_file(run.recipes)))
    save(run, "recipes-check.json", answer)
    return {"recipes_sha256": answer["recipes_sha256"]}


def step_workspace(run, state):
    limits = request_file(run, "limits.json", run.limits)
    save(run, "workspace-init.json", checked(run, "workspace init", "workspace", "--store", run.store, "init",
                                             "--request", limits))


def initiative_record(run):
    return {**run.initiative, "checkouts": [str(run.project)], "source": "owner",
            "lanes": [lane.lease for lane in run.implementers]}


def step_provision(run, state):
    request = {"store": str(run.store), "base": str(run.base), "source": str(run.source), "python": run.python,
               "roles": run.roles, "lanes": {lane.id: lane.kind for lane in run.lanes},
               "initiative": initiative_record(run)}
    # Provision init refuses an initiative it already registered, so a failure after it (the evidence save or the plan
    # write) resumes past it on --continue instead of running it again.
    answer = once(run, state, "provision-init", lambda: checked(run, "provision init", "provision", "init", "--request",
                                                               request_file(run, "provision-init.json", request)))
    save(run, "provision-init.json", answer)
    # Here rather than as a step of its own, so a run already past this step keeps today's unchecked bindings. Provision
    # init refuses an existing base, so the plan can only follow it, before the first add-role.
    plan = hierarchy_hosts.plan_record(hierarchy=run.id, root=run.hosts["root"], team=run.hosts["team"],
                                       stand_ins={run.endpoint("front-door"): FRONT_DOOR_HOST},
                                       config_sha256=sha_file(run.config_path))
    write_atomic(run.base / hierarchy_hosts.PLAN_FILE, as_json(plan))
    save(run, hierarchy_hosts.PLAN_FILE, plan)


def step_front_door(run, state):
    # A stand-in binding that never runs a host: the owner's front-door mail goes through the mailbox CLI.
    request = {"base": str(run.base), "endpoint": run.endpoint("front-door"), "host": FRONT_DOOR_HOST,
               "session": str(uuid.uuid4()), "cwd": str(run.run)}
    save(run, "front-door.json", checked(run, "front-door add-role", "provision", "add-role", "--request",
                                         request_file(run, "front-door.json", request)))


def policy_value(run, authority):
    roles = ["root", "router", "coordinator", "operator", "reviewer"] + (["decider"] if "decider" in run.roles else [])
    actors = {}
    for role in roles:
        router = role == "router"
        # Journal labels only: the journal hashes them, and the served model comes from team.json at `up`.
        actors[role + "-1"] = {"role": role, "generation": 1, "cap_seconds": 86400 if role == "root" else 3600,
                               "profile": {"model": run.team["model"], "effort": "medium" if router else run.team["reasoning"],
                                           "tier": "ultrafast" if router else "default",
                                           "filesystem": "workspace-write" if role == "operator" else "read-only",
                                           "tools": ["read", "decide"] if role == "root" else []}}
    commit = git(run.source, "rev-parse", "HEAD")
    tree = git(run.source, "rev-parse", "HEAD^{tree}")
    return {"schema": hierarchy_lifecycle.POLICY, "source": {"commit": commit, "tree": tree, "dirty_sha256": EMPTY_SHA256},
            "authority": [authority], "actors": actors, "current": {role: role + "-1" for role in roles},
            "successors": {}}


def step_policy(run, state):
    authority = save(run, "owner-authority.txt", ("Owner authorizes the team run %s on %s (base %s), %s.\n" % (
        run.id, run.project, run.base_commit, timestamp()[:10])).encode("utf-8"))
    policy = policy_value(run, authority)
    write_atomic(run.run / "policy.json", as_json(policy))
    save(run, "policy.json", policy)


def step_lifecycle(run, state):
    once(run, state, "lifecycle-init", lambda: save(run, "lifecycle-init.json", checked(
        run, "lifecycle init", "lifecycle", "--root", run.lifecycle, "init", "--policy", run.run / "policy.json",
        "--evidence-only")))
    once(run, state, "checkpoint-before", lambda: save(run, "checkpoint-before.json", checked(
        run, "lifecycle checkpoint", "lifecycle", "--root", run.lifecycle, "checkpoint")))


def step_slots(run, state):
    for lane in run.implementers:
        def ask(lane=lane):
            answer = checked(run, "slot request for " + lane.id, "workspace", "--store", run.store, "request",
                             "--request", request_file(run, "slot-%s.json" % lane.id, {
                                 "initiative": run.id, "kind": "writer", "holder": lane.endpoint}))
            save(run, "slot-request-%s.json" % lane.id, answer)
            return {"request_id": answer["request"]["request_id"]}
        asked = once(run, state, "slot-request:" + lane.id, ask)

        def grant(lane=lane, asked=asked):
            answer = checked(run, "slot grant for " + lane.id, "workspace", "--store", run.store, "grant-next",
                             "--kind", "writer")
            granted = answer.get("granted")
            if granted is None:
                fail("no writer slot is free for %s: %s" % (lane.endpoint, json.dumps(answer.get("waiting"))[:400]))
            if granted["request_id"] != asked["request_id"]:
                fail("the writer slot went to %s, not %s's request %s" % (granted["holder"], lane.endpoint,
                                                                          asked["request_id"]))
            save(run, "slot-grant-%s.json" % lane.id, answer)
        once(run, state, "slot-grant:" + lane.id, grant)


def step_worktrees(run, state):
    for lane in run.implementers:
        def add(lane=lane):
            lane.worktree.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            git(run.project, "worktree", "add", "-q", "-b", lane.branch, str(lane.worktree), run.base_commit)
            if lane.tmpdir is not None:
                lane.tmpdir.mkdir(parents=True, exist_ok=True, mode=0o700)
            save(run, "worktree-%s.json" % lane.id, {
                "path": str(lane.worktree), "branch": lane.branch, "head": git(lane.worktree, "rev-parse", "HEAD"),
                "tmpdir": None if lane.tmpdir is None else str(lane.tmpdir)})
            return {"path": str(lane.worktree), "branch": lane.branch}
        once(run, state, "worktree:" + lane.id, add)


def step_leases(run, state):
    for lane in run.implementers:
        def claim(lane=lane):
            code, answer, proc = aegis(run, "team", "claim", lane.lease, "--workspace", str(run.project), "--paths",
                                       *lane.paths, "--ttl", str(run.lease_ttl), "--owner", lane.endpoint, "--role",
                                       "implementer", "--branch", lane.branch, "--json")
            if code != 0:
                fail("aegis team claim %s: %s" % (lane.lease, answer.get("error") or answer.get("message") or
                                                  proc.stderr.strip()[-400:] or "exit %d" % code), result=answer)
            save(run, "lease-claim-%s.json" % lane.id, answer)
            return {"lease": lane.lease, "oid": answer["oid"]}
        once(run, state, "lease:" + lane.id, claim)


def step_checkouts(run, state):
    request = {"initiative": run.id, "source": "owner",
               "checkouts": [str(run.project)] + [str(lane.worktree) for lane in run.implementers]}
    save(run, "checkouts.json", checked(run, "workspace update", "workspace", "--store", run.store, "update",
                                        "--request", request_file(run, "checkouts.json", request)))


def preflight_result(run, recipe, job, expect, recipes_sha256):
    path = run.run / "preflight" / "store" / "jobs" / (run.id + "pre") / job / "result.json"
    if not path.is_file():
        return {"recipe": recipe, "job": job, "met": False, "problem": "preflight %s: the job left no result" % recipe}
    result = read_json(path)
    tests = result.get("tests")
    row = {"recipe": recipe, "job": job, "state": result.get("state"), "tests": tests, "reason": result.get("reason"),
           "recipes_sha256": result.get("recipes_sha256"),
           "git_stub": (result.get("source_export") or {}).get("git_stub", False), "expect": expect,
           "result": {"path": str(path), "sha256": sha_file(path)}}
    want = expect.get("state", "completed")
    problem = None
    if row["state"] != want:
        problem = "expected state %s, the job ended %s%s" % (want, row["state"],
                                                            " (%s)" % row["reason"] if row["reason"] else "")
    elif ("failed" in expect or "min_passed" in expect) and not isinstance(tests, dict):
        problem = "expected test counts, the job reported none"
    elif "failed" in expect and tests["failed"] != expect["failed"]:
        problem = "expected %d failed, the job reported %d" % (expect["failed"], tests["failed"])
    elif "min_passed" in expect and tests["passed"] < expect["min_passed"]:
        problem = "expected at least %d passed, the job reported %d" % (expect["min_passed"], tests["passed"])
    elif row["recipes_sha256"] != recipes_sha256:
        problem = "the job ran under recipes %s, not the checked %s" % (row["recipes_sha256"], recipes_sha256)
    row["met"] = problem is None
    if problem:
        row["problem"] = "preflight %s: %s" % (recipe, problem)
    return row


def step_preflight(run, state):
    """The kept recipes on the base, in a store of their own, with stand-in sessions that never run."""
    pre = run.run / "preflight"
    pre_id = run.id + "pre"
    require(SLUG.fullmatch(pre_id) is not None, "initiative id %s is too long for the preflight's %s" % (run.id, pre_id))
    store, base = pre / "store", pre / "initiatives" / pre_id
    once(run, state, "preflight-store", lambda: checked(run, "preflight workspace init", "workspace", "--store", store,
                                                        "init", "--request", run.inputs / "limits.json"))
    once(run, state, "preflight-provision", lambda: checked(
        run, "preflight provision init", "provision", "init", "--request", request_file(run, "preflight-init.json", {
            "store": str(store), "base": str(base), "source": str(run.source), "python": run.python,
            "lanes": {"p": "implementer"},
            "initiative": {**run.initiative, "id": pre_id, "repository": run.initiative["repository"] + "-preflight",
                           "checkouts": [str(run.project)], "source": "owner"}})))
    roles = {}
    for role in ("orchestrator", "root"):
        roles[role] = once(run, state, "preflight-" + role, lambda role=role: checked(
            run, "preflight add-role " + role, "provision", "add-role", "--request",
            request_file(run, "preflight-%s.json" % role, {"base": str(base), "endpoint": "%s/%s" % (pre_id, role),
                                                            "host": "claude-code", "session": str(uuid.uuid4()),
                                                            "cwd": str(run.run)})))
    attempt = state["init"].get("preflight_attempt", 0) + 1
    state["init"]["preflight_attempt"] = attempt
    save_state(run, state)
    sender = roles["orchestrator"]
    tree = state["init"]["base_tree"]
    jobs = {}
    for recipe in run.preflight["recipes"]:
        packet = {"schema": PACKET_SCHEMA, "recipe": recipe, "checkout": str(run.project), "commit": run.base_commit,
                  "tree": tree}
        if recipe in run.preflight.get("paths", {}):
            packet["paths"] = run.preflight["paths"][recipe]
        job = "pre-%d-%s" % (attempt, recipe)
        message = {"message_id": job + "-packet", "from": sender["endpoint"], "to": "%s/root" % pre_id,
                   "host": sender["host"], "session": sender["session"], "binding_generation": sender["generation"],
                   "type": "info", "body": json.dumps(packet, sort_keys=True)}
        sent = checked(run, "preflight packet " + recipe, "mailbox", "--root", base / "mailbox", "publish", "--request",
                       request_file(run, "preflight-%s-packet.json" % job, message))
        message = {**message, "message_id": job, "type": "job_request", "body": "Preflight %s on the base." % recipe,
                   "brief": {"path": sent["path"], "sha256": sent["sha256"]}}
        checked(run, "preflight job request " + recipe, "mailbox", "--root", base / "mailbox", "publish", "--request",
                request_file(run, "preflight-%s.json" % job, message))
        jobs[recipe] = job
    ran = checked(run, "preflight run-open", "jobs", "--store", store, "--recipes", run.recipes, "run-open",
                  "--initiative", pre_id, ok=(0, 3))
    save(run, "preflight-run-open.json", ran)
    checked_sha = state["init"]["steps"]["recipes"]["recipes_sha256"]
    rows = [preflight_result(run, recipe, jobs[recipe], run.preflight["expect"].get(recipe, {}), checked_sha)
            for recipe in run.preflight["recipes"]]
    save(run, "preflight-results.json", {"attempt": attempt, "results": rows})
    save(run, "preflight-clean.json", checked(run, "preflight clean", "jobs", "--store", store, "--recipes", run.recipes,
                                              "clean", "--initiative", pre_id, "--finished"))
    problems = [row["problem"] for row in rows if not row["met"]]
    if problems:
        fail(problems[0], results=rows)
    return {"attempt": attempt}


STEPS = {"codex-home": step_codex_home, "recipes": step_recipes, "workspace": step_workspace,
         "provision": step_provision, "front-door": step_front_door, "policy": step_policy,
         "lifecycle": step_lifecycle, "slots": step_slots, "worktrees": step_worktrees, "leases": step_leases,
         "checkouts": step_checkouts, "preflight": step_preflight}


def next_step(state):
    if state is None:
        return INIT_STEPS[0]
    return next((step for step in INIT_STEPS if step not in state["init"]["steps"]), None)


def init(run, args):
    if run.hosts["team"] == CLAUDE:
        # Provision makes tmpdir Codex-only, so a Claude team refuses one here rather than at up (ADR T2(a) section 1).
        for lane in run.implementers:
            if lane.tmpdir is not None:
                refuse("lane %s: tmpdir is only for a Codex writer, and this run's team host is claude-code" % lane.id)
    state = load_state(run)
    if state and (state.get("down", {}).get("started_at") or state.get("down", {}).get("done")):
        refuse("teardown has started; a new run needs a new run folder")
    if init_complete(state):
        refuse("init already completed at %s; a new run needs a new run folder" % state["init"]["complete_at"])
    if args.resume:
        if state is None:
            refuse("nothing to continue: init has not run in %s" % run.run)
    elif state is not None:
        failed = state["init"].get("failed") or {"step": next_step(state), "error": "it was interrupted"}
        refuse("init stopped at %s: %s; fix the cause, then run init --continue" % (failed["step"], failed["error"]))
    else:
        tree = preconditions(run)
        state = {"schema": STATE_SCHEMA, "created_at": timestamp(), "config": str(run.config_path),
                 "custody": custody(run),
                 "init": {"steps": {}, "done": {}, "failed": None, "complete_at": None, "base_tree": tree},
                 "root": None, "up": None, "down": {"done": {}}}
        revalidate_run(run)
        run.run.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not getattr(run, "owner_operation_locked", False):
            # The first init creates the directory that owns the lock. Reload everything under that lock before
            # its first state save too, so two initializers cannot outlive one another and erase later operations.
            with operation_lock(run):
                return init(run, args)
        save_state(run, state)
    revalidate_run(run)
    ran = []
    for step in INIT_STEPS:
        if step in state["init"]["steps"]:
            continue
        try:
            detail = STEPS[step](run, state)
        except (Stop, ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
            code = exc.code if isinstance(exc, Stop) else FAILED
            extra = exc.detail if isinstance(exc, Stop) else {}
            state["init"]["failed"] = {"step": step, "error": str(exc), "at": timestamp()}
            save_state(run, state)
            raise Stop(code, str(exc), step=step, **extra) from exc
        state["init"]["steps"][step] = {"at": timestamp(), **(detail or {})}
        state["init"]["failed"] = None
        save_state(run, state)
        ran.append(step)
    state["init"]["complete_at"] = timestamp()
    save_state(run, state)
    return OK, {"init": "complete", "ran": ran, "run": str(run.run), "evidence": str(run.evidence),
                "next": "login, then root --session <your ROOT session>, then up"}


# -- login and root -------------------------------------------------------------------------------------------------------

@contextmanager
def login_lock(run, busy_message="another login is running for this run"):
    """Keep one lock inode for this run; closing releases it on every success or exception, without unlinking it."""
    import fcntl  # POSIX operations only; the module itself is imported during Windows test collection.
    revalidate_run(run)
    descriptor = os.open(str(run.run / ".login.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600):
            refuse("login lock must be this user's regular file with one link and mode 0600")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            refuse(busy_message, record_command=False)
        yield
    finally:
        os.close(descriptor)


def claude_login_preconditions(run):
    """All read-only Claude checks precede either host's interactive login in a mixed plan."""
    revalidate_homes(run)
    timeout = float(os.environ.get(CLAUDE_AUTH_STATUS_TIMEOUT, "60"))
    require(0 < timeout <= 60, CLAUDE_AUTH_STATUS_TIMEOUT + " must be greater than 0 and at most 60 seconds")
    credentials_digest(run, missing_ok=True)
    return timeout


def login(run, args):
    """Each host the plan uses, logged in to the run's own home. A Codex-only plan answers as it always did."""
    require_init(run)
    if not run.uses(CLAUDE):
        return OK, login_codex(run)
    with login_lock(run):
        require_init(run)
        timeout = claude_login_preconditions(run)
        logins = {}
        try:
            if run.uses(CODEX):
                logins[CODEX] = login_codex(run)
            logins[CLAUDE] = login_claude(run, timeout)
        except Stop as stop:
            if logins:
                stop.detail.setdefault("logins", logins)
            raise
        return OK, {"logins": logins}


def login_codex(run):
    import hierarchy_native_probe as probe
    proc = subprocess.run(["codex", "login"], env=child_env(run))
    if proc.returncode != 0:
        fail("codex login exited %d" % proc.returncode)
    revalidate_homes(run)
    home = Path(run.validated_homes[CODEX]) if run.uses(CLAUDE) else run.codex_home
    # The probe's real-login folder rules, less its own owner mark, with this run's mark and its sessions/ allowed.
    allowed = (set(probe.EXISTING_LOGIN_ENTRIES) - {probe.OWNER_MARK}) | {OWNER_MARK, "sessions"}
    entries = sorted(os.listdir(home))
    extra = [entry for entry in entries if entry not in allowed]
    try:
        if extra:
            raise probe.Refusal("CODEX_HOME holds entries a codex login does not create: " + ", ".join(extra))
        if probe.AUTH_FILE not in entries:
            raise probe.Refusal("CODEX_HOME has no auth.json after codex login")
        auth = probe.auth_digest(home / probe.AUTH_FILE)
        probe.login_extras(home, shutil.which("codex"))
    except probe.Refusal as exc:
        refuse(str(exc))
    answer = {"codex_home": str(run.codex_home), "auth_sha256": auth, "entries": entries}
    revalidate_homes(run)
    save(run, "login.json", answer)
    return answer


def credentials_digest(run, missing_ok=False):
    """The sha256 of the Claude home's credentials file, which must be this user's one regular file with mode 0600. The
    file itself is never copied, and only its hash enters evidence."""
    path = Path(run.validated_homes[CLAUDE]) / CLAUDE_CREDENTIALS
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return None
        refuse("claude_home has no %s after claude auth login" % CLAUDE_CREDENTIALS)
    if stat.S_ISLNK(info.st_mode):
        refuse("%s in claude_home is a symlink: %s" % (CLAUDE_CREDENTIALS, path))
    if not stat.S_ISREG(info.st_mode):
        refuse("%s in claude_home is not a regular file: %s" % (CLAUDE_CREDENTIALS, path))
    # A second link could be the owner's own ~/.claude credentials, which the run would then refresh and use.
    if info.st_nlink != 1:
        refuse("%s in claude_home has %d hard links: %s" % (CLAUDE_CREDENTIALS, info.st_nlink, path))
    if info.st_uid != os.getuid():
        refuse("%s in claude_home is not owned by this user: %s" % (CLAUDE_CREDENTIALS, path))
    if stat.S_IMODE(info.st_mode) != 0o600:
        refuse("%s in claude_home has mode %04o, not 0600: %s" % (CLAUDE_CREDENTIALS, stat.S_IMODE(info.st_mode), path))
    # O_NONBLOCK: a FIFO swapped in after the lstat would otherwise block this open forever.
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if ((opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink, opened.st_uid) !=
                (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid)):
            refuse("%s in claude_home changed while it was checked: %s" % (CLAUDE_CREDENTIALS, path))
        return hashlib.sha256(stream.read()).hexdigest()


def credential_observation(run):
    """Observe identity and bytes in the validated home; metadata also detects a rewrite with identical contents."""
    path = Path(run.validated_homes[CLAUDE]) / CLAUDE_CREDENTIALS
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
        return None
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if ((opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink, opened.st_uid) !=
                (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid)):
            refuse("%s in claude_home changed while it was observed: %s" % (CLAUDE_CREDENTIALS, path))
        digest = hashlib.sha256(stream.read()).hexdigest()
    return {"identity": (info.st_dev, info.st_ino, digest),
            "version": (info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)}


def remove_login_credentials(run, before, written):
    """Within the login lock, remove only the regular file whose device, inode and bytes this login changed."""
    if written is None or written == before:
        return False
    home = Path(run.validated_homes[CLAUDE])
    try:
        real = safe_home(run, home, "claude_home", "CLAUDE_CONFIG_DIR", owner_homes(CLAUDE) + owner_homes(CODEX))
    except Stop:
        return False
    if real != str(home):
        return False
    current = credential_observation(run)
    if current is None or current["identity"] != written["identity"]:
        return False
    (home / CLAUDE_CREDENTIALS).unlink()
    return True


def discard_claude_login_evidence(run):
    """A failed login must not leave an accepted login record or its index entry, including from an earlier login."""
    revalidate_run(run)
    (run.evidence / "login-claude.json").unlink(missing_ok=True)
    path = run.evidence / "index.json"
    if path.is_file():
        value = read_json(path)
        if "login-claude.json" in value["files"]:
            del value["files"]["login-claude.json"]
            write_atomic(path, as_json(value))


def login_claude(run, timeout):
    """claude auth login in the run's CLAUDE_CONFIG_DIR, which the owner finishes in the browser, then its status. The
    evidence keeps the filtered auth record (no email or organization) and the credentials' hash, never the file."""
    revalidate_homes(run)
    credentials_digest(run, missing_ok=True)
    state = require_init(run)
    if CLAUDE in state.get("logins", {}):
        def invalidate(current):
            require_init(run, state=current)
            current.get("logins", {}).pop(CLAUDE, None)
            revalidate_homes(run)
        update_state(run, invalidate)
    # A CLI may truncate or refresh credentials: refuse unsafe existing files before either auth command sees them.
    before = credential_observation(run)
    written = None
    try:
        proc = subprocess.run(["claude", "auth", "login", "--claudeai"], env=child_env(run))
        written = credential_observation(run)
        if proc.returncode != 0:
            fail("claude auth login exited %d" % proc.returncode)
        # A teardown completed by an older command must remain authoritative after the browser login returns.
        require_init(run, record_command=False)
        revalidate_homes(run)
        credentials_digest(run)
        proc = subprocess.run(["claude", "auth", "status", "--json"], env=child_env(run), capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=timeout)
        try:
            parsed = strict_json(proc.stdout)
        except (ValueError, RecursionError):
            parsed = None
        revalidate_homes(run)
        record, problems = hierarchy_hosts.claude_auth_check(proc.returncode, parsed, run.validated_homes[CLAUDE])
        if problems:
            refuse("claude auth status does not show this run's claude.ai login: " + "; ".join(problems))
        digest = credentials_digest(run)
        answer = {"claude_home": str(run.claude_home), "auth": record, "credentials_sha256": digest,
                  "entries": sorted(os.listdir(run.validated_homes[CLAUDE])),
                  "managed_settings": CLAUDE_MANAGED_SETTINGS.exists()}
        revalidate_homes(run)
        save(run, "login-claude.json", answer)
        def accept(current):
            require_init(run, record_command=False, state=current)
            current.setdefault("logins", {})[CLAUDE] = {"credentials_sha256": digest}
            revalidate_homes(run)
        update_state(run, accept)
        return answer
    except Exception as exc:
        removed = remove_login_credentials(run, before, written)
        discard_claude_login_evidence(run)
        if removed and isinstance(exc, Stop):
            raise Stop(exc.code, str(exc) + "; removed credentials written by this login",
                       record_command=exc.record_command, **exc.detail) from exc
        # Keep TimeoutExpired intact: main maps subprocess failures to exit 3.
        raise


def adapter_tools(run, connection):
    """The tool names ROOT's own connection offers, read with tools/list over it."""
    server = read_json(Path(connection))["mcpServers"]["aegis_decision"]
    frames = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
              {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}]
    proc = subprocess.run([server["command"], *server["args"]], input="".join(json.dumps(f) + "\n" for f in frames),
                          capture_output=True, text=True, timeout=60, env=child_env(run))
    for line in proc.stdout.splitlines():
        reply = json.loads(line)
        if reply.get("id") == 2 and "result" in reply:
            return [entry["name"] for entry in reply["result"]["tools"]]
    fail("ROOT's connection listed no tools: %s" % (proc.stdout + proc.stderr)[-400:])


def current_actor(run, role):
    return read_json(run.run / "policy.json")["current"].get(role)


def claude_pin(run):
    revalidate_homes(run)
    pinned = (require_init(run).get("logins", {}).get(CLAUDE) or {}).get("credentials_sha256")
    require(pinned is not None and credentials_digest(run) == pinned,
            "the run's Claude login changed since `login`; run login again before starting Claude")
    for folder, directories, names in os.walk(run.validated_homes[CLAUDE], followlinks=False):
        for name in directories + names:
            require(not (Path(folder) / name).is_symlink(), "claude_home contains a symlink: " + str(Path(folder) / name))


def claude_transcript(run, session):
    found = hierarchy_hosts.transcripts(CLAUDE, run.validated_homes[CLAUDE], session)
    require(len(found) == 1, "Claude session is not confirmed by one transcript in the run's claude_home/projects")
    events = list(hierarchy_hosts.claude_events(found[0].read_bytes()))
    identities = {event["sessionId"] for event in events if "sessionId" in event and isinstance(event["sessionId"], str)}
    require(identities == {session}, "Claude session is not confirmed by its transcript sessionId")
    return found[0]


def planned_binding(run, endpoint, host):
    mailbox = Mailbox(run.mailbox_root)
    entry = hierarchy_provision.registry_role(mailbox, endpoint)
    plan = hierarchy_hosts.governing_plan(run.base, run.mailbox_root, run.id)
    hierarchy_hosts.require_binding(plan, endpoint, host, hierarchy_roles.writer(entry))
    return mailbox


def claude_connection(run, binding, connection):
    """Only provision's own team servers may enter a restricted Claude invocation."""
    setup = read_json(run.base / "provision.json")
    endpoint = binding["endpoint"]
    servers = read_json(Path(connection))
    require(set(servers) == {"mcpServers"}, "Claude connection has unexpected fields")
    if endpoint_parts(endpoint)[1] == "root":
        request = {"lifecycle": str(run.lifecycle), "actor": current_actor(run, "root"),
                   "loop_state": str(run.loop_state), "evidence": str(run.evidence)}
        arguments = hierarchy_provision.decision_args(setup, endpoint, CLAUDE, binding["session"], binding["generation"], request)
        expected = {"aegis_decision": {"command": setup["python"], "args": arguments}}
        allowed = ["mcp__aegis_decision__" + name for name in ROOT_TOOLS]
    else:
        mailbox = Mailbox(run.mailbox_root)
        entry = hierarchy_provision.registry_role(mailbox, endpoint)
        actual = servers["mcpServers"].get("aegis_mailbox", {}).get("args", [])
        options = {}
        for flag, key in (("--lifecycle", "lifecycle"), ("--actor", "actor"), ("--source-repo", "source_repo")):
            if flag in actual:
                offset = actual.index(flag)
                require(offset + 1 < len(actual), "incomplete Claude connection argument: " + flag)
                options[key] = actual[offset + 1]
        if "lifecycle" in options:
            require(options["lifecycle"] == str(run.lifecycle), "Claude connection names another lifecycle")
        if "actor" in options:
            require(options["actor"] == current_actor(run, endpoint_parts(endpoint)[1]), "Claude connection names another actor")
        if "source_repo" in options:
            hierarchy_roles.require_source_views(endpoint, mailbox.endpoint(endpoint).get("kind"))
        arguments = hierarchy_provision.adapter_args(setup, endpoint, CLAUDE, binding["session"], binding["generation"],
                                                       options.get("source_repo"), hierarchy_provision.lifecycle_args(options))
        expected = {"aegis_mailbox": {"command": setup["python"], "args": arguments}}
        tools = hierarchy_provision.MAILBOX_TOOLS + list(hierarchy_provision.role_workspace_tools(mailbox, endpoint))
        if "lifecycle" in options:
            tools += list(hierarchy_roles.lifecycle_tools(entry))
        if "source_repo" in options:
            tools += list(hierarchy_roles.SOURCE_VIEW_TOOLS)
        allowed = ["mcp__aegis_mailbox__" + name for name in tools]
        if hierarchy_provision.takes_board(setup, mailbox, endpoint):
            expected["aegis_board"] = {"command": setup["python"], "args": hierarchy_provision.board_args(
                setup, endpoint, CLAUDE, binding["session"], binding["generation"])}
            allowed += ["mcp__aegis_board__" + name for name in hierarchy_provision.BOARD_TOOL_SPECS]
    require(servers["mcpServers"] == expected, "Claude connection differs from the team's provisioned servers")
    return allowed


def claude_resume_profile(run, binding, profile):
    start = next((request for endpoint, request in plan_roles(run) if endpoint == binding["endpoint"]), None)
    require(start is not None and profile["cwd"] == str(Path(start["cwd"]).resolve()),
            "Claude print profile cwd differs from the configured worktree")
    argv = profile["argv"]
    require(isinstance(argv, list) and all(isinstance(word, str) for word in argv), "invalid Claude print argv")
    connection = str(run.base / "connections" / ("%s-g%d.json" % (binding["endpoint"].replace("/", "%2F"), binding["generation"])))
    allowed = claude_connection(run, binding, connection)
    mailbox = Mailbox(run.mailbox_root)
    tool_words = [word[len("--tools="):] for word in argv if word.startswith("--tools=")]
    require(len(tool_words) == 1, "Claude print profile differs from the registry argv")
    tools, _writer = hierarchy_provision.role_tools(binding["endpoint"], mailbox, tool_words[0])
    allowed += [name for name in tools if name in hierarchy_provision.WRITE_TOOLS]
    options = {}
    for flag, key in (("--model", "model"), ("--effort", "effort")):
        if flag in argv:
            offset = argv.index(flag)
            require(offset + 1 < len(argv), "incomplete Claude print argument: " + flag)
            options[key] = argv[offset + 1]
    options, _fixed = hierarchy_provision.fixed_profile(options, mailbox, binding["endpoint"], CLAUDE)
    options, _team = hierarchy_provision.team_settings(run.base, CLAUDE, options,
                                                      hierarchy_provision.role_kind(mailbox, binding["endpoint"]))
    # The registry builder has one supported --settings payload. Never pass a profile's arbitrary JSON through.
    if "--settings" in argv and options.get("effort") == "max":
        options = {**options, "ultracode": True}
    expected = hierarchy_provision.claude_argv(["--resume", binding["session"]], connection, tools, allowed, options, None)
    require(argv == expected, "Claude print profile differs from the registry argv")
    return expected


def root(run, args):
    state = require_init(run)
    require(hierarchy_provision.SESSION.fullmatch(args.session) is not None, "invalid session: " + args.session[:80])
    host = run.hosts["root"]
    mailbox = planned_binding(run, run.endpoint("root"), host)
    request = {"base": str(run.base), "endpoint": run.endpoint("root"), "host": host, "session": args.session,
               "lifecycle": str(run.lifecycle), "actor": current_actor(run, "root"), "loop_state": str(run.loop_state),
               "evidence": str(run.evidence)}
    history = mailbox.bindings(request["endpoint"])
    require(not history or (history[-1]["session"] == args.session and history[-1]["host"] == host),
            "endpoint is bound to another session; hand it off first")
    hierarchy_roles.require_independent_session(mailbox, request["endpoint"], host, args.session)
    if host == CLAUDE:
        claude_pin(run)
        claude_transcript(run, args.session)
        offered = (hierarchy_provision.DECISION_TOOL, *hierarchy_roles.decision_tools(hierarchy_roles.role(request["endpoint"])))
        require(offered == ROOT_TOOLS, "ROOT tools mismatch: expected " + ", ".join(ROOT_TOOLS))
        setup = read_json(run.base / "provision.json")
        hierarchy_provision.hierarchy_runtime_source.verify(setup, run.base)
        hierarchy_provision.check_role_request(request, setup)
        # Provision stages its session record and validates the request before binding. Avoid a request-file write
        # on this path: an unconfirmed conversation or mismatched binding must leave no files behind.
        try:
            answer = hierarchy_provision.add_role(request)
        except (ValueError, OSError) as exc:
            fail("ROOT provisioning failed: %s; inspect the retained binding, connection and session records" % exc)
        answer["mcp_config"] = answer["connection"]
    else:
        # Stage the input outside the run until provision accepts it. A refusal (for example runtime source drift)
        # cannot leave inputs/root.json behind. The accepted run retains exactly the same request bytes as before.
        with tempfile.TemporaryDirectory() as folder:
            staged = Path(folder) / "root.json"
            staged.write_bytes(as_json(request))
            code, answer, _ = tool(run, "provision", "add-role", "--request", staged)
        if code != 0:
            (refuse if code == REFUSED else fail)(answer.get("error", "provision add-role exited %d" % code))
        request_file(run, "root.json", request)
    try:
        tools = adapter_tools(run, answer["connection"])
    except (Stop, ValueError, OSError, subprocess.SubprocessError) as exc:
        fail("ROOT was bound but its tool probe failed: %s; binding, connection and session record retained" % exc)
    if host == CLAUDE and tuple(tools) != ROOT_TOOLS:
        fail("ROOT tools mismatch after binding; binding and session record retained for inspection", tools=tools)
    save(run, "root-binding.json", {**answer, "tools": tools})
    binding = {"session": args.session, "generation": answer["generation"], "connection": answer["connection"],
               "mcp_config": answer["mcp_config"], "tools": tools, "at": timestamp()}
    if run.uses(CLAUDE):
        def bind(current):
            require_init(run, state=current)
            current["root"] = binding
        update_state(run, bind)
    else:
        state["root"] = binding
        save_state(run, state)
    return OK, {"endpoint": answer["endpoint"], "session": args.session, "generation": answer["generation"],
                "connection": answer["connection"], "mcp_config": answer["mcp_config"], "tools": tools}


# -- up -------------------------------------------------------------------------------------------------------------------

def loop_flags(run):
    return ["--lifecycle", run.lifecycle, "--store", run.store, "--recipes", run.recipes, "--state-dir", run.loop_state]


def process_alive(pid):
    try:
        with open("/proc/%d/stat" % pid, encoding="utf-8") as stream:
            # The state follows the command name, which is in parentheses and may hold spaces.
            return stream.read().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


def loop_process(run):
    """(pid or None, alive, whether that process is this run's loop by its command line)."""
    try:
        pid = int(run.pid_path.read_text().strip())
    except (OSError, ValueError):
        return None, False, False
    if not process_alive(pid):
        return pid, False, False
    try:
        words = Path("/proc/%d/cmdline" % pid).read_bytes().decode("utf-8", "replace").split("\0")
    except OSError:
        return pid, False, False
    ours = any(Path(word).name == "hierarchy_loop.py" for word in words) and any(
        word == "--lifecycle" and index + 1 < len(words) and words[index + 1] == str(run.lifecycle)
        for index, word in enumerate(words))
    return pid, True, ours


def loop_state(run):
    """The loop's own lock-based liveness (hierarchy_loop.py status): running, stale or not_running."""
    if not run.lifecycle.is_dir():
        return "not_running", None
    _code, answer, _ = tool(run, "loop", *loop_flags(run), "status")
    return answer.get("state", "not_running"), answer


def plan_roles(run):
    """(endpoint, start request) in the order up starts them: router, orchestrator, decider, reviewers, implementers."""
    rows = []
    if "router" in run.roles:
        rows.append((run.endpoint("router"), {"cwd": str(run.project), "lifecycle": str(run.lifecycle)}))
    rows.append((run.endpoint("orchestrator"), {"cwd": str(run.project), "reader_shell": True}))
    if "decider" in run.roles:
        rows.append((run.endpoint("decider"), {"cwd": str(run.project), "reader_shell": True,
                                               "lifecycle": str(run.lifecycle), "actor": current_actor(run, "decider")}))
    for lane in run.reviewers:
        rows.append((lane.endpoint, {"cwd": str(run.project), "reader_shell": True}))
    for lane in run.implementers:
        request = {"cwd": str(lane.worktree)}
        if lane.tmpdir is not None:
            request["tmpdir"] = str(lane.tmpdir)
        rows.append((lane.endpoint, request))
    return rows


def expected_profile(run, mailbox, endpoint):
    """What provision builds the role's argv from: the registry's fixed profile, then team.json."""
    request, fixed = hierarchy_provision.fixed_profile({}, mailbox, endpoint, CODEX)
    options, _ = hierarchy_provision.team_settings(run.base, CODEX, request,
                                                   hierarchy_provision.role_kind(mailbox, endpoint))
    if not (options.get("model") and options.get("effort")):
        refuse("%s would start with no model or effort; team.json must give both" % endpoint)
    return {"model": options["model"], "effort": options["effort"], "tier": hierarchy_provision.applied_tier(fixed),
            "effort_from": "the role registry" if fixed is not None else "team.json"}


def find_rollout(run, endpoint, session):
    home = Path(run.validated_homes[CODEX]) if run.uses(CLAUDE) else run.codex_home
    found = sorted((home / "sessions").glob("**/rollout-*%s.jsonl" % session))
    if len(found) != 1:
        fail("%s rollout%s for %s's session %s under %s" % ("no" if not found else str(len(found)),
                                                           "" if len(found) == 1 else "s", endpoint, session,
                                                           home / "sessions"))
    return found[0]


def stop_role(run, endpoint):
    _code, answer, _ = tool(run, "launcher", "--base", run.base, "stop", "--endpoint", endpoint)
    return answer


def check_role(run, endpoint, session, want, accept):
    """The started role's rollout: no sub-agent tools (unless accepted), and the model and effort asked for. The served
    tier is reported, not checked: whether an account is served the Router's ultrafast tier is the probe's question."""
    rollout = find_rollout(run, endpoint, session)
    try:
        catalog = hierarchy_native.multi_agent_state(str(rollout), cid=session)
    except ValueError as exc:
        stop_role(run, endpoint)
        refuse("%s tool catalog is unavailable; it was stopped: %s" % (endpoint, exc))
    offered = catalog["agent_tools"]
    if not catalog["tool_records"] or catalog.get("unknown_tools"):
        stop_role(run, endpoint)
        refuse("%s tool catalog is unavailable; it was stopped" % endpoint)
    if offered and not accept:
        stop_role(run, endpoint)
        refuse("%s was offered sub-agent tools: %s; it was stopped. Pass --accept-agent-tools to accept that, which is "
               "recorded in evidence" % (endpoint, ", ".join(offered)))
    observed = hierarchy_native.inspect_codex(str(rollout), session, requested_tier=want["tier"] or "default")
    served = observed["profile"]
    problem = None
    if served["model"] != want["model"]:
        problem = "%s was served model %s, but team.json asks for %s" % (endpoint, served["model"], want["model"])
    elif served["effort"] != want["effort"]:
        problem = "%s was served effort %s, but %s asks for %s" % (endpoint, served["effort"], want["effort_from"],
                                                                   want["effort"])
    if problem:
        stop_role(run, endpoint)
        refuse(problem)
    return {"rollout": str(rollout), "model": served["model"], "effort": served["effort"],
            "tier": observed["served_tier"], "tier_asked": want["tier"] or "default", "agent_tools": offered}


def start_loop(run):
    recipes = read_json(run.recipes)
    cargo_recipe, _ = recipe_needs(recipes)
    env = child_env(run)
    cargo_dir = None
    if cargo_recipe is not None:
        # The roles' own cargo runs inherit the loop's PATH through the wake, so the recipes' cargo goes first.
        cargo_dir = os.path.dirname(shutil.which("cargo", path=recipe_path(recipes)))
        parts = env.get("PATH", "").split(os.pathsep)
        if parts[:1] != [cargo_dir]:
            env["PATH"] = os.pathsep.join([cargo_dir] + [p for p in parts if p])
    run.loop_state.mkdir(parents=True, exist_ok=True, mode=0o700)
    argv = [sys.executable, "-I", "-B", str(HERE / "hierarchy_loop.py"), *map(str, loop_flags(run)), "run",
            "--interval", str(run.interval)]
    with open(run.log_path, "ab") as log:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, env=env,
                                   cwd=str(run.run), start_new_session=True)
    write_atomic(run.pid_path, ("%d\n" % process.pid).encode("ascii"))
    time.sleep(0.5)
    if process.poll() is not None:
        tail = run.log_path.read_bytes()[-800:].decode("utf-8", "replace")
        fail("the loop exited at once (exit %d); see %s: %s" % (process.returncode, run.log_path, tail))
    environ = {}
    for item in Path("/proc/%d/environ" % process.pid).read_bytes().split(b"\0"):
        key, _, value = item.decode("utf-8", "replace").partition("=")
        if key:
            environ[key] = value
    problems = []
    codex_home = run.validated_homes[CODEX] if run.uses(CLAUDE) else str(run.codex_home)
    if environ.get("CODEX_HOME") != codex_home:
        problems.append("its CODEX_HOME is %s, not %s" % (environ.get("CODEX_HOME"), codex_home))
    # The pinned wake passes no env=, so every Claude wake inherits this home from the loop (ADR T2(a) section 3).
    if run.uses(CLAUDE) and environ.get("CLAUDE_CONFIG_DIR") != run.validated_homes[CLAUDE]:
        problems.append("its CLAUDE_CONFIG_DIR is %s, not %s" % (environ.get("CLAUDE_CONFIG_DIR"),
                                                              run.validated_homes[CLAUDE]))
    if cargo_dir is not None and cargo_dir not in environ.get("PATH", "").split(os.pathsep):
        problems.append("its PATH lacks %s, where the recipes' cargo is" % cargo_dir)
    if problems:
        process.terminate()
        process.wait(timeout=LOOP_WAIT_SECONDS)
        fail("the loop (pid %d) was stopped: %s" % (process.pid, "; ".join(problems)))
    lines = "CODEX_HOME=%s\n" % environ["CODEX_HOME"]
    if run.uses(CLAUDE):
        lines += "CLAUDE_CONFIG_DIR=%s\n" % environ["CLAUDE_CONFIG_DIR"]
    save(run, "loop-environ.txt", (lines + "PATH=%s\n" % environ.get("PATH", "")).encode("utf-8"))
    return {"state": "started", "pid": process.pid, "interval": run.interval, "log": str(run.log_path),
            "cargo_on_path": cargo_dir}


def up(run, args):
    require_init(run)
    # Before the loop status check, which runs a child: nothing is started or written for a Claude team yet.
    if run.hosts["team"] == CLAUDE:
        refuse("this team command starts claude-code team roles from T2(a) PR 6")
    pid, alive, ours = loop_process(run)
    running, _ = loop_state(run)
    if (alive and ours) or running in ("running", "stale"):
        refuse("a loop for this run is already running (pid %s); run down first" % (pid if alive and ours else "unknown"))
    mailbox = Mailbox(run.mailbox_root)
    roles = plan_roles(run)
    team_path = run.base / "team.json"
    if team_path.is_file() and read_json(team_path) != run.team and any(mailbox.bindings(e) for e, _ in roles):
        refuse("team.json differs from this config's team, and roles already started under it keep their settings; "
               "restore it or hand those roles off")
    write_atomic(team_path, as_json(run.team))
    save(run, "team.json", run.team)
    wanted = {endpoint: expected_profile(run, mailbox, endpoint) for endpoint, _ in roles}
    rows, accepted = [], {}
    for endpoint, request in roles:
        history = mailbox.bindings(endpoint)
        if history:
            if history[-1]["host"] != CODEX:
                refuse("%s is bound to a %s session, not a Codex role the launcher starts" % (endpoint,
                                                                                              history[-1]["host"]))
            session, label = history[-1]["session"], "already_bound"
        else:
            path = request_file(run, "start-%s.json" % endpoint.replace("/", "%2F"), {"endpoint": endpoint, **request})
            code, answer, proc = tool(run, "launcher", "--base", run.base, "start", "--request", path)
            if code != 0 or answer.get("state") != "bound":
                reason = answer.get("error") or proc.stderr.strip()[-400:] or "no error was recorded"
                message = "%s did not start: %s (launcher exit %d, state %s)" % (endpoint, reason, code,
                                                                                  answer.get("state"))
                (refuse if code == REFUSED else fail)(message, record=answer)
            session, label = answer["session"], "bound"
        checked_role = check_role(run, endpoint, session, wanted[endpoint], args.accept_agent_tools)
        if checked_role["agent_tools"]:
            accepted[endpoint] = checked_role["agent_tools"]
        rows.append({"endpoint": endpoint, "state": label, "session": session, **checked_role})
    if accepted:
        save(run, "up-agent-tools-accepted.json", {"at": timestamp(), "roles": accepted,
                                                   "note": "accepted by the owner with --accept-agent-tools"})
    save(run, "up-roles.json", rows)
    save(run, "launcher-status-start.json", checked(run, "launcher status", "launcher", "--base", run.base, "status"))
    loop = {"state": "not_started", "reason": "--no-loop"} if args.no_loop else start_loop(run)
    raised = {"at": timestamp(), "roles": [row["endpoint"] for row in rows], "loop": loop}
    def record(current):
        require_init(run, state=current)
        current["up"] = raised
    update_state(run, record)
    note = None
    if "router" in run.roles:
        profile = hierarchy_roles.role(run.endpoint("router"))["model_profile"]
        note = ROUTER_NOTE % (profile["effort"], profile["tier"])
    return OK, {"roles": rows, "router": note, "loop": loop, "team_json": str(team_path)}


# -- request, approve, turn -------------------------------------------------------------------------------------------------

def request(run, args):
    require_init(run)
    value = read_json(absolute(args.file, "--file"))
    require(isinstance(value, dict), "the request file must hold a JSON object")
    draft = "raw" in value
    if draft:
        require(value.get("schema") == hierarchy_team_view.DRAFT and isinstance(value.get("raw"), str) and
                isinstance(value.get("sha256"), str), "a draft must be an aegis.team-request/v1 object from team_request")
        require(hashlib.sha256(value["raw"].encode("utf-8")).hexdigest() == value["sha256"],
                "the draft's sha256 does not match its raw text")
        event = value.get("event")
        require(isinstance(event, dict) and isinstance(event.get("event"), dict) and
                event["event"].get("request") == {"raw": value["raw"], "sha256": value["sha256"]},
                "the draft's publish event does not carry its raw text and sha256")
        body = strict_json(value["raw"])
    else:
        body = value
    require(isinstance(body, dict), "a request must be a JSON object")
    body = dict(body)
    if "schema" in body:
        require(body.pop("schema") == hierarchy_lifecycle.REQUEST, "unsupported request schema")
    require(body.get("id") == args.id, "the request file names %s, not %s" % (body.get("id"), args.id))
    canonical = hierarchy_team_view.draft_request(hierarchy_lifecycle.Lifecycle(run.lifecycle), body)
    if draft:
        require(canonical["raw"] == value["raw"], "the draft is not canonical: draft it again with team_request")
        require(canonical["event"] == value["event"], "the draft's publish event no longer matches the journal (its "
                "coordinator or ROOT custody changed): draft it again")
    write_atomic(run.run / "requests" / (args.id + ".json"), canonical["raw"].encode("utf-8"))
    event_path = run.run / "events" / ("publish-%s.json" % args.id)
    write_atomic(event_path, as_json(canonical["event"]))
    code, answer, _ = tool(run, "lifecycle", "--root", run.lifecycle, "record", "--event", event_path, "--evidence-only")
    if code != 0:
        (refuse if code == REFUSED else fail)(answer.get("error", "lifecycle record exited %d" % code))
    save(run, "request-%s.json" % args.id, {"request_id": args.id, "sha256": canonical["sha256"], "receipt": answer})
    return OK, {"request_id": args.id, "sha256": canonical["sha256"], "published": True, "event": str(event_path)}


def agent_items(stdout):
    """What a codex --json turn did, as role_turn.py showed it: its messages and tool calls."""
    items = []
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        item = event.get("item") if isinstance(event, dict) and event.get("type") == "item.completed" else None
        if not isinstance(item, dict):
            continue
        if item.get("type") == "agent_message":
            items.append({"type": "agent_message", "text": str(item.get("text"))[:2000]})
        elif item.get("type") == "mcp_tool_call":
            items.append({"type": "mcp_tool_call", "tool": item.get("tool"), "arguments": item.get("arguments")})
    return items


@contextmanager
def operation_lock(run, busy_message="another team command is running for this run"):
    """Serialize binding, owner turns and teardown without creating a lock file on a refusal.

    Lock the stable run directory inode: team-state.json is replaced atomically, so locking that file would allow
    a second writer to lock its replacement. Browser login holds only its login lock; state transactions stay short.
    """
    import fcntl
    descriptor = os.open(str(run.run), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            refuse(busy_message, record_command=False)
        run.owner_operation_locked = True
        yield
    finally:
        run.owner_operation_locked = False
        os.close(descriptor)


def turn_deadline():
    timeout = float(os.environ.get(TURN_TIMEOUT_VARIABLE, str(TURN_TIMEOUT_SECONDS)))
    require(0 < timeout <= TURN_TIMEOUT_SECONDS,
            TURN_TIMEOUT_VARIABLE + " must be greater than 0 and at most %d seconds" % TURN_TIMEOUT_SECONDS)
    return timeout


def require_resolved(run, endpoint, *, state=None):
    operation = require_init(run, state=state).get("operations", {}).get(endpoint)
    if operation:
        refuse("%s has unresolved operation %s; inspect status, then use approve/turn --reconcile; never replay an "
               "unknown turn" % (endpoint, operation["id"]), operation=operation)


def process_identity(pid):
    try:
        return Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


OPERATION_SCOPE_REASONS = frozenset(component + " is " + problem
    for component in ("observer_pid", "boot_id", "pid_namespace", "proc_identity")
    for problem in ("unreadable", "invalid"))


def operation_process_scope():
    """Capture once before Popen, including unavailable evidence. Scope is not a native-wait prerequisite."""
    values = {}
    for name, read in (
            ("observer_pid", lambda: Path("/proc/self/stat").read_text(encoding="ascii").split(" ", 1)[0]),
            ("boot_id", lambda: Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()),
            ("pid_namespace", lambda: os.readlink("/proc/self/ns/pid")),
            ("proc_identity", lambda: Path("/proc").stat())):
        try:
            values[name] = read()
        except (OSError, ValueError, UnicodeError):
            return {"state": "UNAVAILABLE", "reason": name + " is unreadable"}
    if values["observer_pid"] != str(os.getpid()):
        return {"state": "UNAVAILABLE", "reason": "observer_pid is invalid"}
    boot, namespace, info = values["boot_id"], values["pid_namespace"], values["proc_identity"]
    try:
        valid_boot = str(uuid.UUID(boot)) == boot
    except (ValueError, TypeError, AttributeError):
        valid_boot = False
    if not valid_boot:
        return {"state": "UNAVAILABLE", "reason": "boot_id is invalid"}
    if not isinstance(namespace, str) or re.fullmatch(r"pid:\[\d+\]", namespace) is None:
        return {"state": "UNAVAILABLE", "reason": "pid_namespace is invalid"}
    if not stat.S_ISDIR(info.st_mode):
        return {"state": "UNAVAILABLE", "reason": "proc_identity is invalid"}
    return {"boot_id": boot, "pid_namespace": namespace, "proc_device": info.st_dev, "proc_inode": info.st_ino,
            "effective_uid": os.geteuid()}


def operation_process_observation(operation):
    """Only positive evidence in the original observer scope can establish that the original instance exited.

    Linux stat field 22 is birth time since boot. Require complete current-Linux records (through field 52),
    and two consistent observations. Missing/unreadable/torn identity is unavailable, never absence.
    """
    unavailable = {"state": "UNAVAILABLE"}
    original_scope = operation.get("process_scope")
    if isinstance(original_scope, dict) and original_scope.get("state") == "UNAVAILABLE":
        reason = original_scope.get("reason")
        return {**unavailable, "reason": "original process scope unavailable: " + reason
                if set(original_scope) == {"state", "reason"} and isinstance(reason, str) and
                   reason in OPERATION_SCOPE_REASONS else "original process scope capture is invalid"}
    pid, start = operation.get("pid"), operation.get("pid_start")
    if type(pid) is not int or pid <= 0 or not isinstance(start, str) or not start.isdigit() or int(start) <= 0:
        return {**unavailable, "reason": "original process identity is missing or invalid"}
    try:
        scope = operation_process_scope()
        if scope.get("state") == "UNAVAILABLE":
            return {**unavailable, "reason": "current process scope unavailable: " + scope["reason"]}
        if operation.get("process_scope") != scope:
            return {**unavailable, "reason": "original process scope is missing or changed"}
        observed = []
        for _ in range(2):
            try:
                raw = Path("/proc/%d/stat" % pid).read_text(encoding="ascii")
            except FileNotFoundError:
                try:
                    Path("/proc/%d" % pid).stat()
                except FileNotFoundError:
                    try:
                        os.kill(pid, 0)  # Signal zero is only a kernel existence/permission probe; nothing is sent.
                    except ProcessLookupError:
                        observed.append(("absent", None))
                        continue
                    return {**unavailable, "reason": "the kernel still sees the PID despite missing proc metadata"}
                return {**unavailable, "reason": "stat is missing while the PID directory is present"}
            prefix, separator, tail = raw.rpartition(")")
            fields = tail.split()
            require(separator and prefix.startswith(str(pid) + " (") and raw.endswith("\n") and len(fields) >= 50 and
                    fields[0] in ("R", "S", "D", "Z", "T", "t", "W", "X", "x", "K", "P", "I") and
                    all(re.fullmatch(r"-?\d+", field) is not None for field in fields[1:]) and
                    fields[19].isdigit() and int(fields[19]) > 0, "malformed operation process stat")
            birth = fields[19]
            if birth == start:
                observed.append(("zombie" if fields[0] == "Z" else "present", birth))
            elif int(birth) > int(start):
                observed.append(("later_instance", birth))
            else:
                return {**unavailable, "reason": "process birth precedes the recorded original instance"}
        if operation_process_scope() != scope or observed[0] != observed[1]:
            return {**unavailable, "reason": "process identity or scope changed during observation"}
    except (OSError, ValueError, UnicodeError, IndexError):
        return {**unavailable, "reason": "process metadata is unreadable or malformed"}
    return {"state": "PRESENT" if observed[0][0] == "present" else "CONFIRMED_ABSENT", "reason": observed[0][0]}


def digest_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def durable_write(path, raw):
    """Accounting is a release prerequisite: sync the contents and rename before reporting it durable."""
    path = Path(path)
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    with open(temporary, "xb") as stream:
        os.chmod(temporary, 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    descriptor = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def accounting_lines(raw):
    error = "operation accounting is incomplete or conflicting; retain the hold"
    require(not raw or raw.endswith(b"\n"), error)
    try:
        rows = [strict_json(line) for line in raw.split(b"\n") if line]
    except (ValueError, UnicodeError):
        refuse(error)
    require(all(isinstance(row, dict) for row in rows), error)
    return rows


def record_turn(run, operation, stdout, code):
    """One durable invocation receipt per id, with an idempotent provider log. A null pending usage may become
    known, but a recorded charge cannot be reset or changed. Raw output remains in the invocation's own file.
    """
    error = "operation accounting is incomplete or conflicting; retain the hold"
    log = run.evidence / operation["turn_log"]
    receipt_path = run.evidence / ("turn-%s.accounting.json" % operation["id"])
    require(not log.is_symlink() and not receipt_path.is_symlink(), error)
    before = log.read_bytes() if log.exists() else b""
    rows = accounting_lines(before)
    receipt = read_json(receipt_path) if receipt_path.exists() else None
    require(code is None or type(code) is int, error)
    identity = {"operation_id": operation["id"], "endpoint": operation["endpoint"], "host": operation["host"],
                "session": operation["session"], "generation": operation["generation"],
                "started_at": operation["started_at"], "stdout": operation["stdout"]}
    usage = hierarchy_hosts.claude_usage(stdout) if operation["host"] == CLAUDE else next(
        (event.get("usage") for event in reversed(list(hierarchy_hosts.claude_events(stdout)))
         if event.get("type") == "turn.completed"), None)
    if receipt is not None:
        require(isinstance(receipt, dict) and set(receipt) == {
                    "operation_id", "identity", "usage", "output_sha256", "output_bytes", "exit_code"} |
                    ({"log_span"} if operation["host"] == CODEX else set()) and
                receipt.get("operation_id") == operation["id"] and receipt.get("identity") == identity and
                type(receipt.get("output_bytes")) is int and 0 <= receipt["output_bytes"] <= len(stdout) and
                digest_bytes(stdout[:receipt["output_bytes"]]) == receipt["output_sha256"] and
                (receipt.get("exit_code") is None or (type(receipt["exit_code"]) is int and
                 (code is None or receipt["exit_code"] == code))) and
                (receipt.get("usage") is None or receipt["usage"] == usage), error)
        if code is None:
            code = receipt["exit_code"]
    desired = {"operation_id": operation["id"], "identity": identity, "usage": usage,
               "output_sha256": digest_bytes(stdout), "output_bytes": len(stdout), "exit_code": code}
    if operation["host"] == CLAUDE:
        row = {key: identity[key] for key in ("operation_id", "endpoint", "host", "session", "started_at", "stdout")}
        row.update(exit_code=code, usage=usage)
        keys = set(row)
        require(all(set(item) == keys and isinstance(item["operation_id"], str) for item in rows), error)
        matches = [i for i, item in enumerate(rows) if item["operation_id"] == operation["id"]]
        require(len(matches) <= 1, error)
        if matches:
            old = rows[matches[0]]
            require(all(old[key] == value for key, value in row.items() if key not in ("exit_code", "usage")) and
                    (old["usage"] is None or old["usage"] == usage) and
                    (old["exit_code"] is None or (type(old["exit_code"]) is int and
                     (code is None or old["exit_code"] == code))), error)
            # A row may have been durably published before its receipt reply was lost. Keep a known native
            # status immutable; neither an unknown caller exit nor a transcript verdict can replace it.
            if code is None:
                code = old["exit_code"]
                row["exit_code"] = desired["exit_code"] = code
            rows[matches[0]] = row
        else:
            require(receipt is None, error)
            rows.append(row)
        raw = b"".join(as_json_line(item) for item in rows)
        if raw != before:
            durable_write(log, raw)
    else:
        # Keep the historical Codex event bytes. Persist an append intent first, then recognize its exact bytes
        # after a lost reply. A partial/conflicting append is never guessed at or appended a second time.
        span = receipt.get("log_span") if receipt else None
        if span is None:
            raw = stdout if not stdout or stdout.endswith(b"\n") else b""
            span = {"offset": len(before), "prefix_sha256": digest_bytes(before),
                    "length": len(raw), "sha256": digest_bytes(raw)}
            desired["log_span"] = span
            durable_write(receipt_path, as_json(desired))
        else:
            raw = stdout[:span["length"]]
            require(len(raw) == span["length"] and digest_bytes(raw) == span["sha256"], error)
        offset = span["offset"]
        require(len(before) >= offset and digest_bytes(before[:offset]) == span["prefix_sha256"], error)
        end = offset + span["length"]
        if len(before) == offset:
            if raw:
                durable_write(log, before + raw)
        else:
            require(len(before) >= end and before[offset:end] == raw, error)
        desired["log_span"] = span
    if receipt != desired:
        durable_write(receipt_path, as_json(desired))
    return code


def record_unresolved_turn(run, operation):
    try:
        record_turn(run, operation, Path(operation["stdout"]).read_bytes(), None)
    except (Stop, ValueError, OSError) as exc:
        fail("operation %s is unresolved and accounting failed: %s; team-state, marker and output retained" %
             (operation["id"], exc), operation=operation)


def marker_witness(path):
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600, "unsafe owner wake marker")
        raw = stream.read()
    return {"device": info.st_dev, "inode": info.st_ino, "ctime_ns": info.st_ctime_ns,
            "sha256": digest_bytes(raw), "operation_id": json.loads(raw)["operation_id"]}


def require_owned_marker(operation):
    path = Path(operation["marker"])
    error = "operation %s wake marker changed; retain the hold and do not clear another wake" % operation["id"]
    if not path.exists() and operation.get("release"):
        return False  # A durable release intent follows terminal proof and durable accounting, never a model retry.
    try:
        observed = marker_witness(path)
    except (OSError, ValueError, KeyError, Stop):
        refuse(error)
    require(observed == operation.get("marker_witness") and observed["operation_id"] == operation["id"], error)
    return True


def transcript_witness(path):
    descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "unsafe operation transcript")
        raw = stream.read()
    require(not raw or raw.endswith(b"\n"), "operation transcript has an incomplete boundary; retain the hold")
    return {"device": info.st_dev, "inode": info.st_ino, "offset": len(raw), "prefix_sha256": digest_bytes(raw)}


def message_text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list) and all(isinstance(item, dict) and item.get("type") in ("text", "input_text") and
                                         isinstance(item.get("text"), str) for item in content):
        return "".join(item["text"] for item in content)
    return None


def terminal_proof(run, operation, stdout):
    """Continuity hashes detect file changes; they do not authenticate provider outcomes. Require the submitted
    user text and the invocation's stream message/turn evidence too. Unsupported or ambiguous layouts stay unknown.
    """
    error = "operation %s transcript cannot prove this session's submitted turn; retain the hold and do not replay" % operation["id"]
    stream = list(hierarchy_hosts.claude_events(stdout))
    answers = [event for event in stream if event.get("type") == "assistant" and
               event.get("session_id") == operation["session"] and isinstance(event.get("message"), dict)]
    proofs = []
    for filename, witness in operation["transcripts"].items():
        path = Path(filename)
        home = run.validated_homes[CLAUDE] if operation["host"] == CLAUDE else run.codex_home
        require(path in hierarchy_hosts.transcripts(operation["host"], home, operation["session"]), error)
        descriptor = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as transcript:
            info = os.fstat(transcript.fileno())
            raw = transcript.read()
        offset = witness["offset"]
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                (info.st_dev, info.st_ino) == (witness["device"], witness["inode"]) and len(raw) >= offset and
                digest_bytes(raw[:offset]) == witness["prefix_sha256"] and (not raw or raw.endswith(b"\n")), error)
        try:
            events = [strict_json(line) for line in raw[offset:].split(b"\n") if line]
        except (ValueError, UnicodeError):
            refuse(error)
        require(all(isinstance(event, dict) for event in events), error)
        if not events:
            continue
        if operation["host"] == CLAUDE:
            relevant = [event for event in events if event.get("type") in ("user", "assistant", "system")]
            require(all(event.get("sessionId") == operation["session"] for event in relevant), error)
            users = [event for event in relevant if event.get("type") == "user"]
            require(len(users) == 1 and relevant[0] == users[0] and isinstance(users[0].get("uuid"), str), error)
            prompt = message_text(users[0].get("message", {}).get("content"))
            require(prompt is not None and digest_bytes(prompt.encode("utf-8")) == operation["prompt_sha256"], error)
            terminals = [event for event in relevant if event.get("type") == "assistant" and
                         isinstance(event.get("message"), dict) and
                         event["message"].get("stop_reason") in ("end_turn", "max_tokens", "stop_sequence")]
            # These fixture-era rows are not a supported native Claude terminal shape. Neither their presence
            # nor a session-only error result proves that this invocation's submitted turn ended.
            require(not any(event.get("type") == "system" and event.get("subtype") in ("turn_failed", "turn_aborted")
                            for event in relevant), error)
            if terminals:
                require(len(terminals) == 1 and relevant[-1] == terminals[0], error)
                message_id = terminals[0]["message"].get("id")
                require(isinstance(message_id, str) and any(event["message"].get("id") == message_id for event in answers), error)
                proofs.append(False)
        else:
            prefix = list(hierarchy_hosts.claude_events(raw[:offset]))
            metadata = [event["payload"] for event in prefix if event.get("type") == "session_meta"]
            require(len(metadata) == 1 and metadata[0].get("id") == operation["session"], error)
            users = [event.get("payload") for event in events if event.get("type") == "response_item" and
                     isinstance(event.get("payload"), dict) and event["payload"].get("role") == "user"]
            require(len(users) == 1, error)
            prompt = message_text(users[0].get("content"))
            require(prompt is not None and digest_bytes(prompt.encode("utf-8")) == operation["prompt_sha256"], error)
            messages = [event["payload"] for event in events if event.get("type") == "event_msg" and
                        isinstance(event.get("payload"), dict)]
            starts = [event for event in messages if event.get("type") == "task_started"]
            require(len(starts) == 1 and isinstance(starts[0].get("turn_id"), str), error)
            turn = starts[0]["turn_id"]
            contexts = [event["payload"] for event in events if event.get("type") == "turn_context"]
            require(len(contexts) == 1 and contexts[0].get("turn_id") == turn and
                    contexts[0].get("cwd") == operation["cwd"], error)
            terminals = [event for event in messages if event.get("type") in ("task_complete", "task_failed", "turn_aborted")]
            if terminals:
                require(len(terminals) == 1 and terminals[0].get("turn_id") == turn, error)
                proofs.append(terminals[0]["type"] != "task_complete")
    require(len(proofs) == 1, "operation %s is unresolved: the transcript has no completed or failed turn; "
            "retain the hold and do not replay" % operation["id"])
    return proofs[0]


def as_json_line(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")


def operation_record(state, operation, *, pending_pid=False):
    operations = state.get("operations")
    recorded = operations.get(operation["endpoint"]) if isinstance(operations, dict) else None
    expected = dict(operation)
    if pending_pid:
        # Only the PID transaction may replace the unpublished PID fields after Popen returns.
        expected["pid"] = None
        expected.pop("pid_start", None)
    if recorded != expected:
        fail("operation %s on %s is no longer current; team-state, output and wake marker were retained" %
             (operation["id"], operation["endpoint"]), operation=operation)
    return recorded


def finish_operation(run, operation, stdout, code):
    from hierarchy_mailbox import writer_lock
    # Lock order: owner directory -> mailbox -> short Claude state transaction. Never acquire a mailbox lock
    # from a state callback, or keep a state lock over provider/accounting I/O or any child wait.
    with writer_lock(run.mailbox_root):
        operation_record(require_init(run), operation)
        if operation.get("release"):
            require(sha_file(run.evidence / ("turn-%s.accounting.json" % operation["id"])) ==
                    operation["release"]["accounting_sha256"],
                    "operation accounting changed after release intent; retain the hold")
        remove = require_owned_marker(operation) if operation.get("marker") else False
        code = record_turn(run, operation, stdout, code)
        index(run, Path(operation["stdout"]).name, Path(operation["stderr"]).name,
              "turn-%s.accounting.json" % operation["id"], operation["turn_log"])
        releasing = dict(operation)
        releasing["release"] = {"accounting_sha256": sha_file(run.evidence / ("turn-%s.accounting.json" % operation["id"]))}
        def release(current):
            require_init(run, state=current)
            operation_record(current, operation)
            current["operations"][operation["endpoint"]] = releasing
        update_state(run, release)
        if remove:
            Path(operation["marker"]).unlink()
        def finish(current):
            require_init(run, state=current)
            operation_record(current, releasing)
            current["operations"].pop(operation["endpoint"])
        update_state(run, finish)
    return code


def model_turn(run, endpoint, binding, argv, cwd, prompt, timeout, marker=None, approval=None,
               operation_id=None, owned_marker=None):
    """Bound the owner's wait, never the host's life. Files survive this command and cannot fill a pipe or SIGPIPE
    the host after a deadline. Persist intent before Popen and the pid immediately afterwards; lost replies hold.
    """
    try:
        env = child_env(run)
        if binding["host"] == CLAUDE:
            claude_pin(run)
        home = run.validated_homes[CLAUDE] if binding["host"] == CLAUDE else run.codex_home
        transcripts = {str(path): transcript_witness(path) for path in
                       hierarchy_hosts.transcripts(binding["host"], home, binding["session"])}
        process_scope = operation_process_scope()
    except (Stop, ValueError):
        if marker:
            from hierarchy_mailbox import writer_lock
            with writer_lock(run.mailbox_root):
                if require_owned_marker({"id": operation_id, "marker": str(marker), "marker_witness": owned_marker}):
                    marker.unlink()
        raise
    identifier = operation_id or uuid.uuid4().hex
    operation = {"id": identifier, "endpoint": endpoint, "host": binding["host"], "session": binding["session"],
                 "generation": binding["generation"], "started_at": timestamp(), "pid": None,
                 "process_scope": process_scope,
                 "stdout": str(run.evidence / ("turn-%s.stdout.jsonl" % identifier)),
                 "stderr": str(run.evidence / ("turn-%s.stderr.txt" % identifier)),
                 "transcripts": transcripts,
                 "prompt_sha256": digest_bytes((prompt if prompt is not None else argv[-1]).encode("utf-8")), "cwd": cwd,
                 "turn_log": "root-turns.jsonl" if endpoint_parts(endpoint)[1] == "root" else
                             "role-turns-%s.jsonl" % endpoint.replace("/", "%2F"),
                 "marker": str(marker) if marker else None, "marker_witness": owned_marker}
    if approval is not None:
        operation["approval"] = approval
    def intend(current):
        require_init(run, state=current)
        require_resolved(run, endpoint, state=current)
        current.setdefault("operations", {})[endpoint] = operation
    try:
        update_state(run, intend)
    except Stop as stop:
        if stop.code == REFUSED and marker:
            from hierarchy_mailbox import writer_lock
            with writer_lock(run.mailbox_root):
                if require_owned_marker(operation):
                    marker.unlink()
        raise
    # Input is a private anonymous file too; writing a long prompt to a pipe could consume the deadline before wait.
    with tempfile.TemporaryFile() as stdin, open(operation["stdout"], "wb") as stdout, open(operation["stderr"], "wb") as stderr:
        if prompt is not None:
            stdin.write(prompt.encode("utf-8"))
            stdin.seek(0)
        try:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=stdin if prompt is not None else subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            operation.update(pid=process.pid, pid_start=process_identity(process.pid))
            def record_pid(current):
                require_init(run, state=current)
                recorded = operation_record(current, operation, pending_pid=True)
                recorded.update(pid=operation["pid"], pid_start=operation["pid_start"])
            update_state(run, record_pid)
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            record_unresolved_turn(run, operation)
            fail("operation %s on %s is unresolved after its deadline; process pid %d was left running, output and "
                 "team-state were retained. Inspect status, then use approve/turn --reconcile; do not replay" %
                 (identifier, endpoint, process.pid), operation=operation)
        except (OSError, subprocess.SubprocessError) as exc:
            record_unresolved_turn(run, operation)
            fail("operation %s is unresolved: %s; team-state and output retained; inspect before reconciliation" %
                 (identifier, exc), operation=operation)
    raw, errors = Path(operation["stdout"]).read_bytes(), Path(operation["stderr"]).read_bytes()
    try:
        finish_operation(run, operation, raw, process.returncode)
    except (Stop, ValueError, OSError) as exc:
        if isinstance(exc, Stop) and exc.code == FAILED:
            raise
        fail("operation %s finished but custody release failed: %s; state, marker and output retained" %
             (identifier, exc), operation=operation)
    return subprocess.CompletedProcess(argv, process.returncode, raw, errors)


def reconcile(run, endpoint):
    state = require_init(run)
    operation = state.get("operations", {}).get(endpoint)
    require(operation is not None, "%s has no unresolved operation" % endpoint)
    observation = operation_process_observation(operation)
    require(observation["state"] != "PRESENT", "operation %s is unresolved: its process is still running" % operation["id"])
    if observation["state"] != "CONFIRMED_ABSENT":
        refuse("operation %s is unresolved: its process exit cannot be confirmed; retain the hold" % operation["id"],
               operation=operation, process_observation=observation)
    stdout = Path(operation["stdout"]).read_bytes()
    failed = terminal_proof(run, operation, stdout)
    events = hierarchy_hosts.claude_events(stdout)
    failed |= any(event.get("type") == "result" and event.get("is_error") is True for event in events)
    approval = operation.get("approval")
    if approval:
        _policy, journal = hierarchy_router.locked_load(hierarchy_lifecycle.Lifecycle(run.lifecycle), 5.0)
        previous = approval["previous"]
        added = journal["decisions"][len(previous):]
        failed |= journal["decisions"][:len(previous)] != previous or len(added) != 1 or any(
            entry["request_id"] != approval["request_id"] or entry["decision"] != approval["decision"] or
            entry["request_sha256"] != approval["request_sha256"] for entry in added)
    receipt_path = run.evidence / ("turn-%s.accounting.json" % operation["id"])
    receipt = read_json(receipt_path) if receipt_path.exists() else {}
    require(isinstance(receipt, dict) and (receipt.get("exit_code") is None or type(receipt["exit_code"]) is int),
            "operation accounting has an invalid exit code; retain the hold")
    native_exit = receipt.get("exit_code")
    failed |= native_exit is not None and native_exit != 0
    # A known native exit (for example 1) is immutable even though reconciliation's public failure exit is 3.
    native_exit = finish_operation(run, operation, stdout, native_exit)
    failed |= native_exit is not None and native_exit != 0
    return (FAILED if failed else OK), {"endpoint": endpoint, "reconciled": operation["id"],
                                       "outcome": "failed" if failed else "completed", "replayed": False}


def approve(run, args):
    state = require_init(run)
    bound = state.get("root")
    if not bound:
        refuse("ROOT is not bound; run root --session <id> first")
    endpoint = run.endpoint("root")
    binding = Mailbox(run.mailbox_root).current_binding(endpoint)
    planned_binding(run, endpoint, binding["host"])
    require(binding["host"] == run.hosts["root"], "ROOT's host differs from team-run.json")
    require(all(bound[key] == binding[key] for key in ("session", "generation")), "ROOT's recorded binding changed")
    if args.reconcile:
        return reconcile(run, endpoint)
    require_resolved(run, endpoint)
    timeout = turn_deadline()
    if binding["host"] == CLAUDE:
        claude_pin(run)
        claude_transcript(run, binding["session"])
        require(tuple(bound["tools"]) == ROOT_TOOLS, "ROOT tools mismatch")
        claude_connection(run, binding, bound["connection"])
        require(tuple(adapter_tools(run, bound["connection"])) == ROOT_TOOLS, "ROOT tools mismatch")
    reason = args.reason
    text(reason, "reason", 512)
    require(not set('"\r\n') & set(reason), "the reason may not contain double quotes or line breaks")
    decision = "deny" if args.deny else "approve"
    lifecycle = hierarchy_lifecycle.Lifecycle(run.lifecycle)
    _policy, before = hierarchy_router.locked_load(lifecycle, 5.0)
    row = next((row for row in hierarchy_team_view.pending(lifecycle)["pending"] if row["request_id"] == args.id), None)
    if row is None:
        rows = {r["request_id"]: r for r in hierarchy_team_view.status(lifecycle)["requests"]}
        existing = rows.get(args.id)
        latest = next((r for r in reversed(before["decisions"]) if r["request_id"] == args.id), None)
        if args.deny and existing and latest and latest["decision"] == "approve":
            row = existing
        else:
            refuse("request %s is not pending a ROOT decision (journal state: %s)" % (
                args.id, existing["state"] if existing else "not published"))
    argv = ["codex"]
    # ROOT reads and decides only: no shell, as provision gives any reader without reader_shell.
    for feature in hierarchy_provision.CODEX_DISABLED + hierarchy_provision.CODEX_SHELL:
        argv += ["--disable", feature]
    argv += ["exec", "--ignore-user-config", "--sandbox", "read-only", "-c", 'approval_policy="never"',
             "-c", bound["mcp_config"], "--json", "-C", str(run.project), "resume", bound["session"],
             (ROOT_PROMPT if not args.deny else ROOT_PROMPT.replace("Call team_pending", "Call team_status"))
             % (args.id, decision, reason)]
    prompt = None
    if binding["host"] == CLAUDE:
        prompt = argv[-1]
        argv = hierarchy_provision.claude_argv(["--resume", binding["session"]], bound["connection"], [],
                                              ["mcp__aegis_decision__" + name for name in ROOT_TOOLS], {}, None)
    proc = model_turn(run, endpoint, binding, argv, str(run.project), prompt, timeout,
                      approval={"request_id": args.id, "decision": decision, "request_sha256": row["request_sha256"],
                                "previous": before["decisions"]})
    stdout = proc.stdout.decode("utf-8", "replace")
    items = hierarchy_hosts.claude_turn_items(stdout) if binding["host"] == CLAUDE else agent_items(stdout)
    messages = [item["text"] for item in items if item["type"] == "agent_message"]
    last = messages[-1] if messages else None
    _policy, journal = hierarchy_router.locked_load(lifecycle, 5.0)
    previous = before["decisions"]
    added = journal["decisions"][len(previous):]
    if journal["decisions"][:len(previous)] != previous or any(
            entry["request_id"] != args.id or entry["decision"] != decision or
            entry["request_sha256"] != row["request_sha256"] for entry in added) or len(added) > 1:
        fail("ROOT recorded unexpected journal decisions; inspect retained journal before continuing",
             decisions=added, codex_exit=proc.returncode)
    recorded = [entry for entry in journal["decisions"] if entry["request_id"] == args.id]
    if not (recorded and recorded[-1]["decision"] == decision and
            recorded[-1]["request_sha256"] == row["request_sha256"]):
        fail("ROOT did not record %s on %s (sha256 %s); its last message: %s" % (decision, args.id,
                                                                                 row["request_sha256"], last),
             root_last_message=last, codex_exit=proc.returncode,
             stderr=proc.stderr.decode("utf-8", "replace")[-800:])
    if binding["host"] == CLAUDE and (proc.returncode != 0 or any(
            event.get("type") == "result" and event.get("is_error") is True
            for event in hierarchy_hosts.claude_events(stdout))):
        fail("Claude ROOT turn failed; journal decisions, transcript and output were retained", claude_exit=proc.returncode)
    return OK, {"request_id": args.id, "decision": decision, "request_sha256": row["request_sha256"],
                "event_id": row["root_decide"]["event_id_" + decision], "root_last_message": last}


def turn(run, args):
    require_init(run)
    endpoint = args.endpoint
    mailbox = Mailbox(run.mailbox_root)
    mailbox.endpoint(endpoint)
    if endpoint_parts(endpoint)[1] == "root":
        refuse("ROOT's turns go through approve")
    history = mailbox.bindings(endpoint)
    if not history:
        refuse("%s is not bound; start it with up first" % endpoint)
    binding = history[-1]
    planned_binding(run, endpoint, binding["host"])
    if args.reconcile:
        require(args.prompt is None, "--reconcile does not accept a prompt")
        return reconcile(run, endpoint)
    require_resolved(run, endpoint)
    timeout = turn_deadline()
    require(isinstance(args.prompt, str) and bool(args.prompt.strip()) and "\0" not in args.prompt, "invalid prompt")
    quoted = endpoint.replace("/", "%2F")
    generation = history[-1]["generation"]
    profile_path = run.base / "profiles" / ("%s-g%d.wake.json" % (quoted, generation))
    if not profile_path.is_file():
        refuse("%s has no wake profile for generation %d: %s" % (endpoint, generation, profile_path))
    marker = mailbox.wake_marker(endpoint)
    if marker.exists():
        refuse("a wake is running for %s (%s); try again after it ends" % (endpoint, marker))
    setup = read_json(run.base / "provision.json")
    unread = mailbox.delivery(setup["delivery_dir"], endpoint)["endpoints"][endpoint]["unread_count"]
    if unread:
        refuse("%s has %d unread message%s; the loop's wake reads %s, so an owner turn now would race it"
               % (endpoint, unread, "" if unread == 1 else "s", "it" if unread == 1 else "them"))
    profile = read_json(profile_path)
    require(all(profile[key] == binding[key] for key in ("host", "session", "generation")),
            "binding changed before owner turn; the outgoing session was not started")
    if binding["host"] == CLAUDE:
        from hierarchy_wake import load_profile
        profile = load_profile(profile_path, endpoint, binding)
        claude_pin(run)
        claude_transcript(run, binding["session"])
        require(profile.get("mode", "print") == "print" and profile["prompt_via"] == "stdin",
                "a Claude owner turn requires a print profile")
        claude_resume_profile(run, binding, profile)
    by_argv = profile["prompt_via"] == "argv"
    argv = profile["argv"] + ([args.prompt] if by_argv else [])
    from hierarchy_mailbox import writer_lock
    from hierarchy_wake import claim_wake
    identifier = uuid.uuid4().hex
    with writer_lock(mailbox.root):
        current = Mailbox(mailbox.root).current_binding(endpoint)
        require(all(profile[key] == current[key] for key in ("host", "session", "generation")),
                "binding changed before owner turn; the outgoing session was not started")
        marker = claim_wake(mailbox, endpoint)
        value = read_json(marker)
        value["operation_id"] = identifier
        durable_write(marker, as_json(value))
        owned_marker = marker_witness(marker)
    proc = model_turn(run, endpoint, binding, argv, profile["cwd"], None if by_argv else args.prompt, timeout, marker,
                      operation_id=identifier, owned_marker=owned_marker)
    log = run.evidence / ("role-turns-%s.jsonl" % quoted)
    items = hierarchy_hosts.claude_turn_items if binding["host"] == CLAUDE else agent_items
    answer = {"endpoint": endpoint, "exit_code": proc.returncode, "items": items(proc.stdout.decode("utf-8", "replace")),
              "log": str(log)}
    if proc.stderr:
        answer["stderr"] = proc.stderr.decode("utf-8", "replace")[-800:]
    if binding["host"] == CLAUDE and (proc.returncode != 0 or any(
            event.get("type") == "result" and event.get("is_error") is True
            for event in hierarchy_hosts.claude_events(proc.stdout))):
        return FAILED, {**answer, "error": "Claude owner turn failed; transcript and output were retained"}
    return (OK if proc.returncode == 0 else FAILED), answer


# -- status ---------------------------------------------------------------------------------------------------------------

def launcher_roles(run):
    if not (run.base / "provision.json").is_file():
        return {}
    _code, answer, _ = tool(run, "launcher", "--base", run.base, "status")
    rows = {}
    for endpoint, row in answer.get("endpoints", {}).items():
        last = row.get("last") or {}
        rows[endpoint] = {"binding": row.get("binding"), "records": row.get("records"),
                          "last": {key: last.get(key) for key in ("action", "state", "at")} if last else None}
    return rows


def status(run, args):
    state = load_state(run)
    complete = init_complete(state)
    pid, alive, ours = loop_process(run)
    running = loop_state(run)[0] if complete else "not_running"
    answer = {"schema": STATUS_SCHEMA, "run": str(run.run), "initiative": run.id,
              "init": {"complete": complete, "next_step": None if complete else next_step(state)},
              "root": (state or {}).get("root"),
              "loop": {"state": running, "pid": pid if alive and ours else None, "pid_alive": bool(alive and ours)},
              "roles": launcher_roles(run) if complete else {}, "team": None, "pending": []}
    if (state or {}).get("operations"):
        answer["unresolved_operations"] = state["operations"]
    if complete:
        lifecycle = hierarchy_lifecycle.Lifecycle(run.lifecycle)
        answer["team"] = hierarchy_team_view.status(lifecycle, loop_state=run.loop_state, evidence=run.evidence)
        answer["pending"] = hierarchy_team_view.pending(lifecycle)["pending"]
    if not args.text:
        return OK, answer
    print(status_text(run, answer), end="")
    return OK, None


def status_text(run, answer):
    lines = ["team %s at %s" % (run.id, run.run)]
    init_state = answer["init"]
    lines.append("init: " + ("complete" if init_state["complete"] else "next step " + str(init_state["next_step"])))
    loop = answer["loop"]
    head = "loop: " + loop["state"]
    if loop["pid"]:
        head += " (pid %d)" % loop["pid"]
    team = answer["team"] or {}
    last = team.get("loop") or {}
    if last.get("pass_id"):
        head += "; pass %s finished %s" % (last["pass_id"], last.get("finished_at"))
        if last.get("current_step"):
            head += ", step %s since %s" % (last["current_step"], last.get("step_started_at"))
    lines.append(head)
    for endpoint, operation in sorted(answer.get("unresolved_operations", {}).items()):
        lines.append("unresolved: %s operation %s pid %s since %s; inspect, then approve/turn --reconcile; do not replay" %
                     (endpoint, operation["id"], operation.get("pid"), operation["started_at"]))
    if answer["roles"]:
        lines.append("roles:")
        for endpoint, row in sorted(answer["roles"].items()):
            binding = row["binding"]
            last_record = row["last"] or {}
            lines.append("  %s: %s, last %s %s at %s" % (
                endpoint, "g%d %s" % (binding["generation"], binding["session"]) if binding else "unbound",
                last_record.get("action"), last_record.get("state"), last_record.get("at")))
    who = {"root": "ROOT must act", "owner": "the owner must act", "router": "the Router's records"}
    for act, rows in sorted((team.get("holds_by_act") or {}).items()):
        if not rows:
            continue
        lines.append("%s (%s):" % (act, who.get(act, act)))
        for row in rows:
            subject = row.get("endpoint") or row.get("request_id") or row.get("job") or ""
            lines.append("  %s %s %s: %s (seen %s times since %s)" % (row["step"], row["kind"], subject, row["detail"],
                                                                     row.get("count"), row.get("first_seen")))
    if answer["pending"]:
        lines.append("pending ROOT decisions:")
        for row in answer["pending"]:
            lines.append("  %s (%s): hierarchy_team.py --config %s approve %s --reason TEXT" % (
                row["request_id"], row["why"], run.config_path, row["request_id"]))
    else:
        lines.append("pending ROOT decisions: none")
    return "\n".join(lines) + "\n"


# -- down -----------------------------------------------------------------------------------------------------------------

def stop_loop(run, wait):
    pid, alive, ours = loop_process(run)
    if pid is None or not alive:
        return {"state": "already_stopped"}
    if not ours:
        return {"state": "already_stopped", "note": "pid %d is not this run's loop" % pid}
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if not process_alive(pid):
            return {"state": "stopped", "pid": pid}
        time.sleep(0.1)
    if not process_alive(pid):
        return {"state": "stopped", "pid": pid}
    fail("the loop (pid %d) did not stop within %d s after SIGTERM; a step may still be running. Run down again once "
         "it has stopped" % (pid, wait))


def stop_roles(run):
    started = launcher_roles(run)
    order = [endpoint for endpoint, _ in plan_roles(run)] if run.lifecycle.is_dir() else []
    names = [e for e in order if e in started] + sorted(e for e in started if e not in order)
    rows = []
    for endpoint in names:
        binding = started[endpoint]["binding"]
        # ROOT is the owner's session and the launcher never stops it; a refused ROOT start still leaves a record.
        if not binding or binding["host"] not in (CODEX, CLAUDE) or endpoint_parts(endpoint)[1] == "root":
            continue
        code, answer, _ = tool(run, "launcher", "--base", run.base, "stop", "--endpoint", endpoint)
        rows.append({"endpoint": endpoint, "state": answer.get("state"), "pids": answer.get("pids", [])})
        if "unowned_pids" in answer:
            rows[-1]["unowned_pids"] = answer["unowned_pids"]
            if not isinstance(answer["unowned_pids"], list) or any(type(pid) is not int or pid <= 0 for pid in answer["unowned_pids"]):
                fail("%s returned invalid unowned_pids; resources were kept" % endpoint, roles=rows)
        if answer.get("unowned_pids"):
            fail("%s has unowned_pids; host ownership is unresolved and resources were kept" % endpoint, roles=rows)
        if code != 0:
            fail("%s could not be stopped: %s" % (endpoint, answer.get("error") or answer.get("state")), roles=rows)
    return rows


def copy_tree(source, target):
    if target.exists():
        shutil.rmtree(target)
    if source.is_dir():
        shutil.copytree(source, target, symlinks=True)
    else:
        target.mkdir(parents=True, mode=0o700)


def rollout_turns(path):
    """One rollout's turns, ported from the cost ADR's ledger (evidence/43-e2e-turn-ledger.py): each turn's token
    spend is the delta of Codex's cumulative token_count, and its publishes are the message ids passed to
    mailbox_publish, refused attempts included, so a repeated id is a retry."""
    keys = ("input_tokens", "cached_input_tokens", "output_tokens")
    rows, current, totals, named, session = [], None, dict.fromkeys(keys, 0), None, None
    with open(path, encoding="utf-8", errors="replace") as stream:
        for line in stream:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if not isinstance(event, dict):
                continue
            payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
            kind = event.get("type")
            if kind == "session_meta" and session is None:
                session = payload.get("id")
            elif kind == "turn_context":
                if current:
                    rows.append(current)
                current = {"start": dict(totals), "end": dict(totals), "prompt": None, "publishes": []}
            elif kind == "event_msg" and payload.get("type") == "token_count" and isinstance(payload.get("info"), dict):
                usage = payload["info"].get("total_token_usage") or {}
                totals = {key: usage.get(key, 0) for key in keys}
                if current:
                    current["end"] = dict(totals)
            elif kind == "response_item" and payload.get("type") == "message" and payload.get("role") == "user":
                said = " ".join(c.get("text", "") for c in payload.get("content", []) if isinstance(c, dict))
                if "started this session for " in said:
                    named = said.split("started this session for ", 1)[1].split(" ", 1)[0].rstrip(".")
                elif said.startswith("You are ROOT"):
                    named = "ROOT"
                if current and current["prompt"] is None and not said.startswith(("<", "#")):
                    current["prompt"] = said[:48]
            elif current and kind == "response_item" and payload.get("type") in (
                    "function_call", "custom_tool_call", "mcp_tool_call") and "mailbox_publish" in json.dumps(payload):
                current["publishes"].extend(PUBLISH_ID.findall(json.dumps(payload)) or ["<unparsed>"])
    if current:
        rows.append(current)
    turns = []
    for number, row in enumerate(rows, 1):
        spent = {key: row["end"][key] - row["start"][key] for key in keys}
        retried = sorted({name for name in row["publishes"] if row["publishes"].count(name) > 1})
        turns.append({"turn": number, **spent, "prompt": row["prompt"], "publishes": row["publishes"],
                      "retried": retried})
    return session, named, turns, totals


def turn_ledger(run, state, sessions):
    names = {}
    base_launches = run.base / "launches"
    for record in sorted(base_launches.glob("*/*.json")) if base_launches.is_dir() else []:
        try:
            value = read_json(record)
        except (OSError, ValueError):
            continue
        if value.get("session"):
            names[value["session"]] = value.get("endpoint")
    if (state or {}).get("root"):
        names[state["root"]["session"]] = run.endpoint("root")
    roles, total = [], {"turns": 0, "input_tokens": 0, "cached_input_tokens": 0, "output_tokens": 0}
    for path in sorted(sessions.rglob("*.jsonl")) if sessions.is_dir() else []:
        session, named, turns, totals = rollout_turns(path)
        roles.append({"endpoint": names.get(session) or named or path.name, "session": session,
                      "rollout": str(path.relative_to(run.evidence)), "turns": turns, "totals": totals})
        total["turns"] += len(turns)
        for key in totals:
            total[key] += totals[key]
    total["all_tokens"] = total["input_tokens"] + total["output_tokens"]
    by_command = {}
    if run.commands_log.is_file():
        for line in run.commands_log.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if row.get("exit") == OK:
                by_command[row["command"]] = by_command.get(row["command"], 0) + 1
    return {"schema": LEDGER_SCHEMA, "at": timestamp(), "roles": roles, "total": total,
            "owner_actions": {"by_command": by_command,
                              "model_turn_commands": by_command.get("approve", 0) + by_command.get("turn", 0)}}


def write_sums(run):
    lines = []
    for path in sorted(run.evidence.rglob("*")):
        if path.is_file() and not path.is_symlink() and path != run.evidence / "SHA256SUMS":
            lines.append("%s  %s\n" % (sha_file(path), path.relative_to(run.evidence)))
    write_atomic(run.evidence / "SHA256SUMS", "".join(lines).encode("utf-8"))
    return len(lines)


def collect(run, state):
    """Step 17 of the guide: the run's records copied into evidence, the turn ledger, then SHA256SUMS."""
    run.evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
    if run.lifecycle.is_dir():
        save(run, "checkpoint-after.json", checked(run, "lifecycle checkpoint", "lifecycle", "--root", run.lifecycle,
                                                   "checkpoint"))
    if (run.base / "provision.json").is_file():
        save(run, "launcher-status-end.json", checked(run, "launcher status", "launcher", "--base", run.base, "status"))
    if run.lifecycle.is_dir() and run.store.is_dir():
        save(run, "router-end.json", checked(run, "router status", "router", "--lifecycle", run.lifecycle, "--store",
                                             run.store, "status"))
    for source, name in ((run.base / "launches", "launches"), (run.delivery, "delivery"), (run.loop_state, "loop"),
                         (run.run / "requests", "requests"), (run.run / "events", "events"),
                         (run.mailbox_root, "mailbox"), (run.store / "events", "store-events"),
                         (run.store / "jobs" / run.id, "jobs"), (run.codex_home / "sessions", "codex-sessions")):
        # T2(a) PR 6 (down) adds (run.claude_home / "projects", "claude-projects") here for a plan that uses
        # claude-code, and purge_claude then checks each copy as purge does. Nothing else of claude_home is copied:
        # never its credentials.
        copy_tree(source, run.evidence / name)
    for source, name in ((run.run / "policy.json", "policy.json"), (run.recipes, "recipes.json"),
                         (run.pid_path, "loop.pid"), (run.log_path, "loop.log"),
                         (run.commands_log, "team-commands.jsonl")):
        if source.is_file():
            shutil.copy2(source, run.evidence / name)
    ledger = turn_ledger(run, state, run.evidence / "codex-sessions")
    save(run, "turn-ledger.json", ledger)
    return {"files": write_sums(run), "turns": ledger["total"]["turns"], "tokens": ledger["total"]["all_tokens"]}


def release_leases(run, state):
    if not any(key.startswith("lease:") for key in state["init"]["done"]):
        return []
    code, listing, proc = aegis(run, "team", "list", "--workspace", str(run.project), "--json")
    if code != 0:
        fail("aegis team list: %s" % (listing.get("error") or proc.stderr.strip()[-400:]))
    live = {lease["lane"]: lease for lease in listing.get("leases", [])}
    rows = []
    for lane in run.implementers:
        if "lease:" + lane.id not in state["init"]["done"]:
            continue
        lease = live.get(lane.lease)
        if lease is None:
            if not (run.evidence / ("lease-release-%s.json" % lane.id)).is_file():
                save(run, "lease-absent-%s.json" % lane.id, listing)
            rows.append({"lane": lane.lease, "state": "already_released"})
            continue
        claimed = read_json(run.evidence / ("lease-claim-%s.json" % lane.id)).get("lease")
        identity = ("lane", "claim_id", "owner", "role", "branch", "paths")
        if not isinstance(claimed, dict) or any(lease.get(key) != claimed.get(key) for key in identity):
            fail("lease ownership changed for %s; resources were kept for inspection" % lane.lease)
        # The oid is read now: a renewal since the claim changed it, and the real run failed on a pasted placeholder.
        code, answer, proc = aegis(run, "team", "release", lane.lease, "--workspace", str(run.project), "--expect",
                                   lease["oid"], "--json")
        if code != 0:
            fail("aegis team release %s: %s" % (lane.lease, answer.get("error") or answer.get("message") or
                                                proc.stderr.strip()[-400:]), result=answer)
        save(run, "lease-release-%s.json" % lane.id, answer)
        rows.append({"lane": lane.lease, "state": "released", "oid": lease["oid"]})
    return rows


def release_slots(run, state):
    rows = []
    asked = {lane.id: state["init"]["done"].get("slot-request:" + lane.id) for lane in run.implementers}
    if not any(asked.values()):
        return rows
    held = {row["request_id"] for row in checked(run, "workspace status", "workspace", "--store", run.store,
                                                 "status")["capacity"]["writer"]["holders"]}
    for lane in run.implementers:
        if not asked[lane.id]:
            continue
        request_id = asked[lane.id]["request_id"]
        if request_id not in held:
            rows.append({"lane": lane.id, "state": "already_released"})
            continue
        proof = next((run.evidence / name for name in ("lease-release-%s.json" % lane.id, "lease-absent-%s.json" % lane.id)
                      if (run.evidence / name).is_file()), None)
        if proof is None:
            fail("the writer slot of %s is kept: its lease release has no evidence" % lane.id)
        answer = checked(run, "slot release for " + lane.id, "workspace", "--store", run.store, "release", "--request",
                         request_file(run, "slot-release-%s.json" % lane.id, {
                             "request_id": request_id, "evidence": {"path": str(proof), "sha256": sha_file(proof)}}))
        save(run, "slot-release-%s.json" % lane.id, answer)
        rows.append({"lane": lane.id, "state": "released"})
    return rows


def remove_worktrees(run, state):
    rows = []
    for lane in run.implementers:
        if "worktree:" + lane.id not in state["init"]["done"]:
            continue
        worktree = Path(state["init"]["done"]["worktree:" + lane.id]["path"])
        if not worktree.exists():
            rows.append({"lane": lane.id, "state": "already_removed", "path": str(worktree)})
            continue
        # Only this run's worktree, by path; never prune or repair, which touch every worktree of the clone.
        removed = git(run.project, "worktree", "remove", str(worktree), ok=True)
        if removed.returncode != 0:
            fail("git worktree remove refused %s: %s; clean it by hand, never with prune or repair"
                 % (worktree, removed.stderr.strip()[-400:]))
        rows.append({"lane": lane.id, "state": "removed", "path": str(worktree)})
    return rows


def remove_review_copies(run):
    rows = []
    for path in sorted(run.run.glob("review-*")) if run.run.is_dir() else []:
        if not path.is_dir() or path.is_symlink():
            continue
        if not (path / "manifest.json").is_file():
            rows.append({"path": str(path), "state": "kept: no review manifest"})
            continue
        answer = checked(run, "review remove " + path.name, "review", "remove", "--out", path)
        rows.append({"path": answer.get("removed", str(path)), "state": "removed"})
    return rows


def parsed_sums(run):
    path = run.evidence / "SHA256SUMS"
    found = {}
    for line in path.read_text(encoding="utf-8").splitlines() if path.is_file() else []:
        digest, _, name = line.partition("  ")
        found[name] = digest
    return found


def ownership(run, home=None, label="codex_home"):
    mark = (run.codex_home if home is None else home) / OWNER_MARK
    if not mark.is_file() or mark.is_symlink():
        refuse("%s was kept: it has no %s mark, so this run did not make it" % (label, OWNER_MARK))
    record = read_json(mark)
    if not isinstance(record, dict) or record.get("run") != str(run.run) or record.get("initiative") != run.id:
        refuse("%s was kept: ownership record does not match this run" % label)


def check_codex_purge(run):
    safe_codex_home(run)
    if not run.codex_home.exists():
        return False
    ownership(run)
    sessions, copies, sums = run.codex_home / "sessions", run.evidence / "codex-sessions", parsed_sums(run)
    for path in sorted(sessions.rglob("*")) if sessions.is_dir() else []:
        if path.is_dir() and not path.is_symlink():
            continue
        relative = path.relative_to(sessions)
        copy = copies / relative
        if path.is_symlink() or not path.is_file():
            refuse("codex_home was kept: sessions/%s is not a regular file" % relative)
        if not copy.is_file() or copy.is_symlink() or run.codex_home.resolve() in copy.resolve().parents:
            refuse("codex_home was kept: sessions/%s has no copy in evidence/codex-sessions" % relative)
        digest = sha_file(path)
        if sha_file(copy) != digest:
            refuse("codex_home was kept: the copy of sessions/%s in evidence/codex-sessions does not match it" % relative)
        if sums.get("codex-sessions/%s" % relative) != digest:
            refuse("codex_home was kept: SHA256SUMS does not list the copy of sessions/%s with its hash" % relative)
    return True


def check_claude_purge(run):
    """Check Claude ownership and transcript retention before either host home is deleted."""
    safe_claude_home(run)
    if not run.claude_home.exists():
        return False
    ownership(run, run.claude_home, "claude_home")
    # Until down copies projects/ to evidence (T2(a) PR 6, in collect), a transcript there would be lost, so a home
    # holding any is kept.
    projects = run.claude_home / "projects"
    if os.path.lexists(projects) and (projects.is_symlink() or not projects.is_dir() or any(projects.iterdir())):
        refuse("claude_home was kept: projects/ holds transcripts, which down copies to evidence from T2(a) PR 6")
    return True


def purge(run):
    if not check_codex_purge(run):
        return "already_purged"
    shutil.rmtree(run.codex_home)
    return "purged"


def purge_claude(run):
    """Deletes claude_home, the run's Claude login, under purge's ownership rules."""
    if not check_claude_purge(run):
        return "already_purged"
    shutil.rmtree(run.claude_home)
    return "purged"


def down(run, args):
    require(args.loop_wait >= 1, "--loop-wait must be at least 1 second")
    for requested, kind, flag in ((args.purge_codex_home, CODEX, "--purge-codex-home"),
                                  (args.purge_claude_home, CLAUDE, "--purge-claude-home")):
        if requested and not run.uses(kind):
            refuse("%s requires a plan that uses %s" % (flag, kind))
    if run.uses(CLAUDE) and load_state(run) is not None:
        with login_lock(run, busy_message="a login is in progress"):
            return down_run(run, args)
    return down_run(run, args)


def down_run(run, args):
    state = load_state(run)
    if state is None:
        return OK, {"state": "nothing to take down: init has not run in %s" % run.run}

    if state.get("operations"):
        fail("unresolved model operations retain this run's resources; inspect status and reconcile before down",
             operations=state["operations"])

    def persist():
        if run.uses(CLAUDE):
            return update_state(run, lambda current: current.update(down=state["down"]))
        save_state(run, state)
        return state

    done = state.setdefault("down", {"done": {}})["done"]
    state["down"].setdefault("started_at", timestamp())
    state = persist()
    answer = {"loop": stop_loop(run, args.loop_wait), "roles": stop_roles(run)}
    if "evidence" in done:
        answer["evidence"] = "already_collected"
    else:
        answer["evidence"] = collect(run, state)
        done["evidence"] = {"at": timestamp(), **answer["evidence"]}
        state = persist()
    if state["init"].get("pending"):
        fail("init has an unresolved outcome; resources were kept for inspection")
    if "workspace" in state["init"]["steps"] and (not run.store.is_dir() or not run.recipes.is_file()):
        fail("job cleanup inputs are unavailable; resources were kept for inspection")
    if run.store.is_dir() and run.recipes.is_file():
        cleaned = checked(run, "jobs clean", "jobs", "--store", run.store, "--recipes", run.recipes, "clean",
                          "--initiative", run.id, "--finished")
        if (not isinstance(cleaned.get("jobs"), list) or not isinstance(cleaned.get("not_finished"), list)
                or any(not isinstance(row, str) for row in cleaned["not_finished"])):
            fail("jobs clean returned invalid completion evidence; resources were kept for inspection")
        answer["jobs"] = {"cleaned": len(cleaned["jobs"]), "not_finished": cleaned["not_finished"]}
        if cleaned.get("not_finished"):
            fail("unfinished jobs retain this run's leases, slots and worktrees", jobs=answer["jobs"])
    answer["leases"] = release_leases(run, state)
    answer["slots"] = release_slots(run, state)
    answer["worktrees"] = remove_worktrees(run, state)
    answer["review_copies"] = remove_review_copies(run)
    if run.evidence.is_dir():
        answer["sha256sums"] = write_sums(run)
    # Validate every requested home before deleting either: one host's refusal must keep both homes intact.
    if args.purge_codex_home:
        check_codex_purge(run)
    if args.purge_claude_home:
        check_claude_purge(run)
    if run.uses(CODEX):
        answer["codex_home"] = purge(run) if args.purge_codex_home else "kept"
    if run.uses(CLAUDE):
        answer["claude_home"] = purge_claude(run) if args.purge_claude_home else "kept"
    done["last"] = timestamp()
    state = persist()
    return OK, answer


COMMANDS = {"init": init, "login": login, "root": root, "up": up, "request": request, "approve": approve, "turn": turn,
            "status": status, "down": down}


def log_command(run, command, code):
    try:
        # Logging is best effort and must not follow an accidentally redirected run after an init refusal.
        revalidate_run(run)
        with open(run.commands_log, "a", encoding="utf-8") as stream:
            stream.write(json.dumps({"command": command, "exit": code, "at": timestamp()}, sort_keys=True) + "\n")
    except (Stop, OSError):
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True, help="Absolute path to team-run.json (aegis.team-run/v1 or v2)")
    commands = parser.add_subparsers(dest="command", required=True)
    started = commands.add_parser("init", help="Every non-model setup step: recipes, store, provision, journal, "
                                               "worktrees, slots, leases and the preflight")
    started.add_argument("--continue", dest="resume", action="store_true", help="Resume a failed init at its first "
                                                                               "incomplete step")
    commands.add_parser("login", help="Log in each host the plan uses in the run's own home (codex login in "
                                      "CODEX_HOME, claude auth login in CLAUDE_CONFIG_DIR), then check it")
    bound = commands.add_parser("root", help="Bind the owner's existing ROOT session with its decision connection")
    bound.add_argument("--session", required=True)
    raised = commands.add_parser("up", help="Write team.json, start the roles in order, check each, start the loop")
    raised.add_argument("--accept-agent-tools", action="store_true",
                        help="Keep a role that was offered Codex sub-agent tools; recorded in evidence")
    raised.add_argument("--no-loop", action="store_true", help="Start the roles only; run loop passes yourself")
    asked = commands.add_parser("request", help="Publish a canonical request as the coordinator")
    asked.add_argument("id")
    asked.add_argument("--file", required=True, help="A team_request draft, or the request's fields")
    decided = commands.add_parser("approve", help="One ROOT turn that decides the pending request, then a journal check")
    decided.add_argument("id")
    decided.add_argument("--deny", action="store_true")
    decided.add_argument("--reason")
    decided.add_argument("--reconcile", action="store_true", help="Reconcile the unresolved ROOT turn without replaying it")
    owned = commands.add_parser("turn", help="One trusted owner turn with the role's current wake argv")
    owned.add_argument("endpoint")
    owned.add_argument("prompt", nargs="?")
    owned.add_argument("--reconcile", action="store_true", help="Reconcile this endpoint's unresolved turn without replaying it")
    commands.add_parser("status", help="Team view, loop liveness and launcher records").add_argument(
        "--text", action="store_true", help="Holds grouped by who must act, and pending ROOT decisions")
    lowered = commands.add_parser("down", help="Collect evidence, then stop and release everything the run holds")
    lowered.add_argument("--purge-codex-home", action="store_true",
                         help="Delete codex_home once every session file has a verified copy in evidence")
    lowered.add_argument("--purge-claude-home", action="store_true",
                         help="Delete claude_home, the run's Claude login, once its owner mark is checked")
    lowered.add_argument("--loop-wait", type=int, default=LOOP_WAIT_SECONDS,
                         help="Seconds to wait for the loop to stop after SIGTERM (default %d)" % LOOP_WAIT_SECONDS)
    args = parser.parse_args(argv)
    run = None
    record_command = True
    try:
        run = Run(args.config)
        state = load_state(run)
        if args.command != "status" and state and "custody" in state and state["custody"] != custody(run):
            refuse("run custody changed since init; restore the recorded configuration")
        guard(run, args.command)
        # All direct state writers on an initialized Codex-only run share the stable directory lock. Claude
        # login/up merge through short state transactions instead, keeping browser-login ROOT concurrency.
        serialized = args.command in ("init", "root", "approve", "turn", "down") or (
            not run.uses(CLAUDE) and args.command == "up")
        if serialized and run.run.is_dir():
            busy = {"login": "another login is running for this run", "down": "a login is in progress"}
            with operation_lock(run, busy.get(args.command, "another team command is running for this run")):
                code, result = COMMANDS[args.command](run, args)
        else:
            code, result = COMMANDS[args.command](run, args)
    except Stop as stop:
        code, result = stop.code, {"error": str(stop), **stop.detail}
        record_command = stop.record_command
    except (ValueError, KeyError, TypeError, UnicodeError, RecursionError) as exc:
        code, result = REFUSED, {"error": str(exc)}
    except (OSError, subprocess.SubprocessError) as exc:
        code, result = FAILED, {"error": str(exc)}
    if code != REFUSED and record_command and run is not None and args.command != "status" and run.run.is_dir():
        try:
            environment_evidence(run)
        except (ValueError, OSError) as exc:
            code, result = FAILED, {"error": "child environment evidence failed: %s; command effects were retained" % exc,
                                    "partial_result": result}
        log_command(run, args.command, code)
    if result is not None:
        print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
