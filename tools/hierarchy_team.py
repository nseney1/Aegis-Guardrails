#!/usr/bin/env python3
"""The owner's one command for a team run: init, login, root, up, request, approve, turn, status and down.

One config, `team-run.json` (aegis.team-run/v1, template in hierarchy_templates/team-run.json), replaces the real
run's shell guide and its helpers. Every subcommand checks path safety: CODEX_HOME is the run's codex_home and
never ~/.codex or a folder inside it (by realpath). Commands that start work require free disk at least min_free_gb;
git, bwrap and codex are on
PATH, and cargo and cargo-nextest on the recipes' path when a kept recipe runs them. A command that spends model
turns (login, up, approve, turn) also refuses an API key in the environment.

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
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
# With -I the script directory is absent from sys.path. Add only this reviewed directory.
HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
from hierarchy_mailbox import (GIT_ID, SLUG, Mailbox, endpoint_parts, fields, matching, read_json, require,  # noqa: E402
                               strict_json, text, timestamp)
import hierarchy_lifecycle  # noqa: E402
import hierarchy_native  # noqa: E402
import hierarchy_provision  # noqa: E402
import hierarchy_roles  # noqa: E402
import hierarchy_router  # noqa: E402
import hierarchy_team_view  # noqa: E402


SCHEMA = "aegis.team-run/v1"
STATE_SCHEMA = "aegis.team-run-state/v1"
INDEX_SCHEMA = "aegis.team-evidence-index/v1"
STATUS_SCHEMA = "aegis.team-run-status/v1"
LEDGER_SCHEMA = "aegis.team-turn-ledger/v1"
OK, REFUSED, FAILED = 0, 2, 3
CODEX = hierarchy_provision.CODEX
HOME_PLACEHOLDER = "/REPLACE/WITH/your/home/folder"
PLACEHOLDER = re.compile(r"REPLACE|<[^<>]*>")
DEFAULT_RECIPES = HERE / "hierarchy_templates" / "job-recipes.json"
PACKET_SCHEMA = "aegis.hierarchy-job-packet/v1"
# Written into codex_home by init: purge deletes only a folder that carries it.
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

    def __init__(self, code, message, **detail):
        super().__init__(message)
        self.code = code
        self.detail = detail


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
               {"codex_home", "source", "live_checkouts", "base_tree", "min_free_gb", "loop", "lease_ttl_seconds"})
        require(value["schema"] == SCHEMA, "unsupported team-run schema: " + str(value["schema"])[:80])
        self.raw = value
        self.run = absolute(value["run"], "run")
        self.codex_home = absolute(value.get("codex_home", str(self.run / "codex-home")), "codex_home")
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


def safe_codex_home(run):
    owner = Path.home() / ".codex"
    real, owner_real = os.path.realpath(run.codex_home), os.path.realpath(owner)
    if real == owner_real or real.startswith(owner_real.rstrip(os.sep) + os.sep):
        refuse("CODEX_HOME %s is inside ~/.codex (%s); a team run uses its own folder" % (run.codex_home, owner))
    candidate = Path(real)
    def contains(parent, child):
        return parent == child or parent in child.parents
    for protected in (Path.home(), run.run, owner):
        if contains(candidate, protected.resolve()):
            refuse("unsafe codex_home: it contains %s" % protected)
    for protected in (run.project, run.source, run.evidence, *[run.run / name for name in MANAGED]):
        protected = protected.resolve()
        if contains(candidate, protected) or contains(protected, candidate):
            refuse("unsafe codex_home: it overlaps %s" % protected)
    if run.codex_home.is_symlink():
        refuse("unsafe codex_home: it is a symlink")
    return real


def guard(run, command):
    real = safe_codex_home(run)
    if command == "down":
        return {}
    ambient = os.environ.get("CODEX_HOME")
    if ambient and os.path.realpath(ambient) != real:
        refuse("CODEX_HOME in this shell is %s, not this run's codex_home %s; unset it or export the run's"
               % (ambient, run.codex_home))
    if command == "status":
        return {}
    probe = nearest(run.run)
    free = shutil.disk_usage(str(probe)).free / 2 ** 30
    if free < run.min_free_gb:
        refuse("only %.1f GB free at %s; this run needs min_free_gb %g" % (free, probe, run.min_free_gb))
    tools = {}
    for name in ("git", "bwrap", "codex"):
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
    if command in SPENDS_TURNS:
        keys = [key for key in API_KEYS if key in os.environ]
        if keys:
            refuse("unset OPENAI_API_KEY and CODEX_API_KEY: codex could bill this run to the key instead of the run's "
                   "login (set: %s)" % ", ".join(keys))
    return tools


# -- state, evidence and child processes ----------------------------------------------------------------------------------

def load_state(run):
    return read_json(run.state_path) if run.state_path.is_file() else None


def custody(run):
    return {key: run.raw.get(key) for key in ("run", "project", "source", "codex_home", "base", "branch",
                                             "initiative", "lanes", "roles")}


def save_state(run, state):
    write_atomic(run.state_path, as_json(state))


def init_complete(state):
    return bool(state and state["init"].get("complete_at"))


def require_init(run):
    state = load_state(run)
    if not init_complete(state):
        refuse("init has not completed; run init first")
    if state.get("down", {}).get("started_at") or state.get("down", {}).get("done"):
        refuse("teardown has started; a new run needs a new run folder")
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
    env = dict(os.environ)
    env["CODEX_HOME"] = str(run.codex_home)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if path is not None:
        env["PATH"] = path
    return env


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


def step_codex_home(run, state):
    safe_codex_home(run)
    run.run.mkdir(parents=True, exist_ok=True, mode=0o700)
    if run.codex_home.exists():
        ownership(run)
        return {"codex_home": str(run.codex_home)}
    run.codex_home.mkdir(parents=True, mode=0o700)
    os.chmod(run.codex_home, 0o700)
    mark = {"run": str(run.run), "initiative": run.id, "created_at": timestamp()}
    write_atomic(run.codex_home / OWNER_MARK, as_json(mark))
    return {"codex_home": str(run.codex_home)}


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
    save(run, "provision-init.json", checked(run, "provision init", "provision", "init", "--request",
                                             request_file(run, "provision-init.json", request)))


def step_front_door(run, state):
    # A stand-in binding that never runs a host: the owner's front-door mail goes through the mailbox CLI.
    request = {"base": str(run.base), "endpoint": run.endpoint("front-door"), "host": "claude-code",
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
        run.run.mkdir(parents=True, exist_ok=True, mode=0o700)
        save_state(run, state)
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

def login(run, args):
    require_init(run)
    import hierarchy_native_probe as probe
    proc = subprocess.run(["codex", "login"], env=child_env(run))
    if proc.returncode != 0:
        fail("codex login exited %d" % proc.returncode)
    # The probe's real-login folder rules, less its own owner mark, with this run's mark and its sessions/ allowed.
    allowed = (set(probe.EXISTING_LOGIN_ENTRIES) - {probe.OWNER_MARK}) | {OWNER_MARK, "sessions"}
    entries = sorted(os.listdir(run.codex_home))
    extra = [entry for entry in entries if entry not in allowed]
    try:
        if extra:
            raise probe.Refusal("CODEX_HOME holds entries a codex login does not create: " + ", ".join(extra))
        if probe.AUTH_FILE not in entries:
            raise probe.Refusal("CODEX_HOME has no auth.json after codex login")
        auth = probe.auth_digest(run.codex_home / probe.AUTH_FILE)
        probe.login_extras(run.codex_home, shutil.which("codex"))
    except probe.Refusal as exc:
        refuse(str(exc))
    answer = {"codex_home": str(run.codex_home), "auth_sha256": auth, "entries": entries}
    save(run, "login.json", answer)
    return OK, answer


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


def root(run, args):
    state = require_init(run)
    require(hierarchy_provision.SESSION.fullmatch(args.session) is not None, "invalid session: " + args.session[:80])
    request = {"base": str(run.base), "endpoint": run.endpoint("root"), "host": CODEX, "session": args.session,
               "lifecycle": str(run.lifecycle), "actor": current_actor(run, "root"), "loop_state": str(run.loop_state),
               "evidence": str(run.evidence)}
    code, answer, _ = tool(run, "provision", "add-role", "--request", request_file(run, "root.json", request))
    if code != 0:
        (refuse if code == REFUSED else fail)(answer.get("error", "provision add-role exited %d" % code))
    tools = adapter_tools(run, answer["connection"])
    save(run, "root-binding.json", {**answer, "tools": tools})
    state["root"] = {"session": args.session, "generation": answer["generation"], "connection": answer["connection"],
                     "mcp_config": answer["mcp_config"], "tools": tools, "at": timestamp()}
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
    found = sorted((run.codex_home / "sessions").glob("**/rollout-*%s.jsonl" % session))
    if len(found) != 1:
        fail("%s rollout%s for %s's session %s under %s" % ("no" if not found else str(len(found)),
                                                           "" if len(found) == 1 else "s", endpoint, session,
                                                           run.codex_home / "sessions"))
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
    if environ.get("CODEX_HOME") != str(run.codex_home):
        problems.append("its CODEX_HOME is %s, not %s" % (environ.get("CODEX_HOME"), run.codex_home))
    if cargo_dir is not None and cargo_dir not in environ.get("PATH", "").split(os.pathsep):
        problems.append("its PATH lacks %s, where the recipes' cargo is" % cargo_dir)
    if problems:
        process.terminate()
        process.wait(timeout=LOOP_WAIT_SECONDS)
        fail("the loop (pid %d) was stopped: %s" % (process.pid, "; ".join(problems)))
    save(run, "loop-environ.txt", ("CODEX_HOME=%s\nPATH=%s\n" % (environ["CODEX_HOME"], environ.get("PATH", "")))
         .encode("utf-8"))
    return {"state": "started", "pid": process.pid, "interval": run.interval, "log": str(run.log_path),
            "cargo_on_path": cargo_dir}


def up(run, args):
    state = require_init(run)
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
    state["up"] = {"at": timestamp(), "roles": [row["endpoint"] for row in rows], "loop": loop}
    save_state(run, state)
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


def approve(run, args):
    state = require_init(run)
    bound = state.get("root")
    if not bound:
        refuse("ROOT is not bound; run root --session <id> first")
    reason = args.reason
    require(not set('"\r\n') & set(reason), "the reason may not contain double quotes or line breaks")
    text(reason, "reason", 512)
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
    proc = subprocess.run(argv, cwd=str(run.project), env=child_env(run), stdin=subprocess.DEVNULL,
                          capture_output=True)
    stdout = proc.stdout.decode("utf-8", "replace")
    append_evidence(run, "root-turns.jsonl", proc.stdout)
    messages = [item["text"] for item in agent_items(stdout) if item["type"] == "agent_message"]
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
    by_argv = profile["prompt_via"] == "argv"
    argv = profile["argv"] + ([args.prompt] if by_argv else [])
    from hierarchy_mailbox import writer_lock
    from hierarchy_wake import claim_wake
    with writer_lock(mailbox.root):
        current = Mailbox(mailbox.root).current_binding(endpoint)
        require(all(profile[key] == current[key] for key in ("host", "session", "generation")),
                "binding changed before owner turn; the outgoing session was not started")
        marker = claim_wake(mailbox, endpoint)
    proc = subprocess.run(argv, cwd=profile["cwd"], env=child_env(run), capture_output=True,
                          input=None if by_argv else args.prompt.encode("utf-8"),
                          stdin=subprocess.DEVNULL if by_argv else None)
    # An interrupted or uncertain launch retains the marker for inspection.
    marker.unlink()
    log = append_evidence(run, "role-turns-%s.jsonl" % quoted, proc.stdout)
    answer = {"endpoint": endpoint, "exit_code": proc.returncode, "items": agent_items(proc.stdout.decode("utf-8",
                                                                                                          "replace")),
              "log": str(log)}
    if proc.stderr:
        answer["stderr"] = proc.stderr.decode("utf-8", "replace")[-800:]
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
        if not binding or binding["host"] != CODEX or endpoint_parts(endpoint)[1] == "root":
            continue
        code, answer, _ = tool(run, "launcher", "--base", run.base, "stop", "--endpoint", endpoint)
        rows.append({"endpoint": endpoint, "state": answer.get("state"), "pids": answer.get("pids", [])})
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


def ownership(run):
    mark = run.codex_home / OWNER_MARK
    if not mark.is_file() or mark.is_symlink():
        refuse("codex_home was kept: it has no %s mark, so this run did not make it" % OWNER_MARK)
    record = read_json(mark)
    if not isinstance(record, dict) or record.get("run") != str(run.run) or record.get("initiative") != run.id:
        refuse("codex_home was kept: ownership record does not match this run")


def purge(run):
    safe_codex_home(run)
    if not run.codex_home.exists():
        return "already_purged"
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
    shutil.rmtree(run.codex_home)
    return "purged"


def down(run, args):
    require(args.loop_wait >= 1, "--loop-wait must be at least 1 second")
    state = load_state(run)
    if state is None:
        return OK, {"state": "nothing to take down: init has not run in %s" % run.run}
    done = state.setdefault("down", {"done": {}})["done"]
    state["down"].setdefault("started_at", timestamp())
    save_state(run, state)
    answer = {"loop": stop_loop(run, args.loop_wait), "roles": stop_roles(run)}
    if "evidence" in done:
        answer["evidence"] = "already_collected"
    else:
        answer["evidence"] = collect(run, state)
        done["evidence"] = {"at": timestamp(), **answer["evidence"]}
        save_state(run, state)
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
    answer["codex_home"] = purge(run) if args.purge_codex_home else "kept"
    done["last"] = timestamp()
    save_state(run, state)
    return OK, answer


COMMANDS = {"init": init, "login": login, "root": root, "up": up, "request": request, "approve": approve, "turn": turn,
            "status": status, "down": down}


def log_command(run, command, code):
    try:
        with open(run.commands_log, "a", encoding="utf-8") as stream:
            stream.write(json.dumps({"command": command, "exit": code, "at": timestamp()}, sort_keys=True) + "\n")
    except OSError:
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True, help="Absolute path to team-run.json (aegis.team-run/v1)")
    commands = parser.add_subparsers(dest="command", required=True)
    started = commands.add_parser("init", help="Every non-model setup step: recipes, store, provision, journal, "
                                               "worktrees, slots, leases and the preflight")
    started.add_argument("--continue", dest="resume", action="store_true", help="Resume a failed init at its first "
                                                                               "incomplete step")
    commands.add_parser("login", help="codex login in the run's CODEX_HOME, then check the login folder")
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
    decided.add_argument("--reason", required=True)
    owned = commands.add_parser("turn", help="One trusted owner turn with the role's current wake argv")
    owned.add_argument("endpoint")
    owned.add_argument("prompt")
    commands.add_parser("status", help="Team view, loop liveness and launcher records").add_argument(
        "--text", action="store_true", help="Holds grouped by who must act, and pending ROOT decisions")
    lowered = commands.add_parser("down", help="Collect evidence, then stop and release everything the run holds")
    lowered.add_argument("--purge-codex-home", action="store_true",
                         help="Delete codex_home once every session file has a verified copy in evidence")
    lowered.add_argument("--loop-wait", type=int, default=LOOP_WAIT_SECONDS,
                         help="Seconds to wait for the loop to stop after SIGTERM (default %d)" % LOOP_WAIT_SECONDS)
    args = parser.parse_args(argv)
    run = None
    try:
        run = Run(args.config)
        state = load_state(run)
        if args.command != "status" and state and "custody" in state and state["custody"] != custody(run):
            refuse("run custody changed since init; restore the recorded configuration")
        guard(run, args.command)
        code, result = COMMANDS[args.command](run, args)
    except Stop as stop:
        code, result = stop.code, {"error": str(stop), **stop.detail}
    except (ValueError, KeyError, TypeError, UnicodeError, RecursionError) as exc:
        code, result = REFUSED, {"error": str(exc)}
    except (OSError, subprocess.SubprocessError) as exc:
        code, result = FAILED, {"error": str(exc)}
    if run is not None and args.command != "status" and run.run.is_dir():
        log_command(run, args.command, code)
    if result is not None:
        print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
