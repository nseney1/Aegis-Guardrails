"""Model-free publisher core; activation and trusted evidence wiring belong to GM-12/D5.

The owner supplies the repository, journal, credential environment and qualification
reader. Model requests supply none of those authorities. No repository code may run
in this process. Python object introspection is not an isolation boundary: the
broker must keep this service outside model processes, as required by ADR G1.

Every effect consumes a service-local permit, rechecks mutable evidence, reserves
its journal intent, and observes its result. A repeated request only reads or
reconciles its first attempt; an ambiguous reply never grants another attempt.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass, replace
import json
import os
import re
import threading
from urllib.parse import urlencode
import weakref

from aegis_core import approval_policy, ghcli, gitsafe, human_gate, primitives, team_gitops

__all__ = ["PublishRequest", "Publisher", "PublishError", "REFUSALS"]

MAX_OUTPUT = 65536
MAX_POLICY_OUTPUT = approval_policy.MAX_CONFIG_BYTES + 128  # cat-file --batch framing.
MAX_PERMITS = 128
MAX_ROOT_CHARS = 16384  # The existing gitsafe.custody scratch-root limit.
REFUSALS = {
    **team_gitops.REFUSALS,
    "invalid_request": "invalid publisher request",
    "invalid_permit": "publisher operation requires its matching unused permit",
    "permit_capacity": "publisher permit capacity reached",
    "unsafe_remote": "publisher requires the configured credential-free HTTPS remote",
    "policy_unavailable": "publisher requires a valid explicit base-bound approval policy",
    "policy_refused": "approval policy refuses this publisher operation",
    "protected_target": "publisher cannot push to or cancel runs on this protected target",
    "not_qualified": "trusted qualification evidence does not authorize these exact bytes",
    "ref_moved": "publisher ref no longer matches the checked commit",
    "not_fast_forward": "publisher requires a verified fast-forward",
    "git_unavailable": "publisher cannot establish Git state",
    "gh_unavailable": "publisher cannot establish forge state",
    "gh_malformed": "forge returned an invalid or oversized publisher observation",
    "identity_unavailable": "publisher requires its separate forge credential",
    "run_refused": "publisher may cancel only a superseded push run on this exact branch",
    "push_refused": "remote refused the publisher fast-forward push",
    "unsafe_git_config": "publisher refuses repository-selected transport programs or redirects",
    "effect_unconfirmed": "publisher effect was not confirmed; reconcile without repeating it",
    "immutable_source": "publisher PR sources are commit-addressed, create-only qualified refs",
    "push_output_invalid": "push output does not prove exactly the permitted ref operation",
}
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_REMOTE = re.compile(r"https://([a-z0-9]+(?:[.-][a-z0-9]+)*)/([A-Za-z0-9_-][A-Za-z0-9_.-]{0,99})/([A-Za-z0-9_-][A-Za-z0-9_.-]{0,99})\.git\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


class PublishError(ValueError):
    """Only fixed refusals cross the broker boundary; no input or transport text."""

    def __init__(self, code):
        super().__init__(REFUSALS[code])
        self.code = code
        self.next_action = {"actor": "owner", "command": "inspect publisher evidence and reconcile the request before any new operation"}


@dataclass(frozen=True)
class PublishRequest:
    request_id: str
    lane: str
    actor: str
    remote: str
    ref: str
    commit: str
    expected_old: str
    operation: str
    head_ref: str = None
    run_id: int = None
    policy_base: str = None


class _Permit:
    def __new__(cls):
        raise PublishError("invalid_permit")


def _oid(value):
    return type(value) is str and len(value) in (40, 64) and _OID.fullmatch(value) is not None


def _branch(value):
    return (type(value) is str and 12 <= len(value) <= 266 and value.startswith("refs/heads/")
            and value[11:] != "HEAD" and human_gate.is_branch_name(value[11:]))


def _remote_identity(value):
    found = _REMOTE.fullmatch(value) if type(value) is str and len(value) <= 512 else None
    if found is None or any(part in (".", "..") for part in found.groups()):
        raise PublishError("unsafe_remote")
    return found[1], found[2] + "/" + found[3]


def _source_ref(commit):
    return "refs/heads/aegis/publish/" + commit


def _valid_request(item):
    if type(item) is not PublishRequest:
        raise PublishError("invalid_request")
    for value in (item.request_id, item.actor):
        if type(value) is not str or len(value) > 128 or not _IDENTIFIER.fullmatch(value):
            raise PublishError("invalid_request")
    if type(item.lane) is not str or len(item.lane) > 63 or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", item.lane):
        raise PublishError("invalid_request")
    if not _branch(item.ref) or not _oid(item.commit):
        raise PublishError("invalid_request")
    if type(item.operation) is not str or item.operation not in ("push", "pr", "release_pr", "cancel"):
        raise PublishError("invalid_request")
    if item.expected_old is None:
        if (item.operation != "push" or not _oid(item.policy_base)
                or item.ref not in ("refs/heads/lane/" + item.lane, _source_ref(item.commit))):
            raise PublishError("invalid_request")
    elif not _oid(item.expected_old) or item.policy_base not in (None, item.expected_old):
        raise PublishError("invalid_request")
    if item.operation == "push" and item.ref.startswith("refs/heads/aegis/publish/"):
        if item.ref != _source_ref(item.commit) or item.expected_old is not None:
            raise PublishError("immutable_source")
    if item.operation in ("pr", "release_pr"):
        if not _branch(item.head_ref) or item.head_ref == item.ref:
            raise PublishError("invalid_request")
        if item.head_ref != _source_ref(item.commit):
            raise PublishError("immutable_source")
    elif item.head_ref is not None:
        raise PublishError("invalid_request")
    if item.operation == "cancel":
        if type(item.run_id) is not int or not 0 < item.run_id <= 2**63 - 1:
            raise PublishError("invalid_request")
    elif item.run_id is not None:
        raise PublishError("invalid_request")
    _remote_identity(item.remote)
    return replace(item)


def _json(result):
    if result is None or type(result) is not ghcli.GhResult or result.returncode != 0:
        raise PublishError("gh_unavailable")
    data = result.stdout
    if type(data) is not str or len(data) > MAX_OUTPUT:
        raise PublishError("gh_malformed")
    try:
        if len(data.encode("utf-8")) > MAX_OUTPUT:
            raise PublishError("gh_malformed")
        return primitives.strict_loads(data)
    except (ValueError, UnicodeError, RecursionError):
        raise PublishError("gh_malformed") from None


def _safe_config(raw, remote, root, remote_name):
    """Allow only known inert metadata and the exact owner-configured remote.

    Include directives are refused. Git startup may load them before the
    --no-includes enumeration option applies; startup failure also fails closed.
    No included configuration can gain network authority after this check.
    Command scope is produced solely by scrubbed gitsafe hardening; system and
    global scopes are disabled by the transport context.
    """
    if type(raw) is not bytes or len(raw) > MAX_OUTPUT or raw.count(b"\0") > 1024:
        return False
    if not raw:
        return True
    if not raw.endswith(b"\0"):
        return False
    try:
        raw.decode("utf-8")
    except UnicodeError:
        return False
    parts = raw[:-1].split(b"\0")
    if len(parts) % 2:
        return False
    booleans = {b"true", b"false"}
    values = {key: booleans for key in (
        b"core.filemode", b"core.bare", b"core.logallrefupdates", b"core.symlinks",
        b"core.ignorecase", b"core.precomposeunicode", b"extensions.worktreeconfig")}
    values.update({b"core.repositoryformatversion": {b"0", b"1"},
                   b"extensions.objectformat": {b"sha1", b"sha256"},
                   b"core.autocrlf": booleans | {b"input"}, b"core.safecrlf": booleans | {b"warn"},
                   b"push.followtags": booleans, b"push.gpgsign": booleans | {b"if-asked"},
                   b"push.recursesubmodules": {b"false", b"no", b"check", b"on-demand", b"only"},
                   b"push.default": {b"nothing", b"current", b"upstream", b"simple", b"matching"}})
    remote_key = ("remote." + remote_name).encode("ascii")
    for scope, record in zip(parts[::2], parts[1::2]):
        key, separator, value = record.partition(b"\n")
        if not separator or not key:
            return False
        if scope == b"command":
            continue
        if scope not in (b"local", b"worktree"):
            return False
        if key == remote_key + b".url" and value == remote.encode("ascii"):
            continue
        if key == remote_key + b".fetch" and value == ("+refs/heads/*:refs/remotes/" + remote_name + "/*").encode("ascii"):
            continue
        lower = key.lower()
        if lower in values and value.lower() in values[lower]:
            continue
        if lower == b"core.worktree" and value == str(root).encode("utf-8"):
            continue
        if lower in (b"user.name", b"user.email") and 0 < len(value) <= 512 and all(c >= 32 and c != 127 for c in value):
            continue
        if key.startswith(b"branch."):
            branch, _, field = key[len(b"branch."):].rpartition(b".")
            if _branch("refs/heads/" + branch.decode("utf-8")):
                if field in (b"remote", b"pushremote") and value == remote_name.encode("ascii"):
                    continue
                if field == b"merge" and _branch(value.decode("utf-8")):
                    continue
        return False
    return True


def _push_status(result, item):
    """Validate the one-ref transaction receipt; never display transport text."""
    raw = result.stdout
    if type(raw) is not bytes or len(raw) > MAX_OUTPUT or raw.count(b"\n") > 8:
        raise PublishError("push_output_invalid")
    rows = []
    for line in raw.splitlines():
        if line.startswith(b"To ") or line == b"Done":
            continue
        parts = line.split(b"\t")
        if len(parts) != 3 or parts[0] not in (b" ", b"*", b"=", b"!"):
            raise PublishError("push_output_invalid")
        if parts[1] != (item.commit + ":" + item.ref).encode("ascii"):
            raise PublishError("push_output_invalid")
        rows.append(parts)
    if type(result.returncode) is not int:
        raise PublishError("push_output_invalid")
    if not rows and result.returncode != 0:
        return "git_unavailable"
    if len(rows) != 1:
        raise PublishError("push_output_invalid")
    flag, _, detail = rows[0]
    if flag == b"!":
        if result.returncode == 0:
            raise PublishError("push_output_invalid")
        return "ref_moved" if detail.endswith((b"(stale info)", b"(already exists)")) else "push_refused"
    if flag == b"=":
        return "ref_moved"  # Git may skip the lease when the ref is already up to date.
    expected_flag = b"*" if item.expected_old is None else b" "
    if flag != expected_flag or result.returncode != 0:
        raise PublishError("push_output_invalid")
    return None


class Publisher:
    """Owner-configured service; callers can obtain effects only with gate permits.

    ``qualified(request)`` is a trusted, read-only service boundary, never a field
    in a broker request. It must verify all required legs for the exact commit/tree
    and operation (including hosted legs for release PRs). The gate also reads the
    base/head policy itself. No legacy-mode publisher is implicitly enabled.

    ``gh`` must be an owner-supplied adapter returning ghcli.GhResult, with both
    output streams capped at MAX_OUTPUT during capture and a bounded timeout.
    The legacy default_gh_runner captures without a cap, so it is deliberately
    not selected here. GM-12 must supply the bounded, isolated D5 transport;
    tests supply a fake adapter. Returned JSON is bounded again before parsing.

    Optional Git, policy, commit and credential readers are owner-configured
    dependencies, never broker request fields. Defaults retain the hardened Git
    runner and base/head policy resolver. Their injection does not grant permits.

    PR head refs must be refs/heads/aegis/publish/<qualified commit>. Provision
    them through a separate create-only push permit with expected_old=None and
    policy_base pinned by the trusted qualification reader. The publisher never
    updates that namespace, so competing permitted requests cannot move a PR's
    source during creation. The owner/sole publisher credential boundary is
    required; arbitrary external owner ref mutation is outside this guarantee.
    """

    def __init__(self, root, journal, *, remote, qualified, gh=None, git_runner=None,
                 commit_resolver=None, policy_resolver=None, credential_reader=None, remote_name="origin"):
        self.__host, self.__repo = _remote_identity(remote)
        if type(remote_name) is not str or len(remote_name) > 64 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", remote_name):
            raise PublishError("invalid_request")
        self.__remote_name = remote_name
        if type(root) is str and len(root) > MAX_ROOT_CHARS:
            raise PublishError("unsafe_journal")
        try:
            self.__root = team_gitops.GitOpsJournal(root).common_dir
        except team_gitops.GitOpsError as error:
            raise PublishError(error.code) from None
        if len(str(self.__root)) > MAX_ROOT_CHARS:
            raise PublishError("unsafe_journal")
        self.__journal = journal
        self.__remote = remote
        self.__qualified = qualified
        if not callable(gh):
            raise PublishError("gh_unavailable")
        if any(reader is not None and not callable(reader)
               for reader in (git_runner, commit_resolver, policy_resolver, credential_reader)):
            raise PublishError("invalid_request")
        self.__gh = gh
        self.__git_run = gitsafe.run if git_runner is None else git_runner
        self.__resolve_commit = gitsafe.resolve_commit if commit_resolver is None else commit_resolver
        self.__resolve_policy = approval_policy.resolve_policy if policy_resolver is None else policy_resolver
        self.__credential_reader = (lambda: os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")) if credential_reader is None else credential_reader
        self.__permits = weakref.WeakKeyDictionary()
        self.__active = weakref.WeakKeyDictionary()
        self.__lock = threading.Lock()

    def _states(self, item):
        binding = {"ref": item.ref, "head": item.commit, "base": item.policy_base or item.expected_old,
                   "owner": item.remote, "branch": item.head_ref or item.ref}
        if item.expected_old is None:
            return ({**binding, "exists": False, "state": item.operation + "_before"},
                    {**binding, "exists": True, "state": item.operation + "_after"})
        if item.run_id is not None:
            binding["run_id"] = item.run_id
        return ({**binding, "state": item.operation + "_before"},
                {**binding, "state": item.operation + "_after"})

    def _history(self, item):
        before, after = self._states(item)
        try:
            rows = [row for row in self.__journal.read().rows if row["request_id"] == item.request_id]
        except team_gitops.GitOpsError as error:
            raise PublishError(error.code) from None
        if rows:
            old = rows[0]
            if (old["op"] != self._journal_op(item) or old["lane"] != item.lane or old["actor"] != item.actor
                    or old["expected_old"] != before or old["expected_new"] != after):
                raise PublishError("request_conflict")
        return rows

    def _journal_op(self, item):
        return {"push": "push", "pr": "pr_open", "release_pr": "pr_open", "cancel": "run_cancel"}[item.operation]

    def gate(self, request):
        """Evaluate the complete refusal set, then issue a request-bound opaque grant.

        Existing durable requests get observation-only grants. They can never
        reserve another attempt, even when qualifications or refs have changed.
        """
        item = _valid_request(request)
        if item.remote != self.__remote:
            raise PublishError("unsafe_remote")
        if not team_gitops.descriptor_supported():
            raise PublishError("unsupported_platform")
        if not self._history(item):
            with gitsafe.custody(scratch=self.__root, stdout_limit=MAX_POLICY_OUTPUT, stderr_limit=MAX_OUTPUT,
                                 env={"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}):
                self._check(item)
        with self.__lock:
            if len(self.__permits) + len(self.__active) >= MAX_PERMITS:
                raise PublishError("permit_capacity")
            permit = object.__new__(_Permit)
            self.__permits[permit] = item
            return permit

    @contextmanager
    def _active_permit(self, permit, operation):
        with self.__lock:
            if type(permit) is not _Permit or permit not in self.__permits:
                raise PublishError("invalid_permit")
            item = self.__permits.pop(permit)
            if item.operation != operation:
                raise PublishError("invalid_permit")
            self.__active[permit] = (item, "checking")
        try:
            yield item
        finally:
            with self.__lock:
                self.__active.pop(permit, None)

    @contextmanager
    def _transport_safety(self):
        """The sole safety check, inside every credentialed entry point."""
        with gitsafe.custody(scratch=self.__root, stdout_limit=MAX_POLICY_OUTPUT, stderr_limit=MAX_OUTPUT,
                             env={"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}):
            try:
                result = self.__git_run(["config", "--null", "--show-scope", "--no-includes", "--list"], self.__root)
                code, raw = result.returncode, result.stdout
            except Exception:
                raise PublishError("git_unavailable") from None
            if type(code) is not int:
                raise PublishError("git_unavailable")
            if code != 0:
                raise PublishError("unsafe_git_config")
            if not _safe_config(raw, self.__remote, self.__root, self.__remote_name):
                raise PublishError("unsafe_git_config")
            yield

    @gitsafe.scrubbed()
    def _tip(self, ref):
        try:
            with self._transport_safety():
                result = self.__git_run(["ls-remote", "--refs", "--exit-code", "--", self.__remote, ref], self.__root,
                                        _env=self._network_env())
            raw = result.stdout
            if result.returncode == 2 and type(raw) is bytes and raw == b"":
                return None  # --exit-code distinguishes authoritative absence.
            if result.returncode != 0 or type(raw) is not bytes or len(raw) > 1024:
                raise PublishError("git_unavailable")
            text = raw.decode("utf-8")
            parts = text.removesuffix("\n").split("\t")
            if len(parts) != 2 or not _oid(parts[0]) or parts[1] != ref:
                raise PublishError("git_unavailable")
            return parts[0]
        except PublishError:
            raise
        except Exception:
            raise PublishError("git_unavailable") from None

    def _network_env(self):
        try:
            token = self.__credential_reader()
        except Exception:
            raise PublishError("identity_unavailable") from None
        if type(token) is not str or not 1 <= len(token) <= 4096 or not all(33 <= ord(c) <= 126 for c in token):
            raise PublishError("identity_unavailable")
        header = base64.b64encode(("x-access-token:" + token).encode("ascii")).decode("ascii")
        settings = [("http." + self.__remote + ".extraHeader", "AUTHORIZATION: basic " + header),
                    ("gc.auto", "0"), ("maintenance.auto", "false"), ("http.followRedirects", "false"),
                    ("http.sslVerify", "true"), ("core.askPass", ""), ("protocol.https.allow", "always")]
        env = {"GIT_ALLOW_PROTOCOL": "https", "GIT_ASKPASS": os.devnull, "SSH_ASKPASS": os.devnull,
               "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
               "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_COUNT": str(len(settings))}
        for index, (key, value) in enumerate(settings):
            env["GIT_CONFIG_KEY_" + str(index)] = key
            env["GIT_CONFIG_VALUE_" + str(index)] = value
        return env

    def _get(self, endpoint):
        try:
            with self._transport_safety():
                return _json(self.__gh(["api", "--hostname", self.__host, "--method", "GET", endpoint], cwd=self.__root))
        except PublishError:
            raise
        except Exception:
            # The forge transport is an external boundary; never echo its error.
            raise PublishError("gh_unavailable") from None

    @gitsafe.scrubbed()
    def _ancestor(self, old, new):
        try:
            result = self.__git_run(["merge-base", "--is-ancestor", old, new], self.__root)
            if result.returncode not in (0, 1):
                raise PublishError("git_unavailable")
            return result.returncode == 0
        except Exception:
            raise PublishError("git_unavailable") from None

    @gitsafe.scrubbed()
    def _check(self, item):
        with self._transport_safety():
            target = item.ref[11:]
            if item.operation in ("push", "cancel") and (target in ("main", "develop") or target.startswith("release/")):
                raise PublishError("protected_target")
            try:
                policy = self.__resolve_policy(self.__root, item.policy_base or item.expected_old, item.commit, target)
            except Exception:
                raise PublishError("policy_unavailable") from None
            if (type(policy) is not approval_policy.Policy or policy.error is not None
                    or policy.mode not in approval_policy.MODES or policy.target != target):
                raise PublishError("policy_unavailable")
            allowed = ("review", "signature") if item.operation == "release_pr" else ("none",)
            if policy.mode not in allowed:
                raise PublishError("policy_refused")
            try:
                qualified = self.__qualified(item)
            except Exception:
                raise PublishError("not_qualified") from None
            if qualified is not True:
                raise PublishError("not_qualified")
            if self._tip(item.ref) != item.expected_old:
                raise PublishError("ref_moved")
            if item.head_ref and self._tip(item.head_ref) != item.commit:
                raise PublishError("ref_moved")
            try:
                if self.__resolve_commit(self.__root, item.commit) != item.commit:
                    raise PublishError("git_unavailable")
            except Exception:
                raise PublishError("git_unavailable") from None
            if item.operation == "push" and not self._ancestor(item.policy_base or item.expected_old, item.commit):
                raise PublishError("not_fast_forward")
            repo = self._get("repos/" + self.__repo)
            if (type(repo) is not dict or repo.get("full_name") != self.__repo or type(repo.get("permissions")) is not dict
                    or repo["permissions"].get("push") is not True):
                raise PublishError("gh_malformed")
            if item.head_ref and self._pull(item) is None:
                raise PublishError("ref_moved")
            if item.operation == "cancel":
                if item.commit != item.expected_old:
                    raise PublishError("run_refused")
                if self._run(item) is None:
                    raise PublishError("run_refused")

    def _pulls_endpoint(self, item):
        query = urlencode({"state": "open", "head": self.__repo.split("/")[0] + ":" + item.head_ref[11:], "base": item.ref[11:], "per_page": 2})
        return "repos/" + self.__repo + "/pulls?" + query

    def _pull(self, item):
        rows = self._get(self._pulls_endpoint(item))
        if type(rows) is not list or len(rows) > 1:
            raise PublishError("gh_malformed")
        if not rows:
            return False
        row = rows[0]
        if type(row) is not dict or type(row.get("head")) is not dict or type(row.get("base")) is not dict:
            raise PublishError("gh_malformed")
        head, base = row["head"], row["base"]
        if type(head.get("repo")) is not dict or type(base.get("repo")) is not dict:
            raise PublishError("gh_malformed")
        number, sha = row.get("number"), head.get("sha")
        valid = (type(number) is int and 0 < number <= 2**63 - 1 and number != 259
                 and row.get("state") == "open" and row.get("draft") is (item.operation == "pr")
                 and head.get("ref") == item.head_ref[11:] and base.get("ref") == item.ref[11:]
                 and head["repo"].get("full_name") == self.__repo and base["repo"].get("full_name") == self.__repo)
        if not valid or not _oid(sha):
            raise PublishError("gh_malformed")
        return True if sha == item.commit else None

    def _run(self, item):
        row = self._get("repos/" + self.__repo + "/actions/runs/" + str(item.run_id))
        fields = ("id", "head_sha", "head_branch", "event", "status", "conclusion")
        if type(row) is not dict or any(field not in row for field in fields):
            raise PublishError("gh_malformed")
        valid = (type(row["id"]) is int and row["id"] == item.run_id
                 and row["head_branch"] == item.ref[11:] and row["event"] == "push"
                 and _oid(row["head_sha"]) and row["head_sha"] != item.commit)
        if not valid or not self._ancestor(row["head_sha"], item.commit):
            raise PublishError("run_refused")
        if row["status"] not in ("queued", "in_progress", "completed", "waiting", "pending", "requested"):
            raise PublishError("gh_malformed")
        if row["conclusion"] is not None and type(row["conclusion"]) is not str:
            raise PublishError("gh_malformed")
        if row["status"] == "completed":
            return True if row["conclusion"] == "cancelled" else None
        return False

    def _observe(self, item):
        before, after = self._states(item)
        if item.operation == "push":
            tip = self._tip(item.ref)
            if tip == item.commit:
                return after
            return before if tip == item.expected_old else {"state": "unknown", **({"oid": tip} if tip is not None else {})}
        if item.operation in ("pr", "release_pr"):
            if self._tip(item.head_ref) != item.commit:
                return {"state": "unknown"}
            pull = self._pull(item)
            return {"state": "unknown"} if pull is None else after if pull else before
        run = self._run(item)
        return {"state": "unknown"} if run is None else after if run else before

    def _replay(self, item):
        rows = self._history(item)
        result = next((row for row in rows if row["kind"] == "result"), None)
        if result is None:
            blocked = []
            def observe(row):
                if row["request_id"] != item.request_id:
                    return None
                try:
                    return team_gitops.Observation(self._observe(item))
                except PublishError as error:
                    if not blocked:
                        blocked.append(error.code)
                    raise
            self.__journal.reconcile(item.lane, observe)
            if blocked:
                raise PublishError(blocked[0])
            result = next((row for row in self._history(item) if row["kind"] == "result"), None)
        status = result["status"] if result else "pending"
        return {"status": status, "code": "effect_busy" if result is None else None if status == "done" else "effect_unconfirmed"}

    def push(self, permit):
        return self._execute(permit, "push")

    def pr(self, permit):
        return self._execute(permit, "pr")

    def release_pr(self, permit):
        return self._execute(permit, "release_pr")

    def cancel(self, permit):
        return self._execute(permit, "cancel")

    def _effect(self, permit):
        """The only mutating network entry; requires an armed journaled permit."""
        with self.__lock:
            if type(permit) is not _Permit or permit not in self.__active:
                raise PublishError("invalid_permit")
            item, phase = self.__active[permit]
            if phase != "ready":
                raise PublishError("invalid_permit")
            self.__active[permit] = (item, "used")
        with self._transport_safety():
            if item.operation == "push":
                env = self._network_env()
                try:
                    result = self.__git_run(["push", "--porcelain", "--no-verify", "--no-signed", "--no-follow-tags",
                                            "--recurse-submodules=no", "--force-with-lease=" + item.ref + ":" + (item.expected_old or ""),
                                            "--", self.__remote, item.commit + ":" + item.ref], self.__root, _env=env)
                    return _push_status(result, item), False
                except PublishError:
                    raise
                except Exception:
                    return "git_unavailable", False
            endpoint = "repos/" + self.__repo + "/pulls"
            data = {"head": item.head_ref[11:] if item.head_ref else "", "base": item.ref[11:],
                    "title": "Qualified release " + item.commit if item.operation == "release_pr" else "Qualified lane " + item.commit,
                    "body": "Exact qualified commit: " + item.commit, "draft": item.operation == "pr"}
            cancel = item.operation == "cancel"
            if cancel:
                endpoint = "repos/" + self.__repo + "/actions/runs/" + str(item.run_id) + "/cancel"
            try:
                result = self.__gh(["api", "--hostname", self.__host, "--method", "POST",
                                   *([] if cancel else ["--input", "-"]), endpoint],
                                  stdin=None if cancel else json.dumps(data).encode("utf-8"), cwd=self.__root)
                if result is None or result.returncode != 0:
                    return "gh_unavailable", cancel and result is not None
                return None, cancel
            except Exception:
                return "gh_unavailable", cancel

    @gitsafe.scrubbed()
    def _execute(self, permit, operation=None):
        with gitsafe.custody(scratch=self.__root, stdout_limit=MAX_POLICY_OUTPUT, stderr_limit=MAX_OUTPUT,
                             env={"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}), \
                self._active_permit(permit, operation) as item:
            try:
                if self._history(item):
                    return self._replay(item)
                self._check(item)
                before, after = self._states(item)
                receipt = self.__journal.record_intent(op=self._journal_op(item), lane=item.lane, actor=item.actor,
                                                      request_id=item.request_id, expected_old=before, expected_new=after)
                with receipt:
                    if not receipt.created:
                        return self._replay(item)
                    failure, cancel_in_flight = None, False
                    try:
                        self._check(item)
                        observed = self._observe(item)
                        if observed != after or item.operation == "push" and item.commit != item.expected_old:
                            with self.__lock:
                                self.__active[permit] = (item, "ready")
                            failure, cancel_in_flight = self._effect(permit)
                        observed = self._observe(item)
                        if failure == "push_refused" and observed != before:
                            failure = "ref_moved"
                    except PublishError:
                        self.__journal.record_result(item.request_id, "unknown", None, receipt=receipt)
                        raise
                    status = "done" if observed == after else "not_applied" if observed == before else "unknown"
                    if failure == "ref_moved" or cancel_in_flight and observed == before:
                        status = "unknown"
                    self.__journal.record_result(item.request_id, status, observed, receipt=receipt)
                    if failure and status != "done":
                        raise PublishError(failure)
                    return {"status": status, "code": None if status == "done" else "effect_unconfirmed"}
            except team_gitops.GitOpsError as error:
                raise PublishError(error.code) from None
