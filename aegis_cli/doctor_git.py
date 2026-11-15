"""Read-only git and disk hygiene for aegis doctor. The report names owner actions and does not delete, prune, gc, rewrite refs, or change doctor's exit code."""
from __future__ import annotations
import os, re, shlex, time, types
from pathlib import Path
from aegis_core import approval_policy, gitsafe, human_gate, primitives, team
from aegis_cli import doctor_git_observe as observe, doctor_git_report as rendering
# Retain the pre-split public names; calls use the owning module's bindings.
from aegis_cli.doctor_git_observe import (
    MAX_HEAVY, PEAK_BYTES, RESERVE_BYTES, LARGE_BYTES, MAX_DEPTH, MAX_ENTRIES, PROBE, descriptor_support)
from aegis_cli.doctor_git_report import SCHEMA, DISPLAY_MAX, VALUE_MAX, display

MAX_WORKTREES, GIT_STDOUT_LIMIT, GIT_STDERR_LIMIT, _REF_CAP, _CAPTURE_SLACK = 256, 64 * 1024, 1024, 1024, 256
(_PRESENCE, _BRANCH, _EXPIRE, _WORKTREES, _OBJECTS) = (
    ("rev-parse", "--is-inside-work-tree"), ("rev-parse", "--abbrev-ref", "HEAD"),
    ("config", "--get", "gc.worktreePruneExpire"), ("worktree", "list", "--porcelain", "-z"), ("count-objects", "-v"))
_GIT_COMMANDS = (_PRESENCE, _BRANCH, _EXPIRE, _WORKTREES, _OBJECTS)
(_invoke, _head_commit, _read_policy, _blob_sizes, _read_object, _read_leases, _list_refs, _custody) = (
    gitsafe.run, gitsafe.head_commit, approval_policy.read_policy, gitsafe.blob_sizes, gitsafe.read_object,
    team.read_leases, gitsafe.list_refs, gitsafe.custody)
_SIGNER_LINE = re.compile(r"\b(?:ssh-|ecdsa-|sk-)[A-Za-z0-9@.-]* [A-Za-z0-9+/=]{20,}")
def _accepted(text):
    if not isinstance(text, str): return None, "git_failed"
    if len(text) > VALUE_MAX: return None, "value_too_long"
    if "\n" in text or "\r" in text or "\x00" in text: return None, "multiline_refused"
    return text, None

def _classify_git(exc):
    code = getattr(exc, "code", "")
    if code in ("git_timeout", "git_output_limit", "git_failed", "git_cleanup_failed"):
        return "git_failed" if code == "git_cleanup_failed" else code
    message = getattr(exc, "message", "")
    if not isinstance(message, str): return "git_failed"
    if message == "git is not installed or not on PATH" or message.startswith("cannot run git:"): return "git_missing"
    return "git_timeout" if "timed out after" in message else "git_failed"

def _git_result(command, exc):
    if command == _PRESENCE and getattr(exc, "code", "") == "git_failed":
        code = getattr(exc, "returncode", None)
        if isinstance(code, int) and not isinstance(code, bool) and code not in (0, 1):
            return types.SimpleNamespace(returncode=code, stdout=b"", stderr=b"")
    return _classify_git(exc)

def _cwd(root):
    if not isinstance(root, (str, Path)): return None
    path = Path(root)
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path): return None
    return path

def _in_custody(root, limit, produce, command=None):
    cwd = _cwd(root)
    if cwd is None or (command is not None and command not in _GIT_COMMANDS):
        return "git_failed"
    scratch, owned = observe.use_scratch(root)
    bind = getattr(scratch, "bind", None)
    if getattr(scratch, "code", "scratch_unknown") or not isinstance(bind, str):
        if owned: observe.close_fd(getattr(scratch, "fd", None))
        return "git_failed"
    try:
        with _custody(scratch=Path(bind), stdout_limit=limit, stderr_limit=GIT_STDERR_LIMIT):
            return produce(cwd)
    except gitsafe.GitError as exc:
        return _git_result(command, exc) if command is not None else _classify_git(exc)
    except human_gate.HumanGateError:
        return "git_failed"
    finally:
        if owned:
            observe.close_fd(scratch.fd)

def _run_git(root, args):
    command = tuple(args)
    return _in_custody(root, GIT_STDOUT_LIMIT, lambda cwd: _invoke(command, cwd), command)

def _one_line(data):
    if not isinstance(data, (bytes, bytearray)) or len(data) > GIT_STDOUT_LIMIT: return None, "git_output_limit"
    if data.endswith(b"\n"): data = data[:-1]
    if data.endswith(b"\r"): data = data[:-1]
    if b"\n" in data or b"\r" in data or b"\0" in data: return None, "multiline_refused"
    if len(data) > VALUE_MAX: return None, "value_too_long"
    try: text = data.decode("utf-8")
    except UnicodeError: return None, "git_failed"
    return _accepted(text)

def _parse_worktrees(data):
    if not isinstance(data, (bytes, bytearray)) or len(data) > GIT_STDOUT_LIMIT:
        return ("git_output_limit", None, None)
    fields = data.split(b"\0")
    if len(fields) > MAX_WORKTREES * 8:
        return ("git_output_limit", None, None)
    records, current = [], []
    for field in fields:
        if field == b"":
            if current:
                records.append(current)
                current = []
            if len(records) > MAX_WORKTREES:
                return ("git_output_limit", None, None)
            continue
        current.append(field)
        if len(current) > 16:
            return ("git_output_limit", None, None)
    if current:
        records.append(current)
    if len(records) > MAX_WORKTREES: return ("git_output_limit", None, None)
    if not records: return ("git_failed", None, None)
    prunable, paths = 0, []
    for record in records:
        path, is_prunable = None, False
        for field in record:
            if field.startswith(b"prunable"):
                is_prunable = True
            elif field.startswith(b"worktree "):
                if path is not None: return ("git_failed", None, None)
                path = field[len(b"worktree "):]
        if not path: return ("git_failed", None, None)
        if is_prunable:
            prunable += 1
        if path is not None:
            paths.append(os.fsdecode(path))
    return prunable, paths, None

def _object_bytes(data):
    if not isinstance(data, (bytes, bytearray)) or len(data) > GIT_STDOUT_LIMIT or data.count(b"\n") > 64: return None, "git_output_limit"
    total, seen = 0, set()
    for line in data.split(b"\n"):
        if line.endswith(b"\r"): line = line[:-1]
        if not line: continue
        if b"\n" in line or b"\r" in line or b"\0" in line or b":" not in line: return None, "git_failed"
        key, _, raw = line.partition(b":")
        if key not in (b"size", b"size-pack"): continue
        if key in seen: return None, "git_failed"
        seen.add(key)
        raw = raw.strip()
        if not raw.isdigit() or len(raw) > 12 or int(raw) > 10 ** 12: return None, "git_failed"
        total += int(raw) * 1024
    return (total, None) if seen == {b"size", b"size-pack"} else (None, "git_failed")

def _presence(root, rows, info):
    result = _run_git(root, _PRESENCE)
    if isinstance(result, str):
        rows.append(rendering.row("git_presence", "warn", result, rendering.RETRY, "git is not available for a read-only report")); return False
    if getattr(result, "returncode", 1) != 0:
        rows.append(rendering.row("git_presence", "warn", "not_a_repository", rendering.RETRY, "the workspace is not a git repository")); return False
    text, code = _one_line(getattr(result, "stdout", b""))
    if text == "true":
        info["present"] = True
        rows.append(rendering.row("git_presence", "pass", "git_present", rendering.NONE, "git work tree")); return True
    if text == "false":
        rows.append(rendering.row("git_presence", "warn", "not_a_work_tree", rendering.RETRY, "git is not in a work tree")); return False
    rows.append(rendering.row("git_presence", "warn", code or "git_failed", rendering.RETRY, "git work tree state was refused")); return False

def _commit_id(value):
    if not isinstance(value, str) or len(value) not in (40, 64): return False
    return all(char in "0123456789abcdef" for char in value)

def _scoped(root, produce):
    return _in_custody(root, GIT_STDOUT_LIMIT + _CAPTURE_SLACK, lambda _cwd: produce())

def _head(root):
    return _scoped(root, lambda: _head_commit(root))

def _policy_at(root, commit):
    try:
        entry = _regular_entry(root, commit, approval_policy.CONFIG_PATH)
        if not isinstance(entry, tuple): return "policy_unavailable"
        return _read_policy(root, commit, strict=True)
    except (approval_policy.PolicyUnavailable, approval_policy.InvalidApprovalPolicy) as exc:
        return "policy_unavailable" if isinstance(exc, approval_policy.PolicyUnavailable) else "invalid_approval_policy"

def _policy(root, commit):
    return _scoped(root, lambda: _policy_at(root, commit))

def _count_signers(data):
    if not isinstance(data, (bytes, bytearray)) or len(data) > GIT_STDOUT_LIMIT:
        return "git_output_limit"
    try: text = data.decode("utf-8")
    except UnicodeError: return "signers_unavailable"
    return sum(1 for line in text.splitlines()
               if not line.lstrip().startswith("#") and _SIGNER_LINE.search(line))

def _regular_entry(root, commit, path):
    if not _commit_id(commit) or not isinstance(path, str): return "signers_unavailable"
    result = _invoke(("ls-tree", "-z", "--full-tree", commit, "--", path), root)
    if isinstance(result, str): return result
    if getattr(result, "returncode", 1) != 0: return "git_failed"
    stdout = getattr(result, "stdout", b"")
    if not isinstance(stdout, (bytes, bytearray)) or len(stdout) > GIT_STDOUT_LIMIT: return "git_output_limit"
    if not stdout: return None
    matched = None
    for record in stdout.split(b"\0"):
        if not record: continue
        meta, sep, raw = record.partition(b"\t")
        fields = meta.split()
        if not sep or len(fields) != 3: return "signers_unavailable"
        mode, kind, oid = (field.decode("ascii", "replace") for field in fields)
        if os.fsdecode(raw) != path: continue
        if kind != "blob" or mode not in ("100644", "100755") or not _commit_id(oid): return "signers_unavailable"
        matched = (mode, oid)
    return matched if matched is not None else "signers_unavailable"

def _signers_at(root, commit):
    found = _regular_entry(root, commit, human_gate.ALLOWED_SIGNERS)
    if not isinstance(found, tuple): return found if isinstance(found, str) else "signers_unavailable"
    _mode, blob = found
    sizes = _blob_sizes(root, (blob,))
    size = sizes.get(blob) if isinstance(sizes, dict) else None
    if isinstance(size, bool) or not isinstance(size, int) or size < 0: return "signers_unavailable"
    if size > GIT_STDOUT_LIMIT: return "git_output_limit"
    return _count_signers(_read_object(root, blob, size))

def _signers(root, commit):
    result = _scoped(root, lambda: _signers_at(root, commit))
    return result if not isinstance(result, str) or result in ("git_output_limit", "git_timeout", "git_failed", "git_missing") else "signers_unavailable"

def _branch_name(root):
    result = _run_git(root, _BRANCH)
    if isinstance(result, str) or getattr(result, "returncode", 1) != 0:
        return None, result if isinstance(result, str) else "git_failed"
    return _one_line(getattr(result, "stdout", b""))

def _policy_view(policy):
    if not isinstance(policy, dict) or not policy or len(policy) > approval_policy.MAX_PATTERNS:
        return None, "invalid_approval_policy"
    view = []
    for pattern, mode in policy.items():
        pat, pcode = _accepted(pattern if isinstance(pattern, str) else "")
        mod, mcode = _accepted(mode if isinstance(mode, str) else "")
        if pcode or mcode or not pat or mod not in approval_policy.MODES:
            return None, pcode or mcode or "invalid_approval_policy"
        shown, scode = rendering.display(pat)
        if scode or not shown:
            return None, scode or "invalid_approval_policy"
        if shown != pat: shown = rendering.digest(pat)
        view.append({"pattern": shown, "mode": mod})
    return view, None

def _signer_row(root, commit, rows):
    count = _signers(root, commit)
    if count in ("git_output_limit", "git_timeout", "git_failed", "git_missing"):
        detail = "signing keys exceeded their cap" if count == "git_output_limit" else "signing keys could not be read"
        rows.append(rendering.row("signers", "warn", count, rendering.RETRY, detail))
        return
    if count == "signers_unavailable" or isinstance(count, bool) or not isinstance(count, int) or count < 0:
        rows.append(rendering.row("signers", "warn", "signers_unavailable", rendering.SIGNERS, "signing keys could not be counted"))
        return
    if count == 0:
        rows.append(rendering.row("signers", "warn", "signers_absent", rendering.SIGNERS, "no signing key is present"))
        return
    rows.append(rendering.row("signers", "pass", "signers_present", rendering.NONE, "signing keys are present"))

def _approval_rows(root, rows, info):
    commit = _head(root)
    if not _commit_id(commit):
        code = commit if commit in ("git_timeout", "git_failed", "git_missing", "git_output_limit") else "no_head" if commit is None else "git_failed"
        detail = "HEAD has no commit" if code == "no_head" else "HEAD could not be read"
        rows.append(rendering.row("approvals", "warn", code, rendering.RETRY, detail))
        return
    target, tcode = _branch_name(root)
    if tcode:
        action = rendering.RENAME if tcode in ("multiline_refused", "value_too_long") else rendering.RETRY
        rows.append(rendering.row("approvals", "warn", tcode, action, "the current branch name was refused"))
        return
    if not target or target == "HEAD":
        rows.append(rendering.row("approvals", "warn", "branch_unknown", rendering.RETRY, "the current branch is unknown")); return
    policy = _policy(root, commit)
    if isinstance(policy, str):
        transport = policy in ("policy_unavailable", "git_timeout", "git_failed", "git_missing", "git_output_limit")
        action = rendering.RETRY if transport else rendering.SUGGEST
        detail = "the map could not be read" if transport else "the map was refused"
        rows.append(rendering.row("approvals", "warn", policy, action, detail))
        return
    if policy is None:
        rows.append(rendering.row("approvals", "warn", "no_approval_map", rendering.SUGGEST, "no approval map is committed"))
        return
    view, pcode = _policy_view(policy)
    if pcode or view is None:
        rows.append(rendering.row("approvals", "warn", pcode or "invalid_approval_policy", rendering.SUGGEST, "the map was refused"))
        return
    effective = approval_policy.mode_for(policy, target)
    shown_target = None
    if target:
        shown_target, scode = rendering.display(target)
        if scode or not shown_target:
            shown_target = None
        elif shown_target != target: shown_target = rendering.digest(target)
    info["approval_modes"] = {"present": True, "effective": effective, "target": shown_target, "patterns": view}
    label = effective if isinstance(effective, str) else "unknown"
    rows.append(rendering.row("approvals", "pass", "approval_mode", rendering.NONE, f"effective approval mode {label}"))
    if any(item["mode"] == "signature" for item in view) or effective == "signature":
        _signer_row(root, commit, rows)

def _capped(found):
    if not hasattr(found, "__len__"): return None
    return "git_output_limit" if len(found) > _REF_CAP else None

def _take(found):
    if isinstance(found, (str, bytes)) or found is None: return "git_failed"
    rows = []
    try:
        for item in found:
            rows.append(item)
            if len(rows) > _REF_CAP: return "git_output_limit"
    except (OSError, ValueError, gitsafe.GitError):
        return "git_failed"
    return rows

def _bad_lease(lane, ref, oid):
    return team.Unreadable(lane if isinstance(lane, str) else "", ref if isinstance(ref, str) else "", oid if isinstance(oid, str) else "", "unreadable")

def _load_leases(root, snapshot):
    leases, bad, prefix = [], [], team.LANES_REF + "/"
    for item in snapshot:
        ref, oid = item if isinstance(item, tuple) and len(item) == 2 else ("", "")
        lane = ref[len(prefix):] if isinstance(ref, str) and ref.startswith(prefix) else ""
        if not team.valid_lane(lane) or not _commit_id(oid):
            bad.append(_bad_lease(lane, ref, oid)); continue
        try:
            data = _read_object(root, oid, team.MAX_LEASE_BYTES)
            if not isinstance(data, (bytes, bytearray)) or len(data) > team.MAX_LEASE_BYTES:
                bad.append(_bad_lease(lane, ref, oid)); continue
            leases.append(team.parse_lease(bytes(data), lane, oid))
        except (gitsafe.GitError, team.LeaseFormatError, ValueError, team.TeamUsageError):
            bad.append(_bad_lease(lane, ref, oid))
    return team.LeaseSet(tuple(leases), tuple(bad))

def _leases_at(root):
    snapshot = _refs_at(root, team.LANES_REF)
    return snapshot if isinstance(snapshot, str) else _load_leases(root, snapshot)

def _leases(root):
    return _scoped(root, lambda: _leases_at(root))

def _remember_branch(lease, live):
    branch = getattr(lease, "branch", None)
    if not isinstance(branch, str):
        return False
    if branch.startswith("refs/heads/"):
        branch = branch[len("refs/heads/"):]
    original, code = _accepted(branch)
    if code or not human_gate.is_branch_name(original):
        return False
    live.add(original)
    return True

def _one_lease(lease, rows, now, live, index):
    if not team.valid_lane(lease.lane):
        rows.append(rendering.row("lease", "warn", "lease_unreadable", rendering.DONE, "a lane ref is not a readable lease"))
        return False
    shown, code = rendering.display(lease.lane)
    if code or not shown:
        rows.append(rendering.row("lease", "warn", code or "lease_unreadable", rendering.DONE, "a lane ref is not a readable lease"))
        return False
    label = shown if shown == lease.lane else rendering.digest(lease.lane)
    if lease.expired(now):
        rows.append(rendering.row(f"lease:{index}", "warn", "expired_lease", rendering.DONE, f"lease {label} is expired"))
        return _remember_branch(lease, live)
    if not _remember_branch(lease, live):
        rows.append(rendering.row(f"lease:{index}", "warn", "lease_branch_unknown", rendering.RETRY, "a live lease has an unknown branch")); return False
    rows.append(rendering.row(f"lease:{index}", "pass", "live_lease", rendering.NONE, f"lease {label} is live"))
    return True

def _lease_rows(root, rows, now):
    found = _leases(root)
    if isinstance(found, str):
        rows.append(rendering.row("leases", "warn", found, rendering.RETRY, "lane leases could not be read"))
        return False, set()
    live, complete = set(), True
    for index, lease in enumerate(found.leases):
        if not _one_lease(lease, rows, now, live, index):
            complete = False
    for bad in found.unreadable:
        complete = False
        lane = getattr(bad, "lane", None)
        detail = "lease %s is unreadable" % lane if rendering.visible(lane) else "a lane ref is not a readable lease"
        if not rendering.visible(lane) and isinstance(lane, str) and lane:
            detail = "lease %s is unreadable" % rendering.digest(lane)
        rows.append(rendering.row("lease_unreadable", "warn", "lease_unreadable", _lease_action(bad), detail))
    return complete, live

def _lease_action(bad):
    lane, ref, oid = getattr(bad, "lane", None), getattr(bad, "ref", None), getattr(bad, "oid", None)
    action = None
    if team.valid_lane(lane) and _commit_id(oid) and rendering.visible(lane):
        action = "owner action: aegis team release %s --expect %s (doctor does not release the lease)" % (lane, oid)
    elif rendering.visible(ref) and _commit_id(oid):
        action = "owner action: git update-ref -d %s %s (doctor does not delete refs)" % (shlex.quote(ref), oid)
    if action and rendering.display(action, max_len=VALUE_MAX) == (action, None): return action
    label = ref if isinstance(ref, str) else (lane if isinstance(lane, str) else "")
    expected = oid if _commit_id(oid) else "unknown"
    return "owner action: privately inspect git for-each-ref refs/aegis/lanes for ref hash %s, expected %s; then git update-ref -d REF OID (doctor does not delete refs)" % (rendering.digest(label), expected)

def _refs_at(root, prefix):
    found = _list_refs(root, prefix)
    limited = _capped(found)
    if limited: return limited
    return _take(found)

def _refs(root, prefix):
    return _scoped(root, lambda: _refs_at(root, prefix))

def _branch_rows(root, rows, knowledge):
    complete, live = knowledge
    found = _refs(root, "refs/heads/lane")
    if isinstance(found, str):
        rows.append(rendering.row("lane_branches", "warn", found, rendering.RETRY, "lane branches could not be read"))
        return
    for index, (ref, _oid) in enumerate(found):
        if not isinstance(ref, str) or not ref.startswith("refs/heads/lane/"):
            continue
        original, code = _accepted(ref[len("refs/heads/"):])
        if code or not original:
            rows.append(rendering.row(f"lane_branch:{index}", "warn", code or "multiline_refused", rendering.RENAME,
                             "a lane branch name was refused"))
            continue
        if not complete or original in live:
            continue
        shown, scode = rendering.display(original)
        if scode or not shown:
            rows.append(rendering.row(f"lane_branch:{index}", "warn", scode or "multiline_refused", rendering.RENAME,
                             "a lane branch name was refused"))
            continue
        label = shown if shown == original else rendering.digest(original)
        rows.append(rendering.row(f"lane_branch:{index}", "warn", "stale_lane_branch", rendering.STALE,
                         f"lane branch {label} has no live lease"))

def _prune_row(root, rows, info):
    result = _run_git(root, _EXPIRE)
    if isinstance(result, str):
        rows.append(rendering.row("worktree_prune_expire", "warn", result, rendering.RETRY, "prune expiry could not be read"))
        return
    status = getattr(result, "returncode", 1)
    if type(status) is not int or status not in (0, 1):
        rows.append(rendering.row("worktree_prune_expire", "warn", "git_failed", rendering.RETRY, "prune expiry could not be read"))
        return
    if status == 1:
        rows.append(rendering.row("worktree_prune_expire", "warn", "prune_expire_unset", rendering.SET_NEVER, "gc.worktreePruneExpire is unset"))
        return
    text, code = _one_line(getattr(result, "stdout", b""))
    if code or not text:
        rows.append(rendering.row("worktree_prune_expire", "warn", code or "git_failed", rendering.SET_NEVER, "prune expiry was refused"))
        return
    shown, scode = rendering.display(text)
    if scode or not shown:
        rows.append(rendering.row("worktree_prune_expire", "warn", scode or "git_failed", rendering.SET_NEVER, "prune expiry was refused"))
        return
    info["worktree_prune_expire"] = shown
    if text == "never":
        rows.append(rendering.row("worktree_prune_expire", "pass", "prune_expire_never", rendering.NONE, "gc.worktreePruneExpire is never"))
        return
    rows.append(rendering.row("worktree_prune_expire", "warn", "prune_expire_set", rendering.SET_NEVER, f"gc.worktreePruneExpire is {shown}"))

def _worktree_rows(root, rows, info):
    result = _run_git(root, _WORKTREES)
    if isinstance(result, str) or getattr(result, "returncode", 1) != 0:
        rows.append(rendering.row("worktrees", "warn", result if isinstance(result, str) else "git_failed", rendering.RETRY, "worktrees could not be listed"))
        return
    stdout = getattr(result, "stdout", b"")
    parsed = _parse_worktrees(stdout)
    if isinstance(parsed[0], str):
        rows.append(rendering.row("worktrees", "warn", parsed[0], rendering.RETRY, "worktree listing was refused"))
        return
    prunable, paths, _code = parsed
    info["prunable_count"] = prunable
    if prunable:
        rows.append(rendering.row("worktrees", "warn", "prunable_worktrees", rendering.NO_PRUNE, f"{prunable} worktrees are prunable"))
    else:
        rows.append(rendering.row("worktrees", "pass", "worktrees", rendering.NONE, "no worktree is prunable"))
    outside = False
    for raw in paths:
        text, code = _accepted(raw)
        if code or not text:
            rows.append(rendering.row("worktrees", "warn", code or "multiline_refused", rendering.OUTSIDE, "a worktree path was refused"))
            continue
        if not os.path.isabs(text) or not primitives.is_within(text, root, unresolvable=False):
            outside = True
    if outside:
        rows.append(rendering.row("worktrees", "warn", "outside_root", rendering.OUTSIDE, "a linked worktree is outside the workspace"))

def _object_rows(root, rows):
    result = _run_git(root, _OBJECTS)
    if isinstance(result, str) or getattr(result, "returncode", 1) != 0:
        rows.append(rendering.row("git_objects", "warn", result if isinstance(result, str) else "git_failed", rendering.RETRY, "object size could not be read"))
        return
    total, code = _object_bytes(getattr(result, "stdout", b""))
    if code:
        rows.append(rendering.row("git_objects", "warn", code, rendering.RETRY, "object size was refused"))
        return
    limit = observe.LARGE_BYTES if isinstance(observe.LARGE_BYTES, int) and not isinstance(observe.LARGE_BYTES, bool) else 1
    if total >= limit:
        rows.append(rendering.row("git_objects", "warn", "large_git_objects", rendering.GC, "the git object store is large"))
        return
    rows.append(rendering.row("git_objects", "pass", "git_objects", rendering.NONE, "git objects are within the report budget"))

def _git_details(root, rows, info, now):
    _approval_rows(root, rows, info)
    _prune_row(root, rows, info)
    _worktree_rows(root, rows, info)
    _branch_rows(root, rows, _lease_rows(root, rows, now))
    _object_rows(root, rows)

def collect(root, *, tier=None, now=None):
    if tier not in ("A", "B", "C"):
        tier = None
    if isinstance(now, bool) or not isinstance(now, int):
        now = int(time.time())
    rows = [rendering.row("trust_tier", "pass" if tier else "warn", "trust_tier", rendering.NONE if tier else rendering.RETRY,
                 f"trust tier {tier}" if tier else "trust tier unavailable")]
    info = {"present": False, "worktree_prune_expire": None, "prunable_count": None, "approval_modes": None}
    disk = {"free": None, "reserve": observe.RESERVE_BYTES, "peak": observe.PEAK_BYTES, "budget_slots": None, "scratch": None}
    trusted = observe.trusted_root(root)
    if trusted is None:
        rows.append(rendering.row("workspace", "warn", "unreadable_path", rendering.RETRY, "the workspace root could not be opened"))
    else:
        scratch = observe.validated_scratch(trusted)
        token = observe.SCRATCH.set(scratch)
        try:
            if _presence(trusted, rows, info):
                _git_details(trusted, rows, info, now)
            observe.disk_rows(rows, disk, scratch)
            observe.scratch_rows(rows, disk, scratch)
            observe.walk(trusted, rows)
        finally:
            observe.SCRATCH.reset(token)
            if scratch.owned:
                observe.close_fd(scratch.fd)
    status = "warn" if any(row["status"] == "warn" for row in rows) else "pass"
    return {
        "schema": SCHEMA, "status": status, "exit_effect": "advisory", "affects_exit": False,
        "doctor_exit_effect": "unchanged", "trust_tier": tier, "rows": rows,
        "approval_modes": info["approval_modes"], "disk": disk,
        "git": {"present": info["present"], "worktree_prune_expire": info["worktree_prune_expire"],
                "prunable_count": info["prunable_count"]},
    }

def _unavailable():
    row = rendering.row("git_hygiene", "warn", "git_hygiene_unavailable", rendering.RETRY, "git hygiene report unavailable")
    return {
        "schema": SCHEMA, "status": "warn", "exit_effect": "advisory", "affects_exit": False,
        "doctor_exit_effect": "unchanged", "trust_tier": None, "rows": [row], "approval_modes": None,
        "disk": {"free": None, "reserve": observe.RESERVE_BYTES, "peak": observe.PEAK_BYTES, "budget_slots": None, "scratch": None},
        "git": {"present": False, "worktree_prune_expire": None, "prunable_count": None},
    }

def _warning_count(summary, added):
    current = summary.get("warnings", 0)
    if isinstance(current, bool) or not isinstance(current, int):
        current = 0
    summary["warnings"] = current + added

def _tier_of(payload):
    if not isinstance(payload, dict):
        return None
    gate = payload.get("human_gate")
    if isinstance(gate, dict) and gate.get("tier") in ("A", "B", "C"):
        return gate["tier"]
    return None

def with_report(payload, root, ui, use_json):
    del ui
    try:
        report = collect(root, tier=_tier_of(payload))
    except Exception:
        report = _unavailable()
    if not isinstance(payload, dict):
        payload = {}
    out = dict(payload)
    summary = dict(out.get("summary") or {})
    _warning_count(summary, sum(1 for row in report["rows"] if row.get("status") == "warn"))
    out["summary"] = summary
    out["git_hygiene"] = report
    if not use_json:
        rendering.print_report(report)
    return out
