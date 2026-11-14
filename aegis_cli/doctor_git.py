"""Read-only git and disk hygiene for aegis doctor. The report names owner actions and does not delete, prune, gc, rewrite refs, or change doctor's exit code."""
from __future__ import annotations
import contextvars, errno, hashlib, os, re, shlex, shutil, stat, sys, time, types
from pathlib import Path
from aegis_core import approval_policy, gitsafe, human_gate, primitives, team
from aegis_core.redaction import CANDIDATE_TOKEN_RE, is_high_entropy_secret, redact_command_secrets
from aegis_core.storage_confined import ConfinedFileError, confined_file, descriptor_supported
(SCHEMA, MAX_HEAVY, PEAK_BYTES, RESERVE_BYTES, LARGE_BYTES, MAX_DEPTH, MAX_ENTRIES, MAX_WORKTREES,
 GIT_STDOUT_LIMIT, GIT_STDERR_LIMIT, DISPLAY_MAX, VALUE_MAX, PROBE, _REF_CAP, _CAPTURE_SLACK) = (
    "aegis.doctor.git/v1", 3, 8 * 1024 * 1024 * 1024, 8 * 1024 * 1024 * 1024, 50 * 1024 * 1024, 3, 256, 256,
    64 * 1024, 1024, 160, 512, "aegis-doctor-probe", 1024, 256)
(_PRESENCE, _BRANCH, _EXPIRE, _WORKTREES, _OBJECTS) = (
    ("rev-parse", "--is-inside-work-tree"), ("rev-parse", "--abbrev-ref", "HEAD"),
    ("config", "--get", "gc.worktreePruneExpire"), ("worktree", "list", "--porcelain", "-z"), ("count-objects", "-v"))
_GIT_COMMANDS = (_PRESENCE, _BRANCH, _EXPIRE, _WORKTREES, _OBJECTS)
(_NONE, _RETRY, _NO_DELETE, _NO_FOLLOW, _NO_PRUNE, _SET_NEVER, _SUGGEST, _SIGNERS, _DONE, _STALE, _DISK, _GC,
 _INSPECT, _RENAME, _PLATFORM, _OUTSIDE, _SCRATCH_ACT) = (
    "owner action: none", "owner action: retry aegis doctor",
    "owner action: review the path and remove it yourself (doctor does not delete)",
    "owner action: replace the symlink with a real directory or file (doctor does not follow links)",
    "owner action: git worktree prune once if the count stays above zero (doctor does not prune)",
    "owner action: git config gc.worktreePruneExpire never (doctor does not write git config)",
    "owner action: commit an approvals map with main signature, develop review, release/** review and * none (doctor does not write configuration)",
    "owner action: add a key to allowed_signers (doctor does not write key material)",
    "owner action: aegis team gc (doctor does not delete leases)",
    "owner action: delete the stale lane branch after the lane is done (doctor does not delete refs)",
    "owner action: free disk until a heavy slot fits (doctor does not delete)",
    "owner action: git gc when objects are large (doctor does not run git gc)",
    "owner action: inspect unmeasured workspace paths manually",
    "owner action: rename the path to a short single line",
    "owner action: run doctor where directory descriptors are available",
    "owner action: leave the path unopened (doctor does not open paths outside the workspace)",
    "owner action: set AEGIS_SCRATCH to a private directory outside the workspace (doctor does not create it)")
_SCRATCH_CODES = frozenset({"scratch_unusable", "multiline_refused", "value_too_long"})
(_invoke, _confined, _scandir, _head_commit, _read_policy, _tree_blobs, _blob_sizes, _read_object, _read_leases,
 _list_refs, _custody) = (
    gitsafe.run, confined_file, os.scandir, gitsafe.head_commit, approval_policy.read_policy, gitsafe.tree_blobs,
    gitsafe.blob_sizes, gitsafe.read_object, team.read_leases, gitsafe.list_refs, gitsafe.custody)
_HELD = contextvars.ContextVar("aegis_doctor_held", default=None)
_SCRATCH = contextvars.ContextVar("aegis_doctor_scratch", default=None)
_SIGNER_LINE = re.compile(r"\b(?:ssh-|ecdsa-|sk-)[A-Za-z0-9@.-]* [A-Za-z0-9+/=]{20,}")
_DETAIL_FALLBACKS = {
    "live_lease": "a lane lease is live", "expired_lease": "a lane lease is expired",
    "lease_unreadable": "a lane ref is not a readable lease",
    "stale_lane_branch": "a lane branch has no live lease",
}
def descriptor_support():
    return descriptor_supported()
def _disk_usage(path):
    if isinstance(path, int) and not isinstance(path, bool):
        info = os.statvfs(path)
        return types.SimpleNamespace(total=info.f_blocks * info.f_frsize, used=0, free=info.f_bavail * info.f_frsize)
    return shutil.disk_usage(path)
def _scratch_env():
    return os.environ
def _marked_secret(token):
    bare = token
    while True:
        if is_high_entropy_secret(bare): return True
        nxt = bare.replace("REDACTED", "")
        if not nxt or nxt == bare: return False
        bare = nxt
def _digest(text):
    raw = text.encode("utf-8", "surrogateescape") if isinstance(text, str) else b""
    return hashlib.sha256(raw).hexdigest()[:12]
def _visible(text):
    if not isinstance(text, str) or not text or any(ch in text for ch in " \n\r\x00"): return None
    shown, code = display(text)
    return text if code is None and shown == text else None
def display(text, *, single_line=True, max_len=DISPLAY_MAX):
    if not isinstance(text, str): text = str(text)
    if len(text) > VALUE_MAX: return None, "value_too_long"
    if single_line and ("\n" in text or "\r" in text or "\x00" in text): return None, "multiline_refused"
    safe = primitives.sanitize_display(text, max_len=None).encode("utf-8", "backslashreplace").decode("utf-8")
    redacted = safe
    for _step in range(max(1, len(safe) + 1)):
        nxt = redact_command_secrets(redacted)
        nxt = CANDIDATE_TOKEN_RE.sub(lambda match: "[REDACTED_HIENT]" if _marked_secret(match.group(0)) else match.group(0), nxt)
        if nxt == redacted: break
        redacted = nxt
    if not isinstance(max_len, int) or isinstance(max_len, bool) or len(redacted) <= max_len:
        return redacted, None
    stop = max_len - 3
    for marker in ("[REDACTED_HIENT]", "[REDACTED]", "REDACTED"):
        begin = redacted.rfind(marker, 0, stop + len(marker))
        if begin != -1 and begin < stop < begin + len(marker):
            stop = begin
            break
    return redacted[:max(0, stop)].rstrip() + "...", None
def _accepted(text):
    if not isinstance(text, str): return None, "git_failed"
    if len(text) > VALUE_MAX: return None, "value_too_long"
    if "\n" in text or "\r" in text or "\x00" in text: return None, "multiline_refused"
    return text, None
def _row(row_id, status, code, owner_action, detail):
    row = {"id": row_id, "status": status, "code": code, "owner_action": owner_action, "detail": detail}
    for key in ("id", "code", "detail", "owner_action"):
        shown, refused = display(row[key], max_len=VALUE_MAX if key == "owner_action" else DISPLAY_MAX)
        if (refused or not shown) and key != "detail":
            return {"id": "git_hygiene", "status": "warn", "code": "git_failed", "owner_action": _RETRY, "detail": "report field unavailable"}
        row[key] = _DETAIL_FALLBACKS.get(row["code"], "finding detail unavailable") if key == "detail" and (refused or not shown or shown != row[key]) else shown
    return row
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
def _close_fd(fd):
    if isinstance(fd, bool) or not isinstance(fd, int) or fd < 0: return
    try: os.close(fd)
    except OSError: return
def _stat_pair(path):
    try: info = os.stat(path)
    except OSError: return None
    return (info.st_dev, info.st_ino)
def _bind_fd(fd, dev, ino):
    if not isinstance(fd, int) or isinstance(fd, bool) or fd < 0 or os.name != "posix" or not os.path.isdir("/proc/self/fd"): return None
    link = "/proc/self/fd/%d" % fd
    return link if _stat_pair(link) == (dev, ino) else None
def _private_dir(info):
    mode = info.st_mode
    if not hasattr(os, "geteuid") or info.st_uid != os.geteuid(): return False
    if mode & (stat.S_IWOTH | stat.S_ISVTX | stat.S_IWGRP): return False
    return bool(mode & stat.S_IWUSR and mode & stat.S_IXUSR)
def _acl_free(fd):
    if sys.platform != "linux" or not callable(getattr(os, "getxattr", None)): return False
    for name in ("system.posix_acl_access", "system.posix_acl_default"):
        try: os.getxattr(fd, name)
        except (OSError, ValueError, NotImplementedError) as exc:
            if getattr(exc, "errno", None) == errno.ENODATA: continue
        return False
    return True
def _inside_root(link, root):
    root_id, seen, current = _stat_pair(root), set(), link
    if root_id is None: return True
    for _step in range(64):
        ident = _stat_pair(current)
        if ident is None or ident in seen or ident == root_id: return True
        seen.add(ident)
        parent = _stat_pair(current + "/..")
        if parent is None or parent == ident: return parent is None
        current += "/.."
    return True
def _scratch_ok(root, fd, dev, ino):
    if not isinstance(fd, int) or isinstance(fd, bool): return None
    try: info = os.fstat(fd)
    except OSError: return None
    if (info.st_dev, info.st_ino) != (dev, ino) or not stat.S_ISDIR(info.st_mode): return None
    if not _private_dir(info) or not _acl_free(fd) or any(_stat_pair(path) == (dev, ino) for path in ("/", "/tmp", "/var/tmp")): return None
    link = _bind_fd(fd, dev, ino)
    if link is None or _inside_root(link, root): return None
    if not os.access(link, os.W_OK | os.X_OK, effective_ids=True): return None
    return link
def _scratch_bad(code):
    return types.SimpleNamespace(path=None, fd=None, dev=None, ino=None, code=code, shown=None, owned=False, bind=None)
def _hold_scratch(path):
    fd = None
    try:
        with _confined(Path(path), (PROBE,)) as handle:
            parent = getattr(handle, "_parent", None)
            if isinstance(parent, bool) or not isinstance(parent, int) or parent < 0: raise ConfinedFileError("io")
            fd = os.dup(parent)
        os.set_inheritable(fd, False); info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode): raise ConfinedFileError("io")
        return fd, info.st_dev, info.st_ino
    except BaseException:
        _close_fd(fd)
        raise
def _validated_scratch(root):
    kind, value = _scratch_choice()
    if kind != "path": return _scratch_bad(value if value in _SCRATCH_CODES else "scratch_unusable")
    if not descriptor_support(): return _scratch_bad("scratch_unknown")
    try: fd, dev, ino = _hold_scratch(value)
    except (ConfinedFileError, OSError, ValueError): return _scratch_bad("scratch_unknown")
    accepted = False
    try:
        bind = _scratch_ok(root, fd, dev, ino)
        shown, refused = display(value)
        if not isinstance(bind, str) or refused or not shown: return _scratch_bad(refused or "scratch_unknown")
        accepted = True
        return types.SimpleNamespace(path=value, fd=fd, dev=dev, ino=ino, code=None, shown=shown, owned=True, bind=bind)
    except (OSError, ValueError, NotImplementedError):
        return _scratch_bad("scratch_unknown")
    finally:
        if not accepted: _close_fd(fd)
def _cwd(root):
    if not isinstance(root, (str, Path)): return None
    path = Path(root)
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path): return None
    return path
def _use_scratch(root):
    bound = _SCRATCH.get()
    if bound is not None:
        return bound, False
    return _validated_scratch(root), True
def _in_custody(root, limit, produce, command=None):
    cwd = _cwd(root)
    if cwd is None or (command is not None and command not in _GIT_COMMANDS):
        return "git_failed"
    scratch, owned = _use_scratch(root)
    bind = getattr(scratch, "bind", None)
    if getattr(scratch, "code", "scratch_unknown") or not isinstance(bind, str):
        if owned: _close_fd(getattr(scratch, "fd", None))
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
            _close_fd(scratch.fd)
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
        rows.append(_row("git_presence", "warn", result, _RETRY, "git is not available for a read-only report")); return False
    if getattr(result, "returncode", 1) != 0:
        rows.append(_row("git_presence", "warn", "not_a_repository", _RETRY, "the workspace is not a git repository")); return False
    text, code = _one_line(getattr(result, "stdout", b""))
    if text == "true":
        info["present"] = True
        rows.append(_row("git_presence", "pass", "git_present", _NONE, "git work tree")); return True
    if text == "false":
        rows.append(_row("git_presence", "warn", "not_a_work_tree", _RETRY, "git is not in a work tree")); return False
    rows.append(_row("git_presence", "warn", code or "git_failed", _RETRY, "git work tree state was refused")); return False
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
        shown, scode = display(pat)
        if scode or not shown:
            return None, scode or "invalid_approval_policy"
        if shown != pat: shown = _digest(pat)
        view.append({"pattern": shown, "mode": mod})
    return view, None
def _signer_row(root, commit, rows):
    count = _signers(root, commit)
    if count in ("git_output_limit", "git_timeout", "git_failed", "git_missing"):
        detail = "signing keys exceeded their cap" if count == "git_output_limit" else "signing keys could not be read"
        rows.append(_row("signers", "warn", count, _RETRY, detail))
        return
    if count == "signers_unavailable" or isinstance(count, bool) or not isinstance(count, int) or count < 0:
        rows.append(_row("signers", "warn", "signers_unavailable", _SIGNERS, "signing keys could not be counted"))
        return
    if count == 0:
        rows.append(_row("signers", "warn", "signers_absent", _SIGNERS, "no signing key is present"))
        return
    rows.append(_row("signers", "pass", "signers_present", _NONE, "signing keys are present"))
def _approval_rows(root, rows, info):
    commit = _head(root)
    if not _commit_id(commit):
        code = commit if commit in ("git_timeout", "git_failed", "git_missing", "git_output_limit") else "no_head" if commit is None else "git_failed"
        detail = "HEAD has no commit" if code == "no_head" else "HEAD could not be read"
        rows.append(_row("approvals", "warn", code, _RETRY, detail))
        return
    target, tcode = _branch_name(root)
    if tcode:
        action = _RENAME if tcode in ("multiline_refused", "value_too_long") else _RETRY
        rows.append(_row("approvals", "warn", tcode, action, "the current branch name was refused"))
        return
    if not target or target == "HEAD":
        rows.append(_row("approvals", "warn", "branch_unknown", _RETRY, "the current branch is unknown")); return
    policy = _policy(root, commit)
    if isinstance(policy, str):
        transport = policy in ("policy_unavailable", "git_timeout", "git_failed", "git_missing", "git_output_limit")
        action = _RETRY if transport else _SUGGEST
        detail = "the map could not be read" if transport else "the map was refused"
        rows.append(_row("approvals", "warn", policy, action, detail))
        return
    if policy is None:
        rows.append(_row("approvals", "warn", "no_approval_map", _SUGGEST, "no approval map is committed"))
        return
    view, pcode = _policy_view(policy)
    if pcode or view is None:
        rows.append(_row("approvals", "warn", pcode or "invalid_approval_policy", _SUGGEST, "the map was refused"))
        return
    effective = approval_policy.mode_for(policy, target)
    shown_target = None
    if target:
        shown_target, scode = display(target)
        if scode or not shown_target:
            shown_target = None
        elif shown_target != target: shown_target = _digest(target)
    info["approval_modes"] = {"present": True, "effective": effective, "target": shown_target, "patterns": view}
    label = effective if isinstance(effective, str) else "unknown"
    rows.append(_row("approvals", "pass", "approval_mode", _NONE, f"effective approval mode {label}"))
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
        rows.append(_row("lease", "warn", "lease_unreadable", _DONE, "a lane ref is not a readable lease"))
        return False
    shown, code = display(lease.lane)
    if code or not shown:
        rows.append(_row("lease", "warn", code or "lease_unreadable", _DONE, "a lane ref is not a readable lease"))
        return False
    label = shown if shown == lease.lane else _digest(lease.lane)
    if lease.expired(now):
        rows.append(_row(f"lease:{index}", "warn", "expired_lease", _DONE, f"lease {label} is expired"))
        return _remember_branch(lease, live)
    if not _remember_branch(lease, live):
        rows.append(_row(f"lease:{index}", "warn", "lease_branch_unknown", _RETRY, "a live lease has an unknown branch")); return False
    rows.append(_row(f"lease:{index}", "pass", "live_lease", _NONE, f"lease {label} is live"))
    return True
def _lease_rows(root, rows, now):
    found = _leases(root)
    if isinstance(found, str):
        rows.append(_row("leases", "warn", found, _RETRY, "lane leases could not be read"))
        return False, set()
    live, complete = set(), True
    for index, lease in enumerate(found.leases):
        if not _one_lease(lease, rows, now, live, index):
            complete = False
    for bad in found.unreadable:
        complete = False
        lane = getattr(bad, "lane", None)
        detail = "lease %s is unreadable" % lane if _visible(lane) else "a lane ref is not a readable lease"
        if not _visible(lane) and isinstance(lane, str) and lane:
            detail = "lease %s is unreadable" % _digest(lane)
        rows.append(_row("lease_unreadable", "warn", "lease_unreadable", _lease_action(bad), detail))
    return complete, live
def _lease_action(bad):
    lane, ref, oid = getattr(bad, "lane", None), getattr(bad, "ref", None), getattr(bad, "oid", None)
    action = None
    if team.valid_lane(lane) and _commit_id(oid) and _visible(lane):
        action = "owner action: aegis team release %s --expect %s (doctor does not release the lease)" % (lane, oid)
    elif _visible(ref) and _commit_id(oid):
        action = "owner action: git update-ref -d %s %s (doctor does not delete refs)" % (shlex.quote(ref), oid)
    if action and display(action, max_len=VALUE_MAX) == (action, None): return action
    label = ref if isinstance(ref, str) else (lane if isinstance(lane, str) else "")
    expected = oid if _commit_id(oid) else "unknown"
    return "owner action: privately inspect git for-each-ref refs/aegis/lanes for ref hash %s, expected %s; then git update-ref -d REF OID (doctor does not delete refs)" % (_digest(label), expected)
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
        rows.append(_row("lane_branches", "warn", found, _RETRY, "lane branches could not be read"))
        return
    for index, (ref, _oid) in enumerate(found):
        if not isinstance(ref, str) or not ref.startswith("refs/heads/lane/"):
            continue
        original, code = _accepted(ref[len("refs/heads/"):])
        if code or not original:
            rows.append(_row(f"lane_branch:{index}", "warn", code or "multiline_refused", _RENAME,
                             "a lane branch name was refused"))
            continue
        if not complete or original in live:
            continue
        shown, scode = display(original)
        if scode or not shown:
            rows.append(_row(f"lane_branch:{index}", "warn", scode or "multiline_refused", _RENAME,
                             "a lane branch name was refused"))
            continue
        label = shown if shown == original else _digest(original)
        rows.append(_row(f"lane_branch:{index}", "warn", "stale_lane_branch", _STALE,
                         f"lane branch {label} has no live lease"))
def _prune_row(root, rows, info):
    result = _run_git(root, _EXPIRE)
    if isinstance(result, str):
        rows.append(_row("worktree_prune_expire", "warn", result, _RETRY, "prune expiry could not be read"))
        return
    status = getattr(result, "returncode", 1)
    if type(status) is not int or status not in (0, 1):
        rows.append(_row("worktree_prune_expire", "warn", "git_failed", _RETRY, "prune expiry could not be read"))
        return
    if status == 1:
        rows.append(_row("worktree_prune_expire", "warn", "prune_expire_unset", _SET_NEVER, "gc.worktreePruneExpire is unset"))
        return
    text, code = _one_line(getattr(result, "stdout", b""))
    if code or not text:
        rows.append(_row("worktree_prune_expire", "warn", code or "git_failed", _SET_NEVER, "prune expiry was refused"))
        return
    shown, scode = display(text)
    if scode or not shown:
        rows.append(_row("worktree_prune_expire", "warn", scode or "git_failed", _SET_NEVER, "prune expiry was refused"))
        return
    info["worktree_prune_expire"] = shown
    if text == "never":
        rows.append(_row("worktree_prune_expire", "pass", "prune_expire_never", _NONE, "gc.worktreePruneExpire is never"))
        return
    rows.append(_row("worktree_prune_expire", "warn", "prune_expire_set", _SET_NEVER, f"gc.worktreePruneExpire is {shown}"))
def _worktree_rows(root, rows, info):
    result = _run_git(root, _WORKTREES)
    if isinstance(result, str) or getattr(result, "returncode", 1) != 0:
        rows.append(_row("worktrees", "warn", result if isinstance(result, str) else "git_failed", _RETRY, "worktrees could not be listed"))
        return
    stdout = getattr(result, "stdout", b"")
    parsed = _parse_worktrees(stdout)
    if isinstance(parsed[0], str):
        rows.append(_row("worktrees", "warn", parsed[0], _RETRY, "worktree listing was refused"))
        return
    prunable, paths, _code = parsed
    info["prunable_count"] = prunable
    if prunable:
        rows.append(_row("worktrees", "warn", "prunable_worktrees", _NO_PRUNE, f"{prunable} worktrees are prunable"))
    else:
        rows.append(_row("worktrees", "pass", "worktrees", _NONE, "no worktree is prunable"))
    outside = False
    for raw in paths:
        text, code = _accepted(raw)
        if code or not text:
            rows.append(_row("worktrees", "warn", code or "multiline_refused", _OUTSIDE, "a worktree path was refused"))
            continue
        if not os.path.isabs(text) or not primitives.is_within(text, root, unresolvable=False):
            outside = True
    if outside:
        rows.append(_row("worktrees", "warn", "outside_root", _OUTSIDE, "a linked worktree is outside the workspace"))
def _object_rows(root, rows):
    result = _run_git(root, _OBJECTS)
    if isinstance(result, str) or getattr(result, "returncode", 1) != 0:
        rows.append(_row("git_objects", "warn", result if isinstance(result, str) else "git_failed", _RETRY, "object size could not be read"))
        return
    total, code = _object_bytes(getattr(result, "stdout", b""))
    if code:
        rows.append(_row("git_objects", "warn", code, _RETRY, "object size was refused"))
        return
    limit = LARGE_BYTES if isinstance(LARGE_BYTES, int) and not isinstance(LARGE_BYTES, bool) else 1
    if total >= limit:
        rows.append(_row("git_objects", "warn", "large_git_objects", _GC, "the git object store is large"))
        return
    rows.append(_row("git_objects", "pass", "git_objects", _NONE, "git objects are within the report budget"))
def _git_details(root, rows, info, now):
    _approval_rows(root, rows, info)
    _prune_row(root, rows, info)
    _worktree_rows(root, rows, info)
    _branch_rows(root, rows, _lease_rows(root, rows, now))
    _object_rows(root, rows)
def _trusted_root(root):
    try:
        path = Path(root)
        if not path.is_absolute(): path = Path.cwd() / path
        resolved = path.resolve()
    except (OSError, ValueError, RuntimeError): return None
    if not resolved.is_dir(): return None
    return resolved
def _disk_rows(rows, disk, scratch):
    target = scratch.fd if not scratch.code else None
    if target is None:
        rows.append(_row("disk_budget", "warn", "disk_unknown", _SCRATCH_ACT, "scratch filesystem is unknown"))
        return
    try:
        free = _disk_usage(target).free
    except (OSError, AttributeError, ValueError):
        rows.append(_row("disk_budget", "warn", "disk_unknown", _RETRY, "scratch filesystem is unknown"))
        return
    if isinstance(free, bool) or not isinstance(free, int):
        rows.append(_row("disk_budget", "warn", "disk_unreadable", _RETRY, "free space could not be read"))
        return
    peak = PEAK_BYTES if isinstance(PEAK_BYTES, int) and not isinstance(PEAK_BYTES, bool) and PEAK_BYTES > 0 else 1
    reserve = RESERVE_BYTES if isinstance(RESERVE_BYTES, int) and not isinstance(RESERVE_BYTES, bool) and RESERVE_BYTES >= 0 else 0
    heavy = MAX_HEAVY if isinstance(MAX_HEAVY, int) and not isinstance(MAX_HEAVY, bool) and MAX_HEAVY > 0 else 1
    slots = min(heavy, max(0, (free - reserve) // peak))
    disk.update(free=free, reserve=reserve, peak=peak, budget_slots=slots)
    if slots <= 0:
        rows.append(_row("disk_budget", "warn", "disk_low", _DISK, "no heavy slot fits in the free space"))
        return
    rows.append(_row("disk_budget", "pass", "disk_budget", _NONE, f"{slots} heavy slots fit"))
def _scratch_choice():
    env = _scratch_env()
    selected, join = None, None
    if hasattr(env, "__contains__") and "AEGIS_SCRATCH" in env:
        selected, join = env["AEGIS_SCRATCH"], "as-is"
    elif hasattr(env, "__contains__") and "XDG_CACHE_HOME" in env and env["XDG_CACHE_HOME"]:
        selected, join = env["XDG_CACHE_HOME"], "xdg"
    else:
        for key in ("HOME", "USERPROFILE"):
            if hasattr(env, "__contains__") and key in env and env[key]:
                selected, join = env[key], "home"
                break
    if not isinstance(selected, str) or not selected:
        return ("code", "scratch_unusable")
    if len(selected) > VALUE_MAX:
        return ("code", "value_too_long")
    if "\n" in selected or "\r" in selected or "\x00" in selected:
        return ("code", "multiline_refused")
    if join == "as-is":
        path = selected
    elif join == "xdg":
        path = str(Path(selected) / "aegis")
    else:
        path = str(Path(selected) / ".cache" / "aegis")
    if len(path) > VALUE_MAX or "\n" in path or "\r" in path or "\x00" in path:
        return ("code", "multiline_refused" if "\n" in path or "\r" in path or "\x00" in path else "value_too_long")
    if not os.path.isabs(path) or ".." in Path(path).parts:
        return ("code", "scratch_unusable")
    return ("path", path)
def _scratch_rows(rows, disk, scratch):
    if scratch.code:
        unknown = scratch.code == "scratch_unknown"
        detail = "scratch location is unknown" if unknown else "scratch location was refused"
        rows.append(_row("scratch", "warn", scratch.code, _SCRATCH_ACT, detail))
        return
    disk["scratch"] = scratch.shown
    rows.append(_row("scratch", "pass", "scratch_outside", _NONE, "scratch is outside the workspace"))
def _directory_identity(root, parts):
    with _confined(Path(root), (*(parts or ()), PROBE)) as handle:
        info = handle.parent_stat()
    return (info.st_dev, info.st_ino)
class _Snap:
    def __init__(self, name, mode, size):
        self.name = name
        self.mode = mode
        self.size = size
class _Bad:
    def __init__(self, code):
        self.code = code
_OVERFLOW = object()
def _held_descriptor():
    fd = getattr(_HELD.get(), "_parent", None)
    if isinstance(fd, bool) or not isinstance(fd, int) or fd < 0:
        return None
    return fd
def _entry_cap():
    return MAX_ENTRIES if isinstance(MAX_ENTRIES, int) and not isinstance(MAX_ENTRIES, bool) and MAX_ENTRIES > 0 else 1
def _read_dir(target, limit):
    iterator = _scandir(target)
    found = []
    try:
        source = iterator if hasattr(iterator, "__next__") else iter(iterator)
        for _ in range(limit + 1):
            try:
                found.append(next(source))
            except StopIteration:
                break
        return found
    finally:
        close = getattr(iterator, "close", None)
        if close is not None: close()
def _snapshot(entry):
    fd = _held_descriptor()
    if fd is None:
        return entry
    name = getattr(entry, "name", None)
    if not isinstance(name, str):
        return _Bad("value_too_long")
    try:
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except OSError:
        return _Bad("unreadable_path")
    return _Snap(name, info.st_mode, info.st_size)
def _list_checked(root, parts, limit):
    path = Path(root).joinpath(*parts)
    with _confined(Path(root), (*(parts or ()), PROBE)) as handle:
        token = _HELD.set(handle)
        try:
            fd = _held_descriptor()
            target = fd if fd is not None else path
            held_id = None
            if fd is not None:
                try:
                    info = os.fstat(fd)
                except OSError:
                    return "unreadable_path"
                held_id = (info.st_dev, info.st_ino)
            for _attempt in (0, 1):
                before = _directory_identity(root, parts)
                if held_id is not None and before != held_id:
                    continue
                try:
                    entries = _read_dir(target, limit)
                except OSError:
                    return "unreadable_path"
                after = _directory_identity(root, parts)
                if held_id is not None:
                    if after != held_id:
                        continue
                elif before != after:
                    continue
                overflow = len(entries) > limit
                chosen = [_snapshot(entry) for entry in entries[:limit]]
                if overflow:
                    chosen.append(_OVERFLOW)
                return chosen
            return "path_changed"
        finally:
            _HELD.reset(token)
def _entry_name(entry):
    name = getattr(entry, "name", None)
    if not isinstance(name, str) or not 1 <= len(name) <= 255:
        return None, "value_too_long"
    if name in (".", "..") or any(char in name for char in ("/", "\\", "\x00", "\n", "\r")):
        return None, "multiline_refused"
    shown, code = display(name)
    return (_digest(name) if shown and shown != name else shown), code
def _path_refusal(code, label):
    action = {
        "path_changed": _RETRY, "scan_capped": _INSPECT, "depth_capped": _INSPECT, "symlink_refused": _NO_FOLLOW,
        "descriptor_unsupported": _PLATFORM, "unreadable_path": _INSPECT,
        "multiline_refused": _RENAME, "value_too_long": _RENAME,
    }.get(code, _RETRY)
    detail = {
        "path_changed": "a directory changed while it was listed",
        "scan_capped": "the workspace listing reached its entry cap",
        "depth_capped": "a directory was not measured beyond the scan depth",
        "symlink_refused": "a symlink was not followed",
        "descriptor_unsupported": "untrusted paths were not opened",
        "unreadable_path": "a directory could not be read",
        "multiline_refused": "a directory entry was refused",
        "value_too_long": "a directory entry was refused",
    }.get(code, "a path was refused")
    if label and label != "workspace":
        shown, refused = display(str(label))
        if refused is None and shown:
            detail = f"{detail} ({shown})"
    return _row("disk_walk", "warn", code, action, detail)
def _file_rows(root, parts, name, shown, mode, size, rows, state, depth):
    if stat.S_ISLNK(mode):
        rows.append(_row("disk_walk", "warn", "symlink_refused", _NO_FOLLOW, f"symlink {shown} was not followed"))
        return
    limit = LARGE_BYTES if isinstance(LARGE_BYTES, int) and not isinstance(LARGE_BYTES, bool) else 1
    if stat.S_ISREG(mode) and size >= limit:
        rows.append(_row("disk_walk", "warn", "large_path", _NO_DELETE, f"large file {shown}"))
        return
    depth_limit = MAX_DEPTH if isinstance(MAX_DEPTH, int) and not isinstance(MAX_DEPTH, bool) else 1
    if stat.S_ISDIR(mode):
        if depth + 1 >= depth_limit or state["capped"]:
            rows.append(_path_refusal("depth_capped" if depth + 1 >= depth_limit else "scan_capped", shown))
        else:
            _walk_dir(root, parts + (name,), rows, state, depth + 1, shown)
def _consider(root, parts, entry, rows, state, depth):
    if isinstance(entry, _Bad):
        rows.append(_path_refusal(entry.code, "workspace"))
        return
    shown, code = _entry_name(entry)
    if code or not shown:
        rows.append(_path_refusal(code or "value_too_long", "workspace"))
        return
    if isinstance(entry, _Snap):
        _file_rows(root, parts, entry.name, shown, entry.mode, entry.size, rows, state, depth)
        return
    try:
        linked = bool(entry.is_symlink())
    except OSError:
        rows.append(_path_refusal("unreadable_path", shown))
        return
    if linked:
        rows.append(_row("disk_walk", "warn", "symlink_refused", _NO_FOLLOW, f"symlink {shown} was not followed"))
        return
    try:
        info = entry.stat(follow_symlinks=False)
    except OSError:
        rows.append(_path_refusal("unreadable_path", shown))
        return
    _file_rows(root, parts, entry.name, shown, info.st_mode, info.st_size, rows, state, depth)
def _walk_dir(root, parts, rows, state, depth, label):
    if state["capped"]: return
    cap = _entry_cap()
    if state["entries"] + state["hold"] >= cap:
        probe = []
        if parts:
            try: probe = _list_checked(root, parts, 0)
            except ConfinedFileError as exc: probe = exc
        if probe:
            state["capped"] = True
            rows.append(_path_refusal(probe if isinstance(probe, str) else "scan_capped" if isinstance(probe, list) else _confined_code(probe), label))
        return
    remaining = cap - state["entries"] - state["hold"]
    state["hold"] += remaining
    try:
        listed = _list_checked(root, parts, remaining)
    except ConfinedFileError as exc:
        rows.append(_path_refusal(_confined_code(exc), label))
        return
    finally:
        state["hold"] -= remaining
    if isinstance(listed, str):
        rows.append(_path_refusal(listed, label))
        return
    body, overflow = [], False
    for entry in listed:
        if entry is _OVERFLOW:
            overflow = True
            break
        body.append(entry)
    state["hold"] += len(body); local = len(body)
    try:
        for entry in body:
            if state["entries"] >= cap:
                if not state["capped"]:
                    state["capped"] = True; rows.append(_path_refusal("scan_capped", label))
                return
            state["hold"] -= 1
            local -= 1
            state["entries"] += 1
            _consider(root, parts, entry, rows, state, depth)
        if overflow and not state["capped"]:
            state["capped"] = True
            rows.append(_path_refusal("scan_capped", label))
    finally:
        state["hold"] -= local
def _confined_code(exc):
    reason = getattr(exc, "reason", "")
    return "symlink_refused" if reason == "unsafe" else "descriptor_unsupported" if reason == "unsupported" else "unreadable_path"
def _walk(root, rows):
    if not descriptor_support():
        rows.append(_row("disk_walk", "warn", "descriptor_unsupported", _PLATFORM, "untrusted paths were not opened"))
        return
    _walk_dir(root, (), rows, {"entries": 0, "capped": False, "hold": 0}, 0, "workspace")
def collect(root, *, tier=None, now=None):
    if tier not in ("A", "B", "C"):
        tier = None
    if isinstance(now, bool) or not isinstance(now, int):
        now = int(time.time())
    rows = [_row("trust_tier", "pass" if tier else "warn", "trust_tier", _NONE if tier else _RETRY,
                 f"trust tier {tier}" if tier else "trust tier unavailable")]
    info = {"present": False, "worktree_prune_expire": None, "prunable_count": None, "approval_modes": None}
    disk = {"free": None, "reserve": RESERVE_BYTES, "peak": PEAK_BYTES, "budget_slots": None, "scratch": None}
    trusted = _trusted_root(root)
    if trusted is None:
        rows.append(_row("workspace", "warn", "unreadable_path", _RETRY, "the workspace root could not be opened"))
    else:
        scratch = _validated_scratch(trusted)
        token = _SCRATCH.set(scratch)
        try:
            if _presence(trusted, rows, info):
                _git_details(trusted, rows, info, now)
            _disk_rows(rows, disk, scratch)
            _scratch_rows(rows, disk, scratch)
            _walk(trusted, rows)
        finally:
            _SCRATCH.reset(token)
            if scratch.owned:
                _close_fd(scratch.fd)
    status = "warn" if any(row["status"] == "warn" for row in rows) else "pass"
    return {
        "schema": SCHEMA, "status": status, "exit_effect": "advisory", "affects_exit": False,
        "doctor_exit_effect": "unchanged", "trust_tier": tier, "rows": rows,
        "approval_modes": info["approval_modes"], "disk": disk,
        "git": {"present": info["present"], "worktree_prune_expire": info["worktree_prune_expire"],
                "prunable_count": info["prunable_count"]},
    }
def _unavailable():
    row = _row("git_hygiene", "warn", "git_hygiene_unavailable", _RETRY, "git hygiene report unavailable")
    return {
        "schema": SCHEMA, "status": "warn", "exit_effect": "advisory", "affects_exit": False,
        "doctor_exit_effect": "unchanged", "trust_tier": None, "rows": [row], "approval_modes": None,
        "disk": {"free": None, "reserve": RESERVE_BYTES, "peak": PEAK_BYTES, "budget_slots": None, "scratch": None},
        "git": {"present": False, "worktree_prune_expire": None, "prunable_count": None},
    }
def _print_report(report, stream=None):
    out = sys.stdout if stream is None else stream
    print("Git and disk hygiene (report only; doctor does not delete, prune, gc or rewrite refs):", file=out)
    for row in report.get("rows", ()):
        status = row.get("status") if row.get("status") in ("pass", "warn") else "warn"
        ident, icode = display(str(row.get("id", "")), single_line=True)
        detail, dcode = display(str(row.get("detail", "")), single_line=True)
        action, acode = display(str(row.get("owner_action", "")), single_line=True, max_len=VALUE_MAX)
        if icode or dcode or acode or not ident or not detail or not action:
            print(f"  [{status}] refused", file=out)
            continue
        print(f"  [{status}] {ident}: {detail}; {action}", file=out)
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
        _print_report(report)
    return out
