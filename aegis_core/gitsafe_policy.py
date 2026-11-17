"""Pure Git request rules and bounded object readers below the issued runner."""
from __future__ import annotations

import os
from pathlib import Path
import re
from types import MappingProxyType

from aegis_core.errors import AegisError
from aegis_core.primitives import sanitize_display, key_within, real_key
from aegis_core.redaction import redact_insight_text

__all__ = [
    "BASE_ENV",
    "LOCAL_ENV",
    "GitError",
    "outside_roots",
    "OID",
    "READ_SHAPES",
    "strict_refuse",
    "bounded_args",
    "strict_root",
    "strict_environment",
    "full_oid",
    "ref_name",
    "read_shape",
    "IDENTITY_ENV",
    "ENVIRON_TYPE",
    "classify_ambient",
    "format_ambient_names",
    "AMBIENT_ENV",
    "LOCATION_ENV",
    "Environment",
    "environment_refusal",
    "environment_layer",
    "merge_inputs",
    "identity_environment",
    "private_headers",
    "private_object",
    "private_objects",
    "request_environment",
]

ENVIRON_TYPE = type(os.environ)
BASE_ENV = {"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_ALLOW_PROTOCOL": "", "GIT_NO_LAZY_FETCH": "1", "LC_ALL": "C"}
LOCAL_ENV = frozenset((
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
    "GIT_OBJECT_DIRECTORY", "GIT_DIR", "GIT_WORK_TREE", "GIT_IMPLICIT_WORK_TREE", "GIT_GRAFT_FILE",
    "GIT_INDEX_FILE", "GIT_NO_REPLACE_OBJECTS", "GIT_REPLACE_REF_BASE", "GIT_PREFIX", "GIT_SHALLOW_FILE",
    "GIT_COMMON_DIR",
))
class GitError(AegisError):
    """The facade's error hierarchy, shared before any runner can be issued."""
    __module__ = "aegis_core.gitsafe"
CustodyRefusal = GitError
def outside_roots(path, roots):
    """Check both spellings; an unresolved executable or fence fails closed."""
    if type(path) is not str or not 0 < len(path) <= 16384 or not os.path.isabs(path): return False
    target = real_key(path)
    spelling = os.path.normcase(os.path.abspath(path))
    return target is not None and all(not key_within(candidate, root)
        for root in roots for candidate in (target, spelling))
OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
READ_SHAPES = frozenset((
    ("version",), ("read-tree", "--empty"), ("write-tree",),
    ("ls-files", "--cached", "--others", "--exclude-standard", "-z"),
    ("update-index", "-z", "--index-info"),
    ("ls-files", "--stage", "--debug", "-z"),
    ("pack-objects", "--stdout"), ("unpack-objects", "-q", "--strict"),
    ("cat-file", "--batch"), ("cat-file", "--batch-check"),
    ("rev-parse", "--verify", "--quiet", "HEAD"), ("rev-parse", "--show-object-format"),
    ("rev-parse", "--git-path", "index"),
    ("rev-parse", "--git-common-dir", "--show-prefix", "--is-shallow-repository", "--show-toplevel"),
    *(("rev-parse", option) for option in ("--git-common-dir", "--show-prefix", "--show-toplevel")),
    ("check-attr", "-z", "--stdin", "filter", "text", "eol", "ident", "working-tree-encoding", "crlf"),
    ("config", "--null", "--get-regexp", r"^core\.(autocrlf|safecrlf|filemode|symlinks|eol|trustctime|checkstat)$"),
    ("config", "--null", "--name-only", "--get-regexp", r"^filter\."),
    ("config", "--show-scope", "--null", "--name-only", "--get-regexp", r"^merge\..+\.driver$"),
))
def strict_refuse():
    raise CustodyRefusal("Strict lane Git command refused.", code="git_custody_refused",
        next_action="Use the lane Git APIs or the CAS fast-forward writer.", process_started=False)
def bounded_args(args):
    from itertools import islice
    if type(args) not in (tuple, list) or len(args) > 512: strict_refuse()
    frozen = args if type(args) is tuple else tuple(islice(args, 513))
    if len(frozen) > 512 or any(type(a) is not str or len(a) > 16384 or "\0" in a for a in frozen): strict_refuse()
    return frozen
def strict_root(cwd):
    if type(cwd) not in (str, type(Path())): strict_refuse()
    text = str(cwd)
    if len(text) > 16384 or "\0" in text or not os.path.isabs(text) or ".." in Path(text).parts: strict_refuse()
    return text
def strict_environment(env, limit=512, *, environ_type=ENVIRON_TYPE):
    frozen, refusal = classify_ambient(env, limit=limit, refuse_keys=False, environ_type=environ_type)
    if refusal is not None: strict_refuse()
    return frozen
def full_oid(value):
    return type(value) is str and len(value) in (40, 64) and OID.fullmatch(value) is not None
def ref_name(value):
    return (type(value) is str and len(value) <= 240 and value.startswith("refs/")
            and not any(ord(c) < 33 or ord(c) > 126 or c in "~^:?*[\\" for c in value)
            and ".." not in value and "@{" not in value
            and all(p and not p.startswith(".") and not p.endswith((".", ".lock")) for p in value.split("/")))
def _literal_path(value):
    if value.startswith(":(literal)"): value = value[len(":(literal)"):]
    return (bool(value) and not value.startswith("/") and len(value) <= 4096
            and all(p not in ("", ".", "..", ".git") for p in value.split("/")))
def read_shape(args):
    if args in READ_SHAPES: return True
    if args[:4] == ("check-attr", "-z", "--stdin", "--source"):
        return (len(args) == 11 and full_oid(args[4])
                and args[5:] == ("filter", "text", "eol", "ident", "working-tree-encoding", "crlf"))
    if len(args) == 2 and args[0] == "read-tree": return full_oid(args[1])
    if len(args) == 2 and args[0] == "check-ref-format": return ref_name(args[1])
    if len(args) == 3 and args[0] == "cat-file" and args[1] in ("blob", "tree", "commit", "-t"): return full_oid(args[2])
    if len(args) == 3 and args[:2] == ("for-each-ref", "--format=%(objectname)%00%(symref)%00%(refname)"): return ref_name(args[2])
    if len(args) == 4 and args[:2] == ("merge-base", "--is-ancestor"): return all(full_oid(x) for x in args[2:])
    if args[:1] == ("ls-tree",):
        if len(args) == 3 and args[1] == "-r": return full_oid(args[2])
        rest = args[2:] if args[1:2] == ("-z",) else args[1:]
        return len(rest) == 3 and full_oid(rest[0]) and rest[1] == "--" and _literal_path(rest[2])
    if args[:1] == ("hash-object",):
        return (len(args) == 4 and args[1:3] == ("-w", "--stdin")
                and args[3].startswith("--path=") and _literal_path(args[3][7:]))
    if args[:1] == ("commit-tree",):
        return (4 <= len(args) <= 18 and len(args) % 2 == 0 and full_oid(args[1])
                and all(args[i] == "-p" and full_oid(args[i + 1]) for i in range(2, len(args), 2)))
    if args[:3] == ("rev-list", "--objects", "--no-object-names"): return len(args) == 6 and full_oid(args[3]) and args[4:] == ("--not", "--all")
    if args[:4] == ("rev-list", "--reverse", "--topo-order", "--no-merges"): return len(args) == 5 and len(args[4].split("..")) == 2 and all(full_oid(x) for x in args[4].split(".."))
    if args[:4] == ("merge-tree", "--write-tree", "--name-only", "-z"):
        rest = args[4:]
        if rest and rest[0].startswith("--merge-base="):
            if not full_oid(rest[0][13:]): return False
            rest = rest[1:]
        return len(rest) == 2 and all(full_oid(x) for x in rest)
    return False
IDENTITY_ENV = frozenset("GIT_" + role + "_" + field for role in ("AUTHOR", "COMMITTER")
                          for field in ("NAME", "EMAIL", "DATE"))
_AMBIENT_REDIRECTS = LOCAL_ENV - {"GIT_NO_REPLACE_OBJECTS", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT"}
def format_ambient_names(names):
    """Format caller-bounded names, never values, in the shared diagnostic order."""
    displayed = []
    for key in names:
        canonical = sanitize_display(key, max_len=None)
        shown = sanitize_display(redact_insight_text(canonical, max_len=max(1, len(canonical))), max_len=256)
        displayed.append("GIT_TRACE* (" + shown + ")" if key.upper().startswith("GIT_TRACE") and key.upper() not in ("GIT_TRACE", "GIT_TRACE2", "GIT_TRACE2_EVENT", "GIT_TRACE2_PERF") else shown)
    return ", ".join(displayed)
def classify_ambient(env, *, limit=512, refuse_keys=True, environ_type=ENVIRON_TYPE):
    """Pure bounded snapshot and deterministic refusal; values never enter diagnostics."""
    from itertools import islice
    if type(env) not in (dict, MappingProxyType, environ_type, Environment): return {}, ("git_custody_refused", "Strict lane Git command refused.", "Use the lane Git APIs or the CAS fast-forward writer.")
    if len(env) > limit: return {}, ("ambient_environment_too_large", "Ambient environment has too many variables.", "Reduce the environment to at most 512 variables, then retry.")
    try:
        frozen = dict(islice(env.items(), limit + 1))
    except (KeyError, RuntimeError):
        return {}, ("ambient_environment_changed", "Ambient environment changed during inspection.", "Stabilize the environment, then retry.")
    if len(frozen) > limit: return {}, ("ambient_environment_too_large", "Ambient environment has too many variables.", "Reduce the environment to at most 512 variables, then retry.")
    if any(type(k) is not str or type(v) is not str for k, v in frozen.items()): return {}, ("git_custody_refused", "Strict lane Git command refused.", "Use the lane Git APIs or the CAS fast-forward writer.")
    if any(len(key) > 256 for key in frozen): return {}, ("ambient_environment_too_large", "Ambient environment variable name exceeds its limit.", "Shorten every environment variable name to at most 256 characters, then retry.")
    if any(len(value) > 65536 for value in frozen.values()): return {}, ("ambient_environment_too_large", "Ambient environment value exceeds its limit.", "Reduce every environment value to at most 65,536 characters, then retry.")
    if any("\0" in key or "\0" in value for key, value in frozen.items()): return {}, ("git_custody_refused", "Strict lane Git command refused.", "Use the lane Git APIs or the CAS fast-forward writer.")
    names = sorted(key for key in frozen if refuse_keys and (key.upper().startswith("GIT_TRACE") or key.upper() in _AMBIENT_REDIRECTS))
    if not names: return frozen, None
    label = format_ambient_names(names)
    return {}, ("ambient_git_environment", "Ambient Git environment refused: " + label + ".", "Unset " + label + " in the environment, then retry.")
AMBIENT_ENV = frozenset(("HOME", "PATH", "SSH_AUTH_SOCK", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "TZ", "TMPDIR"))
_PROGRAM_ENV = frozenset(("GIT_CONFIG", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_SSH_VARIANT", "GIT_EXEC_PATH", "GIT_ASKPASS", "GIT_EXTERNAL_DIFF", "GIT_DIFF_OPTS", "GIT_PAGER", "GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "GIT_PROXY_COMMAND", "PAGER", "EDITOR", "VISUAL", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "GH_PAGER", "GH_BROWSER", "GH_EDITOR", "GH_CONFIG_DIR", "BROWSER", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT", "PYTHONBREAKPOINT", "PYTHONWARNINGS", "BASH_ENV", "ENV", "PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB", "NODE_OPTIONS", "NODE_PATH", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "GCONV_PATH", "LOCPATH", "OPENSSL_CONF", "OPENSSL_MODULES", "MALLOC_TRACE"))
LOCATION_ENV = LOCAL_ENV - {"GIT_NO_REPLACE_OBJECTS", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT"} | {"GIT_NAMESPACE"}
_EFFECT_ENV = dict(GIT_CONFIG_NOSYSTEM="1", GIT_ASKPASS="", SSH_ASKPASS="", SSH_ASKPASS_REQUIRE="never", GIT_PAGER="", PAGER="", GIT_EDITOR="false", GIT_SEQUENCE_EDITOR="false", GIT_SSH_VARIANT="ssh")
class Environment(dict):
    """Mutable input envelope, with immutable transport-issued binding provenance."""
    __module__ = "aegis_core.gitsafe_run"
    __slots__ = ("__proof",)
    def __init__(self, values, proof):
        super().__init__(values)
        self.__proof = MappingProxyType(proof)
    @property
    def _proof(self): return self.__proof
    @property
    def roots(self): return self._proof["roots"]
    @property
    def root(self): return self.roots[0]
    @property
    def source(self): return self._proof["source"]
    @property
    def repository(self): return self._proof["repository"]
    @property
    def origin(self): return self._proof["origin"]
    def with_vars(self, values, *, replace=False, environ_type=ENVIRON_TYPE):
        # This is an untrusted edit, not fresh provenance or a validation bypass.
        values = environment_layer(values, allowed=None, error=GitError, code="git_custody_refused",
            environ_type=self._proof.get("environ_type", environ_type))
        if len(self) > 512 or not replace and len(self) + sum(k not in self for k in values) > 512: strict_refuse()
        changed = Environment({} if replace else self, dict(self._proof))
        changed.update(values)
        return changed
def environment_refusal(error, code, path=None):
    messages = {"effect_command_refused": ("Git operation effect command refused.", "Select an executable outside every custody root; no effect process started.") if path is None else ("strict effects require a native executable: " + sanitize_display(redact_insight_text(sanitize_display(path, max_len=None), max_len=16384), max_len=256) + " is a script; configure the real binary", "Configure the real native binary outside every custody root; no effect process started."),
        "git_failed": ("Git operation executable is unavailable.", "Restore the selected executable installation; no effect process started."),
        "unsupported_effect_platform": ("Descriptor-bound execution is unavailable on this platform.", "Use a platform with descriptor-relative no-follow opens and procfs execution; no effect process started."),
        "effect_environment_limit": ("Git operation effect environment exceeds supported limits.", "Reduce the supplied environment to bounded string entries; no effect process started."),
        "ambient_git_environment": ("Ambient Git environment refused.", "Unset Git program and repository selectors, then retry."),
        "git_custody_refused": ("Strict lane Git command refused.", "Use the lane Git APIs or the CAS fast-forward writer.")}
    message, action = messages[code]
    raise error(message, code=code, next_action=action, process_started=False, effect_process_started=False) from None
def environment_layer(source, *, allowed, error, code, environ_type=ENVIRON_TYPE):
    """Validate retained strings before copying; selector keys are never filtered away."""
    if type(source) not in (dict, MappingProxyType, environ_type, Environment): environment_refusal(error, "effect_environment_limit")
    result = {}
    try:
        for key, value in source.items():
            if type(key) is not str: environment_refusal(error, "effect_environment_limit")
            upper = key[:256].upper()
            if upper in _PROGRAM_ENV | LOCATION_ENV or upper.startswith(("GIT_TRACE", "GIT_CONFIG_", "LD_", "DYLD_", "BASH_FUNC_")):
                environment_refusal(error, code)
            if allowed is not None and key not in allowed: continue
            if (len(result) >= 512 or type(value) is not str or not key or len(key) > 256 or len(value) > 65536 or "\0" in key or "\0" in value or "=" in key):
                environment_refusal(error, "effect_environment_limit")
            try:
                os.fsencode(key)
                os.fsencode(value)
            except UnicodeError:
                environment_refusal(error, "effect_environment_limit")
            result[key] = value
    except (KeyError, RuntimeError):
        environment_refusal(error, "effect_environment_limit")
    return result
def merge_inputs(*sources, error):
    """Bound combined input maps before inserting any additional entry."""
    merged = {}
    for source in sources:
        for key, value in source.items():
            if key not in merged and len(merged) >= 512: environment_refusal(error, "effect_environment_limit")
            merged[key] = value
    return merged
def request_environment(source, *, profile="ordinary", scope=None, overrides=None, base=None,
                        roots=(), root=None, repository=None, bindings=None, error=GitError, scrub=False, allowed=None, kind=None, ambient=None, environ_type=ENVIRON_TYPE):
    """The sole constructor: ordinary compatibility or strict/effect provenance."""
    if profile not in ("ordinary", "strict/effect"): strict_refuse()
    if profile == "ordinary":
        if type(source) is Environment: strict_refuse()
        result = {k: v for k, v in source.items() if not (scrub and k.upper() in LOCAL_ENV)}
        result.update(BASE_ENV if base is None else base)
        result.update(scope or {})
        result.update(overrides or {})
        result.update(bindings or {})
        return result
    ambient = (type(source) is environ_type) if ambient is None else bool(ambient)
    inherited = source._proof if type(source) is Environment else None
    if inherited and kind is not None and kind != inherited["kind"]: strict_refuse()
    kind = kind or (inherited["kind"] if inherited else "git")
    if kind not in ("git", "lane", "gh"): strict_refuse()
    if type(roots) not in (tuple, list) or len(roots) > 64: environment_refusal(error, "effect_environment_limit")
    for path in (*((root,) if root is not None else ()), *roots):
        strict_root(path)
        if real_key(path) is None: strict_refuse()
    fences = tuple(dict.fromkeys(value for path in ((root,) if root is not None else ()) + tuple(roots)
        for value in (os.path.normcase(os.path.abspath(path)), real_key(path)) if value is not None))
    if not fences and not inherited: strict_refuse()
    if inherited:
        checked, refusal = classify_ambient(source, refuse_keys=False, environ_type=environ_type)
        if refusal: environment_refusal(error, "effect_environment_limit")
        changes = {k: v for k, v in checked.items() if inherited["values"].get(k) != v}
        values = environment_layer({k: v for k, v in source.source.items() if k in checked}, allowed=allowed, error=error, code="ambient_git_environment", environ_type=environ_type)
        values = merge_inputs(values, environment_layer(changes, allowed=allowed, error=error, code="git_custody_refused", environ_type=environ_type), error=error)
        fences = tuple(dict.fromkeys((*fences, *inherited["roots"]))) if repository is not None else tuple(dict.fromkeys((*inherited["roots"], *fences)))
        repository = repository if repository is not None else inherited["repository"]
    else:
        if repository is None:
            checked, refusal = classify_ambient(source, environ_type=environ_type)
            if refusal:
                code, message, action = refusal
                raise error(message, code=code, next_action=action, process_started=False)
            source = checked
        values = environment_layer(source, allowed=AMBIENT_ENV if ambient and allowed is None else allowed, error=error, code="ambient_git_environment", environ_type=environ_type)
    for layer in (scope, overrides):
        if layer is not None: values = merge_inputs(values, environment_layer(layer, allowed=None, error=error, code="git_custody_refused", environ_type=environ_type), error=error)
    if len(values) > 512: environment_refusal(error, "effect_environment_limit")
    values["PATH"] = os.pathsep.join(p for p in values.get("PATH", os.defpath).split(os.pathsep) if outside_roots(p, fences))
    if "TMPDIR" in values and not outside_roots(values["TMPDIR"], fences):
        del values["TMPDIR"]
    owner = inherited["bindings"] if inherited and bindings is None else bindings or {}
    locations = dict(GIT_DIR=repository["dirs"][0], GIT_WORK_TREE=fences[0]) if repository is not None and kind in ("git", "lane") else {}
    fixed = {k: v for k, v in (BASE_ENV if base is None else base).items() if k != "GIT_ALLOW_PROTOCOL"}
    result = merge_inputs({"GIT_ALLOW_PROTOCOL": ""}, values, locations, owner, _EFFECT_ENV, fixed, error=error)
    proof = {"roots": fences, "source": MappingProxyType(values), "bindings": MappingProxyType(dict(owner)),
             "values": MappingProxyType(dict(result)), "repository": MappingProxyType(dict(repository)) if repository is not None else None,
             "origin": inherited["origin"] if inherited else object(), "kind": kind, "outside": outside_roots,
             "environ_type": environ_type}
    return Environment(result, proof)
def identity_environment(env, args, *, environ_type=ENVIRON_TYPE):
    supplied = {} if env is None else strict_environment(env, 6, environ_type=environ_type)
    if supplied and (not args or args[0] != "commit-tree" or set(supplied) != IDENTITY_ENV): strict_refuse()
    for key, value in supplied.items():
        if (not value or len(value) > 256 or any(ord(c) < 32 or 127 <= ord(c) < 160
                or 0xD800 <= ord(c) <= 0xDFFF or c in "<>\u2028\u2029" for c in value)
                or key.endswith("DATE") and not re.fullmatch(r"[0-9]{1,12} [+-](?:[01][0-9]|2[0-3])[0-5][0-9]", value)):
            strict_refuse()
    return supplied
def _private_capture(args, cwd, *, env, scratch, limit, stdin, runner, custody, lane):
    if lane is not None:
        if env is not None or scratch is not None: strict_refuse()
        return lane.run_checked(args, cwd, _env=env, stdout_limit=limit, stdin=stdin)
    with custody(scratch=scratch, env=env, stdout_limit=limit):
        return runner(args, cwd, stdin=stdin)
def private_headers(cwd, oids, *, env, scratch, runner, batch, custody, error, lane=None):
    """Bound and verify mixed object metadata; missing is an explicit query result."""
    if type(oids) not in (tuple, list) or len(oids) > 20000: raise error("invalid private object request", code="invalid_object")
    if any(not full_oid(oid) for oid in oids): raise error("invalid private object request", code="invalid_object")
    wanted = list(dict.fromkeys(oids))
    if not wanted: return {}
    limit = sum(len(oid) + 33 for oid in wanted)
    out = _private_capture(batch, cwd, env=env, scratch=scratch, limit=limit,
        stdin=("\n".join(wanted) + "\n").encode("ascii"), runner=runner, custody=custody, lane=lane).stdout
    if len(out) > limit: raise error("invalid private object", code="invalid_object")
    lines = out.split(b"\n")
    if len(lines) != len(wanted) + 1 or lines[-1]: raise error("invalid private object", code="invalid_object")
    result = {}
    for oid, line in zip(wanted, lines):
        if len(line) > len(oid) + 32: raise error("invalid private object", code="invalid_object")
        fields = line.split()
        if fields == [oid.encode("ascii"), b"missing"]:
            result[oid] = None
        elif (len(fields) == 3 and fields[0] == oid.encode("ascii")
              and fields[1] in (b"blob", b"tree", b"commit")
              and len(fields[2]) <= 20 and fields[2].isdigit()):
            result[oid] = (fields[1].decode("ascii"), int(fields[2]))
        else:
            raise error("invalid private object", code="invalid_object")
    return result
def private_object(cwd, oid, *, kind, max_bytes, env, scratch, headers, runner, custody, error, lane=None):
    """One typed object, with a bounded preflight before payload capture."""
    from aegis_core.workspace import git_objects
    if (kind not in ("blob", "tree", "commit") or isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int) or not 0 <= max_bytes <= 128 * 1024 * 1024):
        raise error("invalid private object request", code="invalid_object")
    info = headers(cwd, [oid], env=env, scratch=scratch)[oid]
    if info is None or info[0] != kind: raise error("invalid private object", code="invalid_object")
    size = info[1]
    if size > max_bytes: raise error("private object size limit exceeded", code="git_object_limit")
    data = _private_capture(["cat-file", kind, oid], cwd, env=env, scratch=scratch, limit=size,
        stdin=None, runner=runner, custody=custody, lane=lane).stdout
    if len(data) != size or git_objects.object_id(data, len(oid), kind) != oid: raise error("invalid private object", code="invalid_object")
    return data
def private_objects(cwd, oids, *, max_bytes, max_object_bytes, env, scratch, headers,
                    runner, batch, custody, error, lane=None):
    """Batch publication preflight, then exact ordered type, size and hash validation."""
    from aegis_core.workspace import git_objects
    if any(isinstance(cap, bool) or not isinstance(cap, int) or not 0 <= cap <= 128 * 1024 * 1024
           for cap in (max_bytes, max_object_bytes)):
        raise error("invalid private object request", code="invalid_object")
    info = headers(cwd, oids, env=env, scratch=scratch)
    if not info: return {}
    if any(value is None for value in info.values()): raise error("invalid private object", code="invalid_object")
    total = sum(value[1] for value in info.values())
    wire_limit = total + sum(len(oid) + 34 for oid in info)
    if (total > max_bytes or wire_limit > 128 * 1024 * 1024
            or any(value[1] > max_object_bytes for value in info.values())):
        raise error("private object size limit exceeded", code="git_object_limit")
    out = _private_capture(batch, cwd, env=env, scratch=scratch, limit=wire_limit,
        stdin=("\n".join(info) + "\n").encode("ascii"), runner=runner, custody=custody, lane=lane).stdout
    objects, position = {}, 0
    for oid, (kind, size) in info.items():
        header = (oid + " " + kind + " " + str(size) + "\n").encode("ascii")
        start = position + len(header)
        if (out[position:start] != header or size > len(out) - start - 1
                or out[start + size:start + size + 1] != b"\n"):
            raise error("invalid private object", code="invalid_object")
        data = out[start:start + size]
        if git_objects.object_id(data, len(oid), kind) != oid: raise error("invalid private object", code="invalid_object")
        objects[oid] = (kind, data)
        position = start + size + 1
    if position != len(out): raise error("invalid private object", code="invalid_object")
    return objects
