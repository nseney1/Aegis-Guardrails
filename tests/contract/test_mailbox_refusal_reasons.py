"""Literal mailbox refusal reasons must have fixed recovery advice.

This guard targets honest direct calls in team_mailbox*.py. Dynamic reasons,
aliases, reflective access, receiver identities and callback flows are outside
its scope. Runtime rendering at public mailbox boundaries validates known-family
state without calling instance methods; class-creation checks are defence in depth.
Custom-subclass serializers called directly in process outside those boundaries
are outside that runtime guarantee.
The two reviewed forwarding implementations retain their own advice check.
A separate structural guard inventories explicit MailboxRefusal catches across
core, CLI and MCP. Renderer boundaries must come first in their try statements.
The inventory recognizes names, attributes, tuples and direct import aliases.
Inferred exception types and dynamic rebinding are outside its scope.
Only bounded reads of the repository's own sources are used; no Git history
or platform-specific filesystem capability is required.
"""
import ast
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[2]
PRIMITIVES = "aegis_core/team_mailbox_primitives.py"
STORE = "aegis_core/team_mailbox_store.py"
MAX_SOURCE_BYTES = 1024 * 1024
MAX_MODULES = 128
MAX_BOUNDARY_MODULES = 512
MAX_TOTAL_SOURCE = 16 * MAX_SOURCE_BYTES
BOUNDARY_PACKAGES = ("aegis_core", "aegis_cli", "aegis_mcp", "tools")
TRY_TYPES = (ast.Try, getattr(ast, "TryStar", ast.Try))


def mailbox_trees():
    return source_trees((REPO / "aegis_core").glob("team_mailbox*.py"))


def source_trees(paths):
    sources = source_bytes(paths, REPO, MAX_MODULES)
    assert sources and PRIMITIVES in sources and STORE in sources, "mailbox sources are incomplete"
    return {filename: parse_source(filename, raw) for filename, raw in sorted(sources.items())}


def source_bytes(paths, repo, module_limit):
    sources = {}
    total = 0
    for path in paths:
        assert len(sources) < module_limit, "mailbox module inventory exceeds the limit"
        limit = min(MAX_SOURCE_BYTES, MAX_TOTAL_SOURCE - total)
        try:
            with path.open("rb") as stream:
                raw = stream.read(limit + 1)
        except OSError:
            raise AssertionError("mailbox source is unavailable") from None
        assert len(raw) <= limit, "mailbox source inventory exceeds the byte limit"
        total += len(raw)
        sources[path.relative_to(repo).as_posix()] = raw
    return sources


def parse_source(filename, raw):
    try:
        return ast.parse(raw, filename=filename)
    except (SyntaxError, ValueError, UnicodeError, RecursionError):
        raise AssertionError("mailbox source cannot be parsed") from None


def advice_keys(tree):
    tables = [node.value for node in tree.body if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == "_NEXT"
                      for target in node.targets)]
    assert len(tables) == 1, "mailbox advice table must be declared once"
    table = ast.literal_eval(tables[0])
    assert type(table) is dict and table, "mailbox advice must be a nonempty literal dictionary"
    assert all(type(key) is str and type(value) is str and value
               for key, value in table.items()), "mailbox advice must contain fixed text"
    return set(table)


def literal_reason_sites(tree):
    """Read spellings only; do not infer aliases, receivers or callback identity."""
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        name = (call.func.id if isinstance(call.func, ast.Name)
                else call.func.attr if isinstance(call.func, ast.Attribute) else None)
        if name == "BusyError":
            # Its public argument is a path; the constructor's reason is busy.
            yield call.lineno, name, "busy"
            continue
        if name not in {"MailboxRefusal", "require"}:
            continue
        reason = next((keyword.value for keyword in call.keywords if keyword.arg == "reason"), None)
        if name == "MailboxRefusal" and call.args:
            reason = call.args[0]
        if isinstance(reason, ast.Constant):
            yield call.lineno, name, reason.value
    # BusyError's inline parent initializer supplies the fixed reason above.
    for cls in tree.body:
        if not isinstance(cls, ast.ClassDef) or cls.name != "BusyError":
            continue
        for call in ast.walk(cls):
            if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                    and call.func.attr == "__init__" and isinstance(call.func.value, ast.Call)
                    and isinstance(call.func.value.func, ast.Name) and call.func.value.func.id == "super"
                    and call.args and isinstance(call.args[0], ast.Constant)):
                yield call.lineno, "BusyError initializer", call.args[0].value


def forwarding_errors(tree, filename, advice):
    if filename == PRIMITIVES:
        source = '''def require(condition, message="", *, reason="invalid_record"):
    if not condition:
        raise MailboxRefusal(reason)
'''
    else:
        source = '''@contextmanager
def refusals():
    try:
        yield
    except OSError as error:
        reason = {errno.ENOENT: "missing", errno.EEXIST: "exists", errno.ELOOP: "unsafe_path",
                  errno.ENOTDIR: "unsafe_path"}.get(error.errno, "io")
        raise MailboxRefusal(reason) from None
'''
    expected = ast.parse(source).body[0]
    functions = [node for node in tree.body
                 if isinstance(node, ast.FunctionDef) and node.name == expected.name]
    if len(functions) != 1 or ast.dump(functions[0]) != ast.dump(expected):
        line = functions[0].lineno if functions else 1
        return [f"{filename}:{line}: reviewed forwarding implementation changed"]
    function = functions[0]
    if filename == PRIMITIVES:
        outcomes = function.args.kw_defaults
    else:
        selection = function.body[0].handlers[0].body[0].value
        outcomes = [*selection.func.value.values, selection.args[1]]
    return [f"{filename}:{value.lineno}: forwarded reason has no advice"
            for value in outcomes if value.value not in advice]


@pytest.fixture(scope="module")
def mailbox_sources():
    trees = mailbox_trees()
    return trees, advice_keys(trees[PRIMITIVES])


def test_mailbox_literal_refusal_reasons_have_advice(mailbox_sources):
    trees, advice = mailbox_sources
    errors = [f"{filename}:{line}: refusal reason has no advice"
              for filename, tree in trees.items()
              for line, _name, reason in literal_reason_sites(tree)
              if type(reason) is not str or reason not in advice]
    assert errors == [], "\n".join(errors)


def test_reviewed_mailbox_forwarders_have_advice(mailbox_sources):
    trees, advice = mailbox_sources
    errors = [error for filename in (PRIMITIVES, STORE)
              for error in forwarding_errors(trees[filename], filename, advice)]
    assert errors == [], "\n".join(errors)


BOUNDARY_HANDLERS = (('aegis_core/team_board.py', 'board_operation.decorate.call'),
 ('aegis_core/team_host_plan.py', '_read_json'),
 ('aegis_core/team_host_registry.py', 'guarded.call'),
 ('aegis_core/team_lifecycle.py', 'boundary.call'),
 ('aegis_core/team_mailbox.py', 'Mailbox.host_call'),
 ('aegis_core/team_mailbox.py', 'Mailbox.messages'),
 ('aegis_core/team_mailbox_delivery.py', 'MailboxDelivery.delivery_receipts'),
 ('aegis_core/team_mailbox_pager.py', '_boundary.call'),
 ('aegis_core/team_mailbox_primitives.py', '_manifest_field'),
 ('aegis_core/team_mailbox_service.py', 'operation.decorate.call'),
 ('aegis_core/team_mailbox_primitives.py', 'strict_json'),
 ('aegis_core/team_mailbox_primitives.py', 'validation.call'),
 ('aegis_core/team_mailbox_records.py', 'Records.call'),
 ('aegis_core/team_mailbox_records.py', 'digest.probe'),
 ('aegis_core/team_mailbox_store.py', 'Store.entries'),
 ('aegis_core/team_mailbox_store.py', 'Store.exists'),
 ('aegis_core/team_mailbox_store.py', 'Store.lock'),
 ('aegis_core/team_mailbox_store.py', 'Store.publication_lock'),
 ('aegis_core/team_mailbox_store.py', '_account_home'),
 ('aegis_core/team_roles.py', '_endpoint_key'),
 ('aegis_core/team_roles.py', '_operation.decorate.call'))

# Additional renderer boundaries found by the package census.
BOUNDARY_HANDLERS += (
    ("aegis_cli/team_board.py", "run_board"),
    ("aegis_cli/team_mail.py", "run_mail"),
    ("aegis_core/team_lifecycle_writers.py", "_refusals"),
    ("aegis_core/team_mailbox_doctor.py", "inspect_mailbox"),
)

# These catches translate to their own domain, recover locally, or propagate to
# a renderer. Each entry accounts for one clause, including repeated scopes.
OTHER_REVIEWED_HANDLERS = {
    "aegis_core/team_jobs_recipes.py": ("Recipes._json", "Recipes._packet_checkout", "guard.decorate.call"),
    "aegis_core/team_mailbox_doctor.py": (
        "DiagnosticStore.listing", "DiagnosticStore.probe", "DiagnosticStore.read", "DiagnosticStore.verify_admission",
        "briefs", "briefs", "checked_path", "index_report", "inspect_store", "lock_report", "messages", "messages",
    ),
    "aegis_core/team_mailbox_primitives.py": ("_refusal_values",),
    "aegis_core/team_session_wake.py": ("_failed_start", "_refusals", "_wake", "background_entry", "transcript_mark"),
    "aegis_core/team_workspace_display.py": ("refusals.checked",),
    "aegis_core/team_workspace_store.py": ("_stale", "refusal_context"),
}


def catches_mailbox(handler, names):
    return handler.type is not None and any(
        isinstance(node, ast.Name) and node.id in names
        or isinstance(node, ast.Attribute) and node.attr == "MailboxRefusal"
        for node in ast.walk(handler.type))


def mailbox_tries(tree):
    names = {"MailboxRefusal"}
    statements = []

    def scan(node, scope):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            scope = scope + "." + node.name if scope else node.name
        if isinstance(node, ast.ImportFrom):
            names.update(alias.asname for alias in node.names if alias.name == "MailboxRefusal" and alias.asname)
        if isinstance(node, TRY_TYPES):
            statements.append((scope, node))
        for child in ast.iter_child_nodes(node):
            # Imports and try statements cannot be nested inside expressions.
            if not isinstance(child, ast.expr):
                scan(child, scope)

    scan(tree, "")
    for scope, statement in statements:
        indices = [index for index, handler in enumerate(statement.handlers) if catches_mailbox(handler, names)]
        if indices:
            yield scope, statement, indices


def module_boundary_errors(filename, tree):
    """Any earlier exception family can overlap MailboxRefusal by inheritance."""
    ordered = {scope for module, scope in BOUNDARY_HANDLERS if module == filename}
    remaining = Counter(OTHER_REVIEWED_HANDLERS.get(filename, ()))
    remaining.update(ordered)
    errors = []
    for scope, statement, indices in mailbox_tries(tree) if tree is not None else ():
        for index in indices:
            if remaining[scope] == 0:
                handler = statement.handlers[index]
                errors.append(f"{filename}:{handler.lineno}: unlisted mailbox handler {scope or '<module>'}")
            else:
                remaining[scope] -= 1
        if scope not in ordered:
            continue
        if len(indices) != 1:
            errors.append(f"{filename}:{statement.lineno}: duplicate mailbox boundary clauses")
            continue
        index = indices[0]
        for earlier in statement.handlers[:index]:
            reraises = any(isinstance(node, ast.Raise) for node in ast.walk(earlier))
            effect = "re-raise" if reraises else "serialize or return"
            errors.append(f"{filename}:{earlier.lineno}: earlier handler can {effect} before mailbox rendering")
        handler = statement.handlers[index]
        if not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                   and node.func.id == "render_mailbox_refusal" for node in ast.walk(handler)):
            errors.append(f"{filename}:{handler.lineno}: mailbox boundary has no renderer")
    for scope, count in sorted(remaining.items()):
        if count:
            kind = "boundary" if scope in ordered else "handler"
            errors.append(f"{filename}:1: missing mailbox {kind} {scope}")
    return errors


def boundary_order_errors(trees):
    filenames = trees.keys() | OTHER_REVIEWED_HANDLERS.keys() | {filename for filename, _scope in BOUNDARY_HANDLERS}
    return [error for filename in sorted(filenames) for error in module_boundary_errors(filename, trees.get(filename))]


def boundary_trees(repo):
    packages = [repo / name for name in BOUNDARY_PACKAGES]
    assert all(package.is_dir() for package in packages), "mailbox source packages are incomplete"
    paths = (path for package in packages for path in package.rglob("*.py"))
    sources = source_bytes(paths, repo, MAX_BOUNDARY_MODULES)
    trees = {}
    for filename, raw in sources.items():
        tree = parse_source(filename, raw)
        if next(mailbox_tries(tree), None) is not None:
            trees[filename] = tree
    return trees


@pytest.fixture(scope="module")
def boundary_sources():
    return boundary_trees(REPO)


def changed_boundary(trees, filename, scope):
    changed = deepcopy(trees[filename])
    statements = [(statement, indices) for current, statement, indices in mailbox_tries(changed)
                  if current == scope]
    assert len(statements) == 1
    statement, indices = statements[0]
    index, = indices
    return changed, statement, statement.handlers[index]


def test_mailbox_boundary_renderer_precedes_every_overlapping_handler(boundary_sources):
    assert boundary_order_errors(boundary_sources) == []


@pytest.mark.parametrize("package,import_line,exception", [
    ("aegis_core", "from aegis_core.team_mailbox_primitives import MailboxRefusal", "MailboxRefusal"),
    ("aegis_cli", "from aegis_core import team_mailbox_primitives", "(OSError, team_mailbox_primitives.MailboxRefusal)"),
    ("aegis_mcp", "from aegis_core.team_mailbox_primitives import MailboxRefusal as Refused", "Refused"),
    ("tools", "from aegis_core.team_mailbox_primitives import MailboxRefusal", "MailboxRefusal"),
])
def test_mailbox_boundary_contract_refuses_an_unlisted_adapter(
    boundary_sources, tmp_path, package, import_line, exception,
):
    for name in BOUNDARY_PACKAGES:
        (tmp_path / name / "nested").mkdir(parents=True)
    filename = f"{package}/nested/new_adapter.py"
    path = tmp_path / filename
    path.write_text(f"{import_line}\ntry:\n pass\nexcept {exception}:\n pass\n", encoding="utf-8")
    def check():
        return boundary_order_errors({**boundary_sources, **boundary_trees(tmp_path)})

    expected = [f"{filename}:4: unlisted mailbox handler <module>"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = [pool.submit(check) for _ in range(2)]
        assert [future.result(timeout=10) for future in pending] == [expected, expected]
    path.write_text(import_line + "\n", encoding="utf-8")
    assert check() == []


def test_mailbox_boundary_contract_refuses_a_second_catch_in_a_listed_scope(boundary_sources):
    filename, scope = "aegis_cli/team_mail.py", "run_mail"
    changed, statement, handler = changed_boundary(boundary_sources, filename, scope)
    statement.handlers.append(deepcopy(handler))
    assert module_boundary_errors(filename, changed) == [
        f"{filename}:{handler.lineno}: unlisted mailbox handler {scope}",
        f"{filename}:{statement.lineno}: duplicate mailbox boundary clauses",
    ]
    assert module_boundary_errors(filename, boundary_sources[filename]) == []


@pytest.mark.parametrize("filename,scope", BOUNDARY_HANDLERS)
@pytest.mark.parametrize("kind", ["domain_reraise", "ancestor_reraise", "serialization"])
def test_mailbox_boundary_contract_refuses_an_earlier_overlapping_handler(boundary_sources, filename, scope, kind):
    changed, statement, _handler = changed_boundary(boundary_sources, filename, scope)
    source = ("try:\n pass\nexcept HostRefusal:\n raise\n" if kind == "domain_reraise" else
              "try:\n pass\nexcept ValueError:\n raise\n" if kind == "ancestor_reraise" else
              "try:\n pass\nexcept Exception as error:\n return error.as_dict()\n")
    handler = ast.parse(source).body[0].handlers[0]
    ast.copy_location(handler, statement.handlers[0])
    statement.handlers.insert(0, handler)
    errors = module_boundary_errors(filename, changed)
    assert any(error.startswith(filename + ":") and "before mailbox rendering" in error for error in errors)


@pytest.mark.parametrize("filename,scope", BOUNDARY_HANDLERS)
def test_mailbox_boundary_contract_refuses_a_removed_mailbox_clause(boundary_sources, filename, scope):
    changed, statement, handler = changed_boundary(boundary_sources, filename, scope)
    statement.handlers.remove(handler)
    assert f"{filename}:1: missing mailbox boundary {scope}" in module_boundary_errors(filename, changed)


@pytest.mark.parametrize("filename,scope", BOUNDARY_HANDLERS)
def test_mailbox_boundary_contract_refuses_a_removed_renderer(boundary_sources, filename, scope):
    changed, _statement, handler = changed_boundary(boundary_sources, filename, scope)
    handler.body = [ast.Raise(exc=None, cause=None)]
    assert f"{filename}:{handler.lineno}: mailbox boundary has no renderer" in module_boundary_errors(filename, changed)


@pytest.mark.parametrize("filename,scope", BOUNDARY_HANDLERS)
def test_mailbox_boundary_contract_allows_later_domain_handlers(boundary_sources, filename, scope):
    changed, statement, _handler = changed_boundary(boundary_sources, filename, scope)
    handler = ast.parse("try:\n pass\nexcept Exception:\n raise\n").body[0].handlers[0]
    ast.copy_location(handler, statement.handlers[-1])
    statement.handlers.append(handler)
    assert module_boundary_errors(filename, changed) == []


def test_mailbox_boundary_contract_checks_retry_and_run_concurrently(boundary_sources):
    def check(index):
        filename, scope = BOUNDARY_HANDLERS[index % len(BOUNDARY_HANDLERS)]
        changed, statement, _handler = changed_boundary(boundary_sources, filename, scope)
        if index % 2:
            handler = ast.parse("try:\n pass\nexcept ValueError:\n raise\n").body[0].handlers[0]
            ast.copy_location(handler, statement.handlers[0])
            statement.handlers.insert(0, handler)
            assert module_boundary_errors(filename, changed)
        else:
            assert module_boundary_errors(filename, changed) == []
        return module_boundary_errors(filename, boundary_sources[filename])
    with ThreadPoolExecutor(max_workers=3) as pool:
        pending = [pool.submit(check, index) for index in range(18)]
        assert all(future.result(timeout=10) == [] for future in pending)
