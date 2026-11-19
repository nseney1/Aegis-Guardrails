"""Literal mailbox refusal reasons must have fixed recovery advice.

This guard targets honest direct calls in team_mailbox*.py. Dynamic reasons,
aliases, reflective access, receiver identities and callback flows are outside
its scope. Runtime rendering at public mailbox boundaries validates known-family
state without calling instance methods; class-creation checks are defence in depth.
Custom-subclass serializers called directly in process outside those boundaries
are outside that runtime guarantee.
The two reviewed forwarding implementations retain their own advice check.
A separate structural guard pins the inventoried boundary scopes: their mailbox
renderer clause comes first, ahead of any overlapping domain refusal handler.
Only bounded reads of the repository's own sources are used; no Git history
or platform-specific filesystem capability is required.
"""
import ast
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[2]
PRIMITIVES = "aegis_core/team_mailbox_primitives.py"
STORE = "aegis_core/team_mailbox_store.py"
MAX_SOURCE_BYTES = 1024 * 1024
MAX_MODULES = 128
MAX_TOTAL_SOURCE = 16 * MAX_SOURCE_BYTES


def mailbox_trees():
    return source_trees((REPO / "aegis_core").glob("team_mailbox*.py"))


def source_trees(paths):
    sources = {}
    total = 0
    for path in paths:
        assert len(sources) < MAX_MODULES, "mailbox module inventory exceeds the limit"
        limit = min(MAX_SOURCE_BYTES, MAX_TOTAL_SOURCE - total)
        try:
            with path.open("rb") as stream:
                raw = stream.read(limit + 1)
        except OSError:
            raise AssertionError("mailbox source is unavailable") from None
        assert len(raw) <= limit, "mailbox source inventory exceeds the byte limit"
        total += len(raw)
        sources[path.relative_to(REPO).as_posix()] = raw
    assert sources and PRIMITIVES in sources and STORE in sources, "mailbox sources are incomplete"
    trees = {}
    for filename, raw in sorted(sources.items()):
        try:
            trees[filename] = ast.parse(raw, filename=filename)
        except (SyntaxError, ValueError, UnicodeError, RecursionError):
            raise AssertionError("mailbox source cannot be parsed") from None
    return trees


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



def scoped_tries(node, scope=""):
    if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
        scope = scope + "." + node.name if scope else node.name
    if isinstance(node, ast.Try):
        yield scope, node
    for child in ast.iter_child_nodes(node):
        yield from scoped_tries(child, scope)


def catches_mailbox(handler):
    return handler.type is not None and any(
        isinstance(node, ast.Name) and node.id == "MailboxRefusal"
        or isinstance(node, ast.Attribute) and node.attr == "MailboxRefusal"
        for node in ast.walk(handler.type))


def boundary_order_errors(trees):
    """Any earlier exception family can overlap MailboxRefusal by inheritance."""
    required = set(BOUNDARY_HANDLERS)
    seen = set()
    errors = []
    for filename, tree in sorted(trees.items()):
        for scope, statement in scoped_tries(tree):
            key = filename, scope
            if key not in required:
                continue
            handlers = [index for index, handler in enumerate(statement.handlers) if catches_mailbox(handler)]
            if not handlers:
                continue
            seen.add(key)
            if len(handlers) != 1:
                errors.append(f"{filename}:{statement.lineno}: duplicate mailbox boundary clauses")
                continue
            index = handlers[0]
            for earlier in statement.handlers[:index]:
                reraises = any(isinstance(node, ast.Raise) for node in ast.walk(earlier))
                effect = "re-raise" if reraises else "serialize or return"
                errors.append(f"{filename}:{earlier.lineno}: earlier handler can {effect} before mailbox rendering")
            handler = statement.handlers[index]
            if not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                       and node.func.id == "render_mailbox_refusal" for node in ast.walk(handler)):
                errors.append(f"{filename}:{handler.lineno}: mailbox boundary has no renderer")
    errors.extend(f"{filename}:1: missing mailbox boundary {scope}" for filename, scope in sorted(required - seen))
    return errors


@pytest.fixture(scope="module")
def boundary_sources():
    paths = [*(REPO / "aegis_core").glob("team_mailbox*.py"),
             *(REPO / filename for filename in sorted({filename for filename, _scope in BOUNDARY_HANDLERS})
               if not Path(filename).name.startswith("team_mailbox"))]
    return source_trees(paths)


def changed_boundary(trees, filename, scope):
    changed = {**trees, filename: deepcopy(trees[filename])}
    statements = [statement for current, statement in scoped_tries(changed[filename])
                  if current == scope and any(catches_mailbox(handler) for handler in statement.handlers)]
    assert len(statements) == 1
    return changed, statements[0]


def test_mailbox_boundary_renderer_precedes_every_overlapping_handler(boundary_sources):
    assert boundary_order_errors(boundary_sources) == []


@pytest.mark.parametrize("filename,scope", BOUNDARY_HANDLERS)
@pytest.mark.parametrize("kind", ["domain_reraise", "ancestor_reraise", "serialization"])
def test_mailbox_boundary_contract_refuses_an_earlier_overlapping_handler(boundary_sources, filename, scope, kind):
    changed, statement = changed_boundary(boundary_sources, filename, scope)
    source = ("try:\n pass\nexcept HostRefusal:\n raise\n" if kind == "domain_reraise" else
              "try:\n pass\nexcept ValueError:\n raise\n" if kind == "ancestor_reraise" else
              "try:\n pass\nexcept Exception as error:\n return error.as_dict()\n")
    handler = ast.parse(source).body[0].handlers[0]
    ast.copy_location(handler, statement.handlers[0])
    statement.handlers.insert(0, handler)
    errors = boundary_order_errors(changed)
    assert any(error.startswith(filename + ":") and "before mailbox rendering" in error for error in errors)


@pytest.mark.parametrize("filename,scope", BOUNDARY_HANDLERS)
def test_mailbox_boundary_contract_refuses_a_removed_mailbox_clause(boundary_sources, filename, scope):
    changed, statement = changed_boundary(boundary_sources, filename, scope)
    statement.handlers[:] = [handler for handler in statement.handlers if not catches_mailbox(handler)]
    assert f"{filename}:1: missing mailbox boundary {scope}" in boundary_order_errors(changed)


@pytest.mark.parametrize("filename,scope", BOUNDARY_HANDLERS)
def test_mailbox_boundary_contract_refuses_a_removed_renderer(boundary_sources, filename, scope):
    changed, statement = changed_boundary(boundary_sources, filename, scope)
    handler = next(handler for handler in statement.handlers if catches_mailbox(handler))
    handler.body = [ast.Raise(exc=None, cause=None)]
    assert f"{filename}:{handler.lineno}: mailbox boundary has no renderer" in boundary_order_errors(changed)


@pytest.mark.parametrize("filename,scope", BOUNDARY_HANDLERS)
def test_mailbox_boundary_contract_allows_later_domain_handlers(boundary_sources, filename, scope):
    changed, statement = changed_boundary(boundary_sources, filename, scope)
    handler = ast.parse("try:\n pass\nexcept Exception:\n raise\n").body[0].handlers[0]
    ast.copy_location(handler, statement.handlers[-1])
    statement.handlers.append(handler)
    assert boundary_order_errors(changed) == []


def test_mailbox_boundary_contract_checks_retry_and_run_concurrently(boundary_sources):
    def check(index):
        filename, scope = BOUNDARY_HANDLERS[index % len(BOUNDARY_HANDLERS)]
        changed, statement = changed_boundary(boundary_sources, filename, scope)
        if index % 2:
            handler = ast.parse("try:\n pass\nexcept ValueError:\n raise\n").body[0].handlers[0]
            ast.copy_location(handler, statement.handlers[0])
            statement.handlers.insert(0, handler)
            assert boundary_order_errors(changed)
        assert boundary_order_errors(boundary_sources) == []
        return boundary_order_errors(boundary_sources)
    with ThreadPoolExecutor(max_workers=3) as pool:
        pending = [pool.submit(check, index) for index in range(18)]
        assert all(future.result(timeout=10) == [] for future in pending)
