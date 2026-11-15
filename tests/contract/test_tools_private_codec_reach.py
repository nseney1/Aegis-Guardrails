"""Name-based private codec boundary, independent of receiver provenance.

Tracked source files deliberately use portable plain reads. RULE M refuses
private-name string constants regardless of their consumer; computed namespace
mutation is outside this source contract.
"""
import ast
import importlib
import sys
from collections import namedtuple
from inspect import getmembers
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import NamedTuple

import pytest

REPO = Path(__file__).resolve().parents[2]
CODECS = ("aegis_core.message_codec", "aegis_core.message_codec_store")
# Coordinator NAMEDTUPLE API EXCLUSION, 2026-11-15T07:44:55Z: public protocol
# names (_make, _asdict, _replace, _fields, _field_defaults) are underscored to
# avoid field-name clashes. Derive generated names from both stdlib factories;
# exclude them only from runtime inventory, preserving every AST-bound name.
NAMEDTUPLE_PUBLIC_API = frozenset(
    name for factory in (namedtuple, NamedTuple)
    for name, _value in getmembers(SimpleNamespace(**{**vars(factory("CodecProtocolProbe", ()))}))
    if name.startswith("_") and not name.startswith("__")
)
# Coordinator OWNED-NAME TABLE ruling, 2026-11-15T03:56:08Z. Shrink only.
OWNED_NAMES = frozenset({
    ("tools/hierarchy_host_authority.py", "_lock"),
    ("tools/hierarchy_host_authority.py", "_reference"),
    ("tools/hierarchy_mailbox_doctor.py", "_open"),
    ("tools/hierarchy_mailbox_index.py", "_identity"),
    ("tools/hierarchy_small_change_dispatch.py", "_directory"),
})


def _private(name):
    return (isinstance(name, str) and name.isidentifier() and name != "_"
            and name.startswith("_") and not name.startswith("__"))


def _owned_method_body_nodes(method):
    """Walk this method's body without borrowing stores from another scope."""
    pending = list(method.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef,
                             ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            continue
        yield node
        pending.extend(ast.iter_child_nodes(node))


def _defined_private_names(tree):
    """Inventory every binding and private identifier literal at any depth."""
    # RULE M INVENTORY REDESIGN, 2026-11-15T09:42:51Z: scope and receiver
    # provenance do not narrow this inventory. Ownership is proved separately.
    named_nodes = tuple(kind for kind in (
        getattr(ast, "MatchAs", None), getattr(ast, "MatchStar", None),
        getattr(ast, "TypeVar", None), getattr(ast, "TypeVarTuple", None),
        getattr(ast, "ParamSpec", None),
    ) if kind is not None)
    mapping_pattern = getattr(ast, "MatchMapping", None)
    type_alias = getattr(ast, "TypeAlias", None)
    found = set()
    for node in ast.walk(tree):
        names = ()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler)):
            names = (node.name,)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names = (node.id,)
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names = (node.attr,)
        elif isinstance(node, ast.alias):
            names = (node.asname or node.name.split(".")[0],)
        elif isinstance(node, ast.arg):
            names = (node.arg,)
        elif isinstance(node, named_nodes):
            names = (node.name,)
        elif mapping_pattern is not None and isinstance(node, mapping_pattern):
            names = (node.rest,)
        elif type_alias is not None and isinstance(node, type_alias):
            names = (node.name.id,)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            names = node.names
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            names = (node.value,)
        found.update(name for name in names if _private(name))
    return found


def _runtime_private_names(modules):
    found = set()
    for module in modules:
        pending, seen = [(SimpleNamespace(**{**vars(module)}), ())], set()
        while pending:
            namespace, protocol = pending.pop()
            members = getmembers(namespace)
            found.update(name for name, _value in members if _private(name) and name not in protocol)
            for _name, value in members:
                if isinstance(value, type) and value.__module__ == module.__name__ and id(value) not in seen:
                    seen.add(id(value))
                    protocol = (NAMEDTUPLE_PUBLIC_API if issubclass(value, tuple) and
                                isinstance(getattr(value, "_fields", None), tuple) else ())
                    pending.append((SimpleNamespace(**{**vars(value)}), protocol))
    return found


def codec_private_names(root=REPO, *, runtime_modules=None):
    """Union source inventory with loaded repository modules or explicit stand-ins.

    Scratch AST-only fixtures supply another root; they need not be executable.
    Runtime controls supply their own module objects without replacing imports.
    """
    if runtime_modules is None:
        runtime_modules = tuple(importlib.import_module(name) for name in CODECS) if root == REPO else ()
    found = set()
    for module in CODECS:
        rel = module.replace(".", "/") + ".py"
        tree = ast.parse((root / rel).read_text(encoding="utf-8"), filename=rel)
        found.update(_defined_private_names(tree))
    return found | _runtime_private_names(runtime_modules)


def _owned_class_targets(target):
    if isinstance(target, ast.Name) and isinstance(target.ctx, ast.Store):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        children = [_owned_class_targets(child) for child in target.elts]
        return None if any(child is None for child in children) else set().union(*children)
    return None


def _owned_method_stores(method):
    found = set()

    def target_names(target):
        if (isinstance(target, ast.Attribute) and isinstance(target.ctx, ast.Store)
                and isinstance(target.value, ast.Name) and target.value.id in ("self", "cls")
                and _private(target.attr)):
            found.add(target.attr)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for child in target.elts:
                target_names(child)

    for node in _owned_method_body_nodes(method):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                target_names(target)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target_names(node.target)
    return found


def _owned_private_names(tree):
    """Ownership is narrower than inventory: no imported/aliased module names."""
    found = set()

    def collect(node, class_scope=False):
        if isinstance(node, ast.ClassDef):
            for child in node.body:
                collect(child, True)
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _private(node.name):
                found.add(node.name)
            if class_scope:
                found.update(_owned_method_stores(node))
            return
        if class_scope and (isinstance(node, ast.Assign) or
                            isinstance(node, ast.AnnAssign) and node.value is not None):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                names = _owned_class_targets(target)
                if names is not None:
                    found.update(name for name in names if _private(name))
                if (isinstance(target, ast.Name) and target.id == "__slots__"
                        and isinstance(node.value, (ast.Tuple, ast.List))
                        and all(isinstance(item, ast.Constant) and isinstance(item.value, str)
                                for item in node.value.elts)):
                    found.update(item.value for item in node.value.elts if _private(item.value))
            return
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr,
                             ast.Import, ast.ImportFrom, ast.Lambda,
                             ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            return
        for child in ast.iter_child_nodes(node):
            collect(child, class_scope)

    collect(tree)
    return found


def _codec_imports(tree):
    """RULE M: direct imports or any codec-naming string invalidate a row."""
    def codec(name):
        return any(name == module or name.startswith(module + ".") for module in CODECS)

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and "message_codec" in node.value:
            return True
        if isinstance(node, ast.Import) and any(codec(alias.name) for alias in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and node.module:
            if codec(node.module) or any(codec(node.module + "." + alias.name) for alias in node.names):
                return True
    return False


def _private_uses(tree, forbidden):
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in forbidden:
            found.append((node.lineno, node.attr, "attribute"))
        elif isinstance(node, ast.ImportFrom) and node.module in CODECS:
            found.extend((node.lineno, alias.name, "from_import") for alias in node.names if alias.name in forbidden)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in forbidden:
            found.append((node.lineno, node.value, "literal"))
    return found


def owned_name_errors(rows, trees, forbidden):
    errors = []
    for rel, name in sorted(rows):
        label = rel + ":" + name
        if rel == "tools/hierarchy_mailbox_records.py":
            errors.append(label + ": codec importer cannot have an owned-name row")
            continue
        if rel not in trees:
            errors.append(label + ": stale owned-name row")
            continue
        tree = trees[rel]
        if name not in forbidden or not _private_uses(tree, {name}):
            errors.append(label + ": stale owned-name row")
        if name not in _owned_private_names(tree):
            errors.append(label + ": name is not defined by the module")
        if _codec_imports(tree):
            errors.append(label + ": imports a message codec module or contains a message_codec string literal")
    return errors


def private_codec_reaches(root, *, codec_root=REPO, owned_names=(), runtime_modules=None):
    """Refuse private names, exempting only supplied rows whose proof succeeds."""
    tools = root / "tools"
    if not tools.is_dir():
        raise FileNotFoundError("tools source directory missing")
    # Preserve the original brief's explicit ban on the retired codec._options.
    forbidden = codec_private_names(codec_root, runtime_modules=runtime_modules) | {"_options"}
    trees = {}
    for path in sorted(tools.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        trees[rel] = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
    rows = frozenset(owned_names)
    errors = owned_name_errors(rows, trees, forbidden)
    assert not errors, "\n".join(errors)
    return sorted((rel, line, name) for rel, tree in trees.items()
                  for line, name, kind in _private_uses(tree, forbidden)
                  if kind != "attribute" or (rel, name) not in rows)


def test_tools_use_only_public_codec_names():
    assert private_codec_reaches(REPO, owned_names=OWNED_NAMES) == []


@pytest.mark.parametrize("source,member,line", [
    ("from aegis_core import message_codec as mc\nbackend, = (mc,)\nbackend._selector('body')", "_selector", 3),
    ("class Reader:\n    def view(self, codec):\n        self.backend = codec\n        self.backend._selector('body')", "_selector", 4),
    ("from aegis_core import message_codec as mc\nimport json as backend\nbackend = mc\nbackend._selector('body')", "_selector", 4),
    ("from aegis_core import message_codec as mc\nstore = mc.Store(root)\nstore._read_bytes(None)", "_read_bytes", 3),
    ("getattr(any_receiver, '_selector')('body')", "_selector", 1),
])
def test_reviewer_binding_forms_are_refused_by_private_name(tmp_path, source, member, line):
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "probe.py").write_text(source + "\n", encoding="utf-8")
    assert private_codec_reaches(tmp_path) == [("tools/probe.py", line, member.rsplit(".", 1)[-1])]


@pytest.mark.parametrize("source,member,line", [
    ("codec._options(None)", "aegis_core.message_codec._options", 1),
    ("from aegis_core import message_codec as codec\ncodec._options(None)", "aegis_core.message_codec._options", 2),
    ("import aegis_core.message_codec as mc\nmc._options(None)", "aegis_core.message_codec._options", 2),
    ("import aegis_core.message_codec\naegis_core.message_codec._options(None)", "aegis_core.message_codec._options", 2),
    ("from aegis_core import message_codec as mc\nalias = mc\nalias._options(None)", "aegis_core.message_codec._options", 3),
    ("from aegis_core import message_codec_store as storage\nalias = storage\nalias.Store._read_bytes(None)", "aegis_core.message_codec_store.Store._read_bytes", 3),
    ("from aegis_core.message_codec import _options as prepare\nprepare(None)", "aegis_core.message_codec._options", 1),
    ("def view(codec):\n    alias = codec\n    alias._options(None)", "aegis_core.message_codec._options", 3),
    ("class Reader:\n    def view(self):\n        self.codec._options(None)", "aegis_core.message_codec._options", 3),
    ("facade = codec_tools()\nfacade._options(None)", "aegis_core.message_codec._options", 2),
    ("import importlib as loading\nfacade = loading.import_module('aegis_core.message_codec_store')\nfacade._release(None)", "aegis_core.message_codec_store._release", 3),
])
def test_planted_private_codec_reach_is_reported(tmp_path, source, member, line):
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "probe.py").write_text(source + "\n", encoding="utf-8")
    assert private_codec_reaches(tmp_path) == [("tools/probe.py", line, member.rsplit(".", 1)[-1])]


def test_public_codec_names_and_unrelated_private_names_are_allowed(tmp_path):
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "probe.py").write_text(
        "from aegis_core import message_codec as codec\n"
        "codec.prepare_read(None)\n"
        "def unrelated():\n    import json as codec\n    codec._decoder\n",
        encoding="utf-8",
    )
    assert private_codec_reaches(tmp_path) == []


def test_scan_retries_and_concurrent_roots_do_not_share_aliases(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    roots = [tmp_path / name for name in ("bad", "safe")]
    for root in roots:
        (root / "tools").mkdir(parents=True)
    bad = roots[0] / "tools" / "probe.py"
    bad.write_text("alias = codec\nalias._options(None)\n", encoding="utf-8")
    (roots[1] / "tools" / "probe.py").write_text(
        "import json as codec\nalias = codec\nalias._decoder\n", encoding="utf-8")
    expected = [("tools/probe.py", 2, "_options")]
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(private_codec_reaches, root) for root in roots]
        assert [future.result(timeout=10) for future in futures] == [expected, []]
    bad.write_text("codec.prepare_read(None)\n", encoding="utf-8")
    assert private_codec_reaches(roots[0]) == []
    bad.write_text("alias = codec\nalias._options(None)\n", encoding="utf-8")
    assert private_codec_reaches(roots[0]) == expected


def test_scan_refuses_missing_directory_and_malformed_source(tmp_path):
    with pytest.raises(FileNotFoundError, match="^tools source directory missing$"):
        private_codec_reaches(tmp_path)
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "bad.py").write_text("def broken(\n", encoding="utf-8")
    with pytest.raises(SyntaxError) as caught:
        private_codec_reaches(tmp_path)
    assert caught.value.filename == "tools/bad.py"


def test_private_definition_inventory_includes_class_state_locals_and_args_but_not_dunders(tmp_path):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "message_codec.py").write_text(
        "def _helper(_argument):\n    def _local(): pass\n"
        "class _Thing:\n    _class_field = 1\n    _annotated: int\n"
        "    __slots__ = ('_slot', '__dunder')\n"
        "    def _method(self):\n        self._instance = 1\n"
        "    @classmethod\n    def public(cls):\n        cls._class_value = 1\n"
        "    def __special__(self): pass\n",
        encoding="utf-8")
    (core / "message_codec_store.py").write_text(
        "async def _store_helper(): pass\nclass Store:\n    def _read_bytes(self): pass\n",
        encoding="utf-8")
    assert codec_private_names(tmp_path) == {
        "_helper", "_local", "_argument", "_Thing", "_class_field", "_annotated", "_slot", "_method",
        "_instance", "_class_value", "_store_helper", "_read_bytes"}
    tools = tmp_path / "tools"
    tools.mkdir()
    path = tools / "probe.py"
    path.write_text("arbitrary._instance\ngetattr(arbitrary, '_class_value')\n", encoding="utf-8")
    assert private_codec_reaches(tmp_path, codec_root=tmp_path) == [
        ("tools/probe.py", 1, "_instance"), ("tools/probe.py", 2, "_class_value")]


def test_own_attribute_name_collisions_are_reported_without_an_allowlist(tmp_path):
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "probe.py").write_text(
        "class Own:\n    def _selector(self): pass\n"
        "    def public(self):\n        self._selector()\n", encoding="utf-8")
    assert private_codec_reaches(tmp_path) == [("tools/probe.py", 4, "_selector")]


def test_reviewed_owned_table_can_only_shrink():
    assert OWNED_NAMES <= {
        ("tools/hierarchy_host_authority.py", "_lock"),
        ("tools/hierarchy_host_authority.py", "_reference"),
        ("tools/hierarchy_mailbox_doctor.py", "_open"),
        ("tools/hierarchy_mailbox_index.py", "_identity"),
        ("tools/hierarchy_small_change_dispatch.py", "_directory"),
    }


def test_owned_name_exemption_requires_a_definition_and_occurrence(tmp_path):
    tools = tmp_path / "tools"
    tools.mkdir()
    path = tools / "probe.py"
    row = frozenset({("tools/probe.py", "_lock")})
    path.write_text("class Own:\n    def __init__(self):\n        self._lock = None\n", encoding="utf-8")
    assert private_codec_reaches(tmp_path, owned_names=row) == []
    path.write_text(
        "class Own:\n    @classmethod\n    def make(cls):\n"
        "        self = object.__new__(cls)\n        self._lock = None\n", encoding="utf-8")
    assert private_codec_reaches(tmp_path, owned_names=row) == []
    path.write_text("x._lock\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="name is not defined by the module"):
        private_codec_reaches(tmp_path, owned_names=row)
    path.write_text("class Own:\n    def _lock(self): pass\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="stale owned-name row"):
        private_codec_reaches(tmp_path, owned_names=row)
    path.write_text("public = 1\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="stale owned-name row"):
        private_codec_reaches(tmp_path, owned_names=row)


@pytest.mark.parametrize("declaration", [
    "import aegis_core.message_codec_store as storage",
    "from aegis_core.message_codec import Store",
    "from aegis_core import message_codec as codec",
    "import importlib as loader\nloader.import_module('aegis_core.message_codec_store')",
    "from importlib import import_module as load\nload('aegis_core.message_codec')",
    "__import__('aegis_core.message_codec_store')",
    "from builtins import __import__ as load\nload('aegis_core.message_codec')",
    "__import__('aegis_core', fromlist=['message_codec_store'])",
    "import importlib\nimportlib.import_module('.message_codec', package='aegis_core')",
    "__import__(**{'name': 'aegis_core.message_codec_store'})",
])
def test_owned_name_with_any_literal_codec_import_is_refused(tmp_path, declaration):
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "probe.py").write_text(
        declaration + "\nclass Own:\n    def __init__(self):\n        self._lock = None\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="imports a message codec module"):
        private_codec_reaches(tmp_path, owned_names={("tools/probe.py", "_lock")})


def test_codec_importer_can_never_have_an_owned_name_row(tmp_path):
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "hierarchy_mailbox_records.py").write_text(
        "class Own:\n    def __init__(self):\n        self._lock = None\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="codec importer cannot have an owned-name row"):
        private_codec_reaches(tmp_path, owned_names={("tools/hierarchy_mailbox_records.py", "_lock")})


def test_new_owned_collision_outside_the_reviewed_table_is_refused(tmp_path):
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "probe.py").write_text("def _lock(): pass\nx._lock\n", encoding="utf-8")
    assert private_codec_reaches(tmp_path) == [("tools/probe.py", 2, "_lock")]


@pytest.mark.parametrize("declaration", [
    "import importlib as loader\nload = loader.import_module\nload('aegis_core.message_codec')",
    "import importlib\nload, = (importlib.import_module,)\nload('aegis_core.message_codec_store')",
    "import importlib\nclass Loader:\n    load = importlib.import_module\nLoader.load('aegis_core.message_codec')",
    "load = getattr(__builtins__, '__import__')\nload('aegis_core.message_codec_store')",
])
def test_owned_name_with_literal_loader_alias_is_refused(tmp_path, declaration):
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "probe.py").write_text(
        declaration + "\nclass Own:\n    def __init__(self):\n        self._lock = None\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="imports a message codec module"):
        private_codec_reaches(tmp_path, owned_names={("tools/probe.py", "_lock")})


def test_rule_m_existing_module_bindings_are_inventoried():
    assert {"_MISSING", "_views"} <= codec_private_names()


@pytest.mark.parametrize("name", ["_MISSING", "_views"])
@pytest.mark.parametrize("form", ["attribute", "import", "getattr"])
def test_rule_m_existing_module_binding_reach_is_refused(tmp_path, name, form):
    tools = tmp_path / "tools"
    tools.mkdir()
    source = {
        "attribute": "from aegis_core import message_codec as mc\nmc." + name,
        "import": "from aegis_core.message_codec import " + name,
        "getattr": "from aegis_core import message_codec as mc\ngetattr(mc, '" + name + "')",
    }[form]
    (tools / "probe.py").write_text(source + "\n", encoding="utf-8")
    assert private_codec_reaches(tmp_path) == [("tools/probe.py", len(source.splitlines()), name)]


@pytest.mark.parametrize("module,name", [("message_codec", "_selector"), ("message_codec_store", "_read_bytes")])
@pytest.mark.parametrize("declaration,call", [
    ("from builtins import getattr as fetch", "fetch(mc, '{name}')"),
    ("fetch = getattr", "fetch(mc, '{name}')"),
    ("fetch, = (getattr,)", "fetch(mc, '{name}')"),
    ("class Getter:\n    fetch = getattr", "Getter.fetch(mc, '{name}')"),
])
def test_rule_m_literal_private_name_refuses_any_getter_binding(tmp_path, module, name, declaration, call):
    tools = tmp_path / "tools"
    tools.mkdir()
    source = "from aegis_core import " + module + " as mc\n" + declaration + "\n" + call.format(name=name)
    (tools / "probe.py").write_text(source + "\n", encoding="utf-8")
    assert private_codec_reaches(tmp_path) == [("tools/probe.py", len(source.splitlines()), name)]


@pytest.mark.parametrize("module", ["message_codec", "message_codec_store"])
@pytest.mark.parametrize("loader", [
    "storage = getattr(importlib, 'import_module')('aegis_core.{module}')",
    "storage = getattr(builtins, '__import__')('aegis_core.{module}')",
    "load = getattr(importlib, 'import_module')\nstorage = load('aegis_core.{module}')",
])
def test_rule_m_inline_or_saved_loader_invalidates_exempt_module(tmp_path, module, loader):
    tools = tmp_path / "tools"
    tools.mkdir()
    rel = "tools/hierarchy_mailbox_doctor.py"
    source = (REPO / rel).read_text(encoding="utf-8")
    source += "\nimport importlib, builtins\n" + loader.format(module=module) + "\nstorage.Store._open\n"
    (tmp_path / rel).write_text(source, encoding="utf-8")
    with pytest.raises(AssertionError, match="imports a message codec module"):
        private_codec_reaches(tmp_path, owned_names={(rel, "_open")})


def test_rule_m_inventory_collects_bindings_at_any_depth(tmp_path):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "message_codec.py").write_text(
        "import os as _os\nfrom pathlib import Path as _Path\n"
        "_constant = 1\n_typed: object\n_left, (_inner, *_rest) = (1, (2, 3))\n"
        "class Public:\n    import json as _json\n    _field: object\n"
        "    def public(self):\n        _local = 1\n        import os as _local_os\n"
        "public_lambda = lambda: (_lambda_local := 1)\n"
        "for _index in []: pass\nwith context() as _handle: pass\n"
        "try: pass\nexcept Exception as _error: pass\n"
        "if (_named := True): pass\n"
        "public_list = [item for _comprehension_local in []]\n", encoding="utf-8")
    (core / "message_codec_store.py").write_text("", encoding="utf-8")
    assert codec_private_names(tmp_path) == {
        "_os", "_Path", "_constant", "_typed", "_left", "_inner", "_rest", "_json", "_field",
        "_index", "_handle", "_error", "_named", "_local", "_local_os", "_lambda_local", "_comprehension_local"}


@pytest.mark.parametrize("name", ["_selector", "_read_bytes", "_MISSING", "_views"])
def test_rule_m_plain_private_name_literal_is_refused(tmp_path, name):
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "probe.py").write_text("marker = '" + name + "'\n", encoding="utf-8")
    assert private_codec_reaches(tmp_path) == [("tools/probe.py", 1, name)]


def test_rule_m_private_literals_match_exact_names(tmp_path):
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "probe.py").write_text("names = ('_selector_extra', '__dict__', 'plain _selector text')\n", encoding="utf-8")
    assert private_codec_reaches(tmp_path) == []


def test_rule_m_any_codec_naming_literal_invalidates_an_owned_row(tmp_path):
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "probe.py").write_text(
        "label = 'not an import: message_codec mentioned'\n"
        "class Own:\n    def __init__(self):\n        self._lock = None\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="imports a message codec module"):
        private_codec_reaches(tmp_path, owned_names={("tools/probe.py", "_lock")})


def test_rule_m_combined_private_module_import_is_refused(tmp_path):
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "probe.py").write_text(
        "from aegis_core.message_codec import _MISSING, _views\n", encoding="utf-8")
    assert private_codec_reaches(tmp_path) == [
        ("tools/probe.py", 1, "_MISSING"), ("tools/probe.py", 1, "_views")]


def test_rule_m_exact_security_loader_variant_invalidates_doctor_row(tmp_path):
    (tmp_path / "tools").mkdir()
    rel = "tools/hierarchy_mailbox_doctor.py"
    source = (REPO / rel).read_text(encoding="utf-8")
    source += ('\nimport importlib\n'
               'storage = getattr(importlib, "import_module")("aegis_core.message_codec_store")\n'
               'storage.Store._open\n')
    (tmp_path / rel).write_text(source, encoding="utf-8")
    with pytest.raises(AssertionError, match="imports a message codec module"):
        private_codec_reaches(tmp_path, owned_names={(rel, "_open")})


def test_rule_m_inline_dunder_builtins_loader_invalidates_owned_row(tmp_path):
    (tmp_path / "tools").mkdir()
    rel = "tools/hierarchy_host_authority.py"
    (tmp_path / rel).write_text(
        'getattr(__builtins__, "__import__")("aegis_core.message_codec_store").Store(root)\n'
        'class Own:\n    def __init__(self):\n        self._lock = None\n', encoding="utf-8")
    with pytest.raises(AssertionError, match="imports a message codec module"):
        private_codec_reaches(tmp_path, owned_names={(rel, "_lock")})


@pytest.mark.parametrize("source", [
    "class Probe:\n    _lock._lock = 1\n",
    "class Probe:\n    _lock[0] = 1\n",
    "class Probe:\n    other._lock = 1\n",
    "class Probe:\n    self._lock = 1\n",
    "def public(self):\n    self._lock = 1\n",
    "self._lock = 1\n",
])
def test_rule_m_nondefining_targets_cannot_prove_owned_name(tmp_path, source):
    (tmp_path / "tools").mkdir()
    rel = "tools/hierarchy_host_authority.py"
    (tmp_path / rel).write_text(source, encoding="utf-8")
    with pytest.raises(AssertionError, match="name is not defined by the module"):
        private_codec_reaches(tmp_path, owned_names={(rel, "_lock")})


@pytest.mark.parametrize("source", [
    "class Probe:\n    _lock = None\nx._lock\n",
    "class Probe:\n    _lock, other = (None, None)\nx._lock\n",
    "class Probe:\n    def public(self):\n        self._lock = None\n",
    "class Probe:\n    @classmethod\n    def public(cls):\n        cls._lock = None\n",
])
def test_rule_m_defining_targets_can_prove_owned_name(tmp_path, source):
    (tmp_path / "tools").mkdir()
    rel = "tools/hierarchy_host_authority.py"
    (tmp_path / rel).write_text(source, encoding="utf-8")
    assert private_codec_reaches(tmp_path, owned_names={(rel, "_lock")}) == []


@pytest.mark.parametrize("receiver", ["self", "cls"])
@pytest.mark.parametrize("nested", ["sync", "async", "lambda"])
def test_r6_nested_scope_stores_cannot_prove_ownership(tmp_path, receiver, nested):
    (tmp_path / "tools").mkdir()
    rel = "tools/hierarchy_host_authority.py"
    tree = ast.parse((REPO / rel).read_text(encoding="utf-8"))
    removed = 0
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store)
                and node.attr == "_lock" and isinstance(node.value, ast.Name)
                and node.value.id in ("self", "cls")):
            node.attr = "fixture_lock"
            removed += 1
    assert removed > 0
    if nested == "lambda":
        inner = "        helper = lambda " + receiver + ": [None for " + receiver + "._lock in ()]\n"
    else:
        prefix = "async " if nested == "async" else ""
        inner = "        " + prefix + "def helper(" + receiver + "):\n            " + receiver + "._lock = 1\n"
    source = ast.unparse(tree) + "\nclass Probe:\n    def method(" + receiver + "):\n" + inner
    (tmp_path / rel).write_text(source, encoding="utf-8")
    with pytest.raises(AssertionError, match="name is not defined by the module"):
        private_codec_reaches(tmp_path, owned_names={(rel, "_lock")})


@pytest.mark.parametrize("rel,name", sorted(OWNED_NAMES))
def test_r6_private_name_literal_is_not_exempted_by_owned_row(tmp_path, rel, name):
    (tmp_path / "tools").mkdir()
    source = (REPO / rel).read_text(encoding="utf-8").rstrip("\n") + "\n"
    line = len(source.splitlines()) + 1
    (tmp_path / rel).write_text(source + "marker = '" + name + "'\n", encoding="utf-8")
    rows = {row for row in OWNED_NAMES if row[0] == rel}
    assert private_codec_reaches(tmp_path, owned_names=rows) == [(rel, line, name)]


def test_r6_slot_proves_ownership_but_its_literal_is_still_refused(tmp_path):
    (tmp_path / "tools").mkdir()
    rel = "tools/hierarchy_host_authority.py"
    (tmp_path / rel).write_text("class Probe:\n    __slots__ = ('_lock',)\n", encoding="utf-8")
    assert private_codec_reaches(tmp_path, owned_names={(rel, "_lock")}) == [(rel, 2, "_lock")]


def test_r6_annotation_expressions_bind_in_the_defining_scope(tmp_path):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "message_codec.py").write_text(
        "def public(pos: (_pos := int), /, normal: (_normal := int), "
        "*values: (_vararg := int), keyword: (_keyword := int), "
        "**kwargs: (_kwarg := int)) -> (_result := int):\n    _local = 1\n",
        encoding="utf-8")
    (core / "message_codec_store.py").write_text("", encoding="utf-8")
    assert codec_private_names(tmp_path) == {"_pos", "_normal", "_vararg", "_keyword", "_kwarg", "_result", "_local"}


@pytest.mark.parametrize("statement", [
    "mapping[tuple(_lock for _lock in ())] = 1",
    "mapping[tuple(_lock for _lock in ())]: int",
    "mapping[tuple(_lock for _lock in ())] += 1",
    "for mapping[tuple(_lock for _lock in ())] in ():\n    pass",
    "with context() as mapping[tuple(_lock for _lock in ())]:\n    pass",
])
def test_r6_target_expressions_cannot_define_owned_names(tmp_path, statement):
    (tmp_path / "tools").mkdir()
    rel = "tools/hierarchy_host_authority.py"
    source = "class Probe:\n    mapping = {}\n" + "\n".join("    " + line for line in statement.splitlines())
    source += "\n    other._lock\n"
    (tmp_path / rel).write_text(source, encoding="utf-8")
    with pytest.raises(AssertionError, match="name is not defined by the module"):
        private_codec_reaches(tmp_path, owned_names={(rel, "_lock")})


@pytest.mark.parametrize("source", [
    "from other_module import _lock\n",
    "import other_module as _lock\n",
    "_lock = other_module.store._lock\n",
    "_lock: object = other_module.store._lock\n",
    "if (_lock := other_module.store._lock): pass\n",
    "for _lock in (): pass\n",
    "with context() as _lock: pass\n",
    "try: pass\nexcept Exception as _lock: pass\n",
    "class Probe:\n    from other_module import _lock\n",
    "class Probe:\n    import other_module as _lock\n",
    "class Probe:\n    for _lock in (): pass\n",
    "class Probe:\n    with context() as _lock: pass\n",
    "class Probe:\n    try: pass\n    except Exception as _lock: pass\n",
    "class Probe:\n    if (_lock := other_module.store._lock): pass\n",
    "class Probe:\n    __slots__ = {'public': '_lock'}\n",
    "class Probe:\n    __slots__ = {'_lock': 'documentation'}\n",
    "class Probe:\n    __slots__ = '_lock'\n",
    "class Probe:\n    __slots__ = ('_lock', *other_slots)\n",
    "class Probe:\n    __slots__ = make_slots('_lock')\n",
    "class Probe:\n    other[(_lock := 1)] = 2\n",
    "_lock += 1\n",
    "class Probe:\n    _lock += 1\n",
    "class Probe:\n    def method(self):\n        self._lock += 1\n",
])
def test_r6_inventory_bindings_do_not_imply_local_ownership(tmp_path, source):
    (tmp_path / "tools").mkdir()
    rel = "tools/hierarchy_host_authority.py"
    (tmp_path / rel).write_text(source + "other_module.store._lock\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="name is not defined by the module"):
        private_codec_reaches(tmp_path, owned_names={(rel, "_lock")})


@pytest.mark.parametrize("source", [
    "def _lock(): pass\nx._lock\n",
    "async def _lock(): pass\nx._lock\n",
    "class Probe:\n    def _lock(self): pass\nx._lock\n",
    "class Probe:\n    async def _lock(self): pass\nx._lock\n",
])
def test_r6_local_function_definitions_prove_owned_names(tmp_path, source):
    (tmp_path / "tools").mkdir()
    rel = "tools/hierarchy_host_authority.py"
    (tmp_path / rel).write_text(source, encoding="utf-8")
    assert private_codec_reaches(tmp_path, owned_names={(rel, "_lock")}) == []


@pytest.mark.parametrize("module", ["message_codec", "message_codec_store"])
@pytest.mark.parametrize("scope", ["module", "class"])
@pytest.mark.parametrize("statement", [
    "mapping[(_hidden := 1)] = 2",
    "(_hidden := object()).member = 1",
    "mapping[(_hidden := 1)]: int",
    "(_hidden := object()).member: int = 1",
    "mapping[(_hidden := 1)] += 2",
    "(_hidden := object()).member += 1",
    "for mapping[(_hidden := 1)] in ():\n    pass",
    "for (_hidden := object()).member in ():\n    pass",
    "with context() as mapping[(_hidden := 1)]:\n    pass",
    "with context() as (_hidden := object()).member:\n    pass",
    "public, (mapping[(_hidden := 1)],) = values",
    "public, (_hidden := object()).member = values",
    "[*mapping[(_hidden := 1)], public] = values",
    "mapping[(lambda value=(_hidden := 1): value)()] = 2",
])
def test_r8_target_walrus_bindings_enter_inventory_and_refuse_reach(tmp_path, module, scope, statement):
    core = tmp_path / "aegis_core"
    core.mkdir()
    source = statement + "\n"
    if scope == "class":
        source = "class Probe:\n" + "".join("    " + line + "\n" for line in statement.splitlines())
    for name in ("message_codec", "message_codec_store"):
        (core / (name + ".py")).write_text(source if name == module else "", encoding="utf-8")
    assert codec_private_names(tmp_path) == {"_hidden"}
    tools = tmp_path / "tools"
    tools.mkdir()
    for reach in ("from aegis_core." + module + " import _hidden", "codec._hidden", "'_hidden'"):
        (tools / "probe.py").write_text(reach + "\n", encoding="utf-8")
        assert private_codec_reaches(tmp_path, codec_root=tmp_path) == [("tools/probe.py", 1, "_hidden")]


@pytest.mark.parametrize("statement", [
    "mapping[tuple((_hidden := _local) for _local in ())] = 2",
    "mapping[[(_hidden := _local) for _local in ()]]: int",
    "mapping[{(_hidden := _local) for _local in ()}] += 1",
    "mapping[{_local: (_hidden := _local) for _local in ()}] = 2",
])
def test_r8_target_comprehension_walrus_binds_in_module_scope(tmp_path, statement):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "message_codec.py").write_text(statement + "\n", encoding="utf-8")
    (core / "message_codec_store.py").write_text("", encoding="utf-8")
    assert codec_private_names(tmp_path) == {"_hidden", "_local"}
    (tmp_path / "tools").mkdir()
    for reach in ("from aegis_core.message_codec import _hidden", "codec._hidden", "'_hidden'"):
        (tmp_path / "tools" / "probe.py").write_text(reach + "\n", encoding="utf-8")
        assert private_codec_reaches(tmp_path, codec_root=tmp_path) == [("tools/probe.py", 1, "_hidden")]


@pytest.mark.parametrize("source", [
    "def public():\n    mapping[(_hidden := 1)] = 2\n",
    "async def public():\n    mapping[(_hidden := 1)] = 2\n",
    "class Probe:\n    def public(self):\n        mapping[(_hidden := 1)] = 2\n",
    "mapping[(lambda: (_hidden := 1))()] = 2\n",
    "class Probe:\n    mapping[(lambda: (_hidden := 1))()] = 2\n",
    "def public():\n    mapping[tuple((_hidden := item) for item in ())] = 2\n",
    "mapping[(lambda: [(_hidden := item) for item in ()])()] = 2\n",
])
def test_r8_target_walrus_bindings_in_function_scopes_are_included(tmp_path, source):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "message_codec.py").write_text(source, encoding="utf-8")
    (core / "message_codec_store.py").write_text("", encoding="utf-8")
    assert codec_private_names(tmp_path) == {"_hidden"}


@pytest.mark.parametrize("source", [
    "class Probe:\n    _lock: int\nother._lock\n",
    "class Probe:\n    def method(self):\n        self._lock: int\nother._lock\n",
])
def test_r9_bare_annotations_do_not_prove_ownership(tmp_path, source):
    (tmp_path / "tools").mkdir()
    rel = "tools/hierarchy_host_authority.py"
    (tmp_path / rel).write_text(source, encoding="utf-8")
    with pytest.raises(AssertionError, match="name is not defined by the module"):
        private_codec_reaches(tmp_path, owned_names={(rel, "_lock")})


@pytest.mark.parametrize("source,name,minimum", [
    ("def public():\n    global _hidden\n    _hidden = 1\n", "_hidden", (3, 9)),
    ("def public():\n    global _hidden\n    (_hidden := 1)\n", "_hidden", (3, 9)),
    ("if False:\n    match 1:\n        case _hidden: pass\n", "_hidden", (3, 10)),
    ("if False:\n    match [1]:\n        case [*_hidden]: pass\n", "_hidden", (3, 10)),
    ("if False:\n    match {}:\n        case {**_hidden}: pass\n", "_hidden", (3, 10)),
    ("class Public:\n    if False:\n        match 1:\n            case _hidden: pass\n", "_hidden", (3, 10)),
    ("if False:\n    type _Hidden = int\n", "_Hidden", (3, 12)),
    ("class Public:\n    if False:\n        type _Hidden = int\n", "_Hidden", (3, 12)),
    ("class Public:\n    class Nested: pass\nPublic.Nested._hidden = 1\n", "_hidden", (3, 9)),
])
def test_r9_runtime_bindings_enter_inventory_and_refuse_reach(tmp_path, source, name, minimum):
    if sys.version_info < minimum:
        pytest.skip("planted syntax requires Python " + ".".join(map(str, minimum)))
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "message_codec.py").write_text(source, encoding="utf-8")
    (core / "message_codec_store.py").write_text("", encoding="utf-8")
    namespace = {"__name__": "aegis_core.message_codec"}
    exec(compile(source, "planted-codec.py", "exec"), namespace)
    module = SimpleNamespace(**namespace)
    runtime_modules = (module, ModuleType("aegis_core.message_codec_store"))
    assert name in codec_private_names(tmp_path, runtime_modules=runtime_modules)
    (tmp_path / "tools").mkdir()
    for reach in ("from aegis_core.message_codec import " + name, "codec." + name, repr(name)):
        (tmp_path / "tools" / "probe.py").write_text(reach + "\n", encoding="utf-8")
        assert private_codec_reaches(tmp_path, codec_root=tmp_path, runtime_modules=runtime_modules) == [
            ("tools/probe.py", 1, name)]


@pytest.mark.parametrize("receiver", ["self", "cls"])
@pytest.mark.parametrize("expression", [
    "[item for RECEIVER._hidden in ()]",
    "{item for RECEIVER._hidden in ()}",
    "{item: item for RECEIVER._hidden in ()}",
    "(item for RECEIVER._hidden in ())",
    "[item for RECEIVER in [item for RECEIVER._hidden in ()]]",
    "helper = lambda RECEIVER=[item for RECEIVER._hidden in ()]: RECEIVER",
    "def helper(value=[item for RECEIVER._hidden in ()]): pass",
    "class Helper(tuple(item for RECEIVER._hidden in ())): pass",
])
def test_r9_method_comprehension_stores_enter_inventory_and_refuse_reach(tmp_path, receiver, expression):
    source = "class Public:\n    def method(" + receiver + "):\n        " + expression.replace("RECEIVER", receiver) + "\n"
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "message_codec.py").write_text(source, encoding="utf-8")
    (core / "message_codec_store.py").write_text("", encoding="utf-8")
    assert codec_private_names(tmp_path) == {"_hidden"}
    (tmp_path / "tools").mkdir()
    for reach in ("from aegis_core.message_codec import _hidden", "codec._hidden", "'_hidden'"):
        (tmp_path / "tools" / "probe.py").write_text(reach + "\n", encoding="utf-8")
        assert private_codec_reaches(tmp_path, codec_root=tmp_path) == [("tools/probe.py", 1, "_hidden")]


@pytest.mark.parametrize("source", [
    "class Public:\n    def method(self):\n        [item for self in () for self._hidden in ()]\n",
    "class Public:\n    def method(cls):\n        [item for cls in () for cls._hidden in ()]\n",
    "class Public:\n    def method(self):\n        helper = lambda self: [item for self._hidden in ()]\n",
])
def test_r9_shadowed_or_nested_comprehension_stores_are_included(tmp_path, source):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "message_codec.py").write_text(source, encoding="utf-8")
    (core / "message_codec_store.py").write_text("", encoding="utf-8")
    assert codec_private_names(tmp_path) == {"_hidden"}


@pytest.mark.parametrize("module", ["message_codec", "message_codec_store"])
@pytest.mark.parametrize("source", [
    "from collections import namedtuple\nPublic = namedtuple('Public', ())\n",
    "from typing import NamedTuple\nclass Public(NamedTuple):\n    value: int\n",
])
def test_r10_generated_namedtuple_protocol_names_are_not_private_codec_names(tmp_path, module, source):
    core = tmp_path / "aegis_core"
    core.mkdir()
    for name in ("message_codec", "message_codec_store"):
        (core / (name + ".py")).write_text(source if name == module else "", encoding="utf-8")
    namespace = {"__name__": "aegis_core." + module}
    exec(compile(source, "planted-namedtuple.py", "exec"), namespace)
    runtime = SimpleNamespace(**namespace)
    assert codec_private_names(tmp_path, runtime_modules=(runtime,)) == set()


@pytest.mark.parametrize("module", ["message_codec", "message_codec_store"])
@pytest.mark.parametrize("name", ["_make", "_asdict", "_replace", "_fields", "_field_defaults"])
def test_r10_source_defined_protocol_names_stay_inventoried_and_refused(tmp_path, module, name):
    core = tmp_path / "aegis_core"
    core.mkdir()
    source = "class Public:\n    def " + name + "(self): pass\n"
    for member in ("message_codec", "message_codec_store"):
        (core / (member + ".py")).write_text(source if member == module else "", encoding="utf-8")
    namespace = {"__name__": "aegis_core." + module}
    exec(compile(source, "planted-own-method.py", "exec"), namespace)
    runtime = SimpleNamespace(**namespace)
    assert codec_private_names(tmp_path, runtime_modules=(runtime,)) == {name}
    (tmp_path / "tools").mkdir()
    for reach in ("from aegis_core." + module + " import " + name, "codec." + name, repr(name)):
        (tmp_path / "tools" / "probe.py").write_text(reach + "\n", encoding="utf-8")
        assert private_codec_reaches(tmp_path, codec_root=tmp_path, runtime_modules=(runtime,)) == [
            ("tools/probe.py", 1, name)]


def test_r10_namedtuple_subclass_own_asdict_stays_inventoried_and_refused(tmp_path):
    core = tmp_path / "aegis_core"
    core.mkdir()
    source = ("from typing import NamedTuple\nclass Base(NamedTuple):\n    value: int\n"
              "class Public(Base):\n    def _asdict(self): pass\n")
    (core / "message_codec.py").write_text(source, encoding="utf-8")
    (core / "message_codec_store.py").write_text("", encoding="utf-8")
    namespace = {"__name__": "aegis_core.message_codec"}
    exec(compile(source, "planted-own-asdict.py", "exec"), namespace)
    runtime = SimpleNamespace(**namespace)
    assert codec_private_names(tmp_path, runtime_modules=(runtime,)) == {"_asdict"}
    (tmp_path / "tools").mkdir()
    for reach in ("from aegis_core.message_codec import _asdict", "codec._asdict", "'_asdict'"):
        (tmp_path / "tools" / "probe.py").write_text(reach + "\n", encoding="utf-8")
        assert private_codec_reaches(tmp_path, codec_root=tmp_path, runtime_modules=(runtime,)) == [
            ("tools/probe.py", 1, "_asdict")]


@pytest.mark.parametrize("module", ["message_codec", "message_codec_store"])
@pytest.mark.parametrize("scope", ["function", "async", "nested", "method"])
@pytest.mark.parametrize("statement", [
    "_hidden = 1",
    "_hidden: int = 1",
    "_hidden += 1",
    "for _hidden in ():\n    pass",
    "with context() as _hidden:\n    pass",
    "(_hidden := 1)",
    "public, (_hidden, *rest) = values",
    "mapping[(_hidden := 1)] = 2",
    "result = [(_hidden := item) for item in ()]",
    "result = lambda value=(_hidden := 1): value",
    "def nested(value=(_hidden := 1)): pass",
    "class Nested((_hidden := object)): pass",
    "import os as _hidden",
    "from os import name as _hidden",
    "try: pass\nexcept Exception as _hidden: pass",
    "def _hidden(): pass",
    "class _hidden: pass",
])
def test_r11_uncalled_function_globals_enter_static_inventory_and_refuse_reach(tmp_path, module, scope, statement):
    source = "def public():\n    global _hidden\n" + "".join(
        "    " + line + "\n" for line in statement.splitlines())
    if scope == "async":
        source = "async " + source
    elif scope == "nested":
        source = "def outer():\n" + "".join("    " + line + "\n" for line in source.splitlines())
    elif scope == "method":
        source = "class Public:\n" + "".join("    " + line + "\n" for line in source.splitlines())
    core = tmp_path / "aegis_core"
    core.mkdir()
    for name in ("message_codec", "message_codec_store"):
        (core / (name + ".py")).write_text(source if name == module else "", encoding="utf-8")
    assert codec_private_names(tmp_path, runtime_modules=()) == {"_hidden"}
    (tmp_path / "tools").mkdir()
    for reach in ("codec.public(); codec._hidden", "from aegis_core." + module + " import _hidden", "'_hidden'"):
        (tmp_path / "tools" / "probe.py").write_text(reach + "\n", encoding="utf-8")
        assert private_codec_reaches(tmp_path, codec_root=tmp_path, runtime_modules=()) == [
            ("tools/probe.py", 1, "_hidden")]


@pytest.mark.parametrize("source", [
    "def public():\n    global _hidden\n",
    "def public():\n    global _hidden\n    def nested():\n        _hidden = 1\n",
    "def public():\n    global _hidden\n    result = lambda: (_hidden := 1)\n",
    "def public():\n    global _hidden\n    result = [item for _hidden in ()]\n",
    "def public():\n    global _hidden\n    other._hidden = 1\n",
    "def public():\n    _hidden = 1\n",
    "def public():\n    _hidden = 1\n    def nested():\n        nonlocal _hidden\n        _hidden = 2\n",
])
def test_r11_declarations_and_other_scope_bindings_are_included(tmp_path, source):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "message_codec.py").write_text(source, encoding="utf-8")
    (core / "message_codec_store.py").write_text("", encoding="utf-8")
    assert codec_private_names(tmp_path, runtime_modules=()) == {"_hidden"}


@pytest.mark.parametrize("module", ["message_codec", "message_codec_store"])
@pytest.mark.parametrize("scope", ["module", "class", "global_function"])
@pytest.mark.parametrize("statement,name,minimum", [
    ("match 1:\n    case _hidden: pass", "_hidden", (3, 10)),
    ("match [1]:\n    case [*_hidden]: pass", "_hidden", (3, 10)),
    ("match {}:\n    case {**_hidden}: pass", "_hidden", (3, 10)),
    ("type _Hidden = int", "_Hidden", (3, 12)),
])
def test_r11_untaken_bindings_enter_static_inventory_and_refuse_reach(tmp_path, module, scope, statement, name, minimum):
    if sys.version_info < minimum:
        pytest.skip("planted syntax requires Python " + ".".join(map(str, minimum)))
    source = "if False:\n" + "".join("    " + line + "\n" for line in statement.splitlines())
    if scope == "class":
        source = "class Public:\n" + "".join("    " + line + "\n" for line in source.splitlines())
    elif scope == "global_function":
        source = "def public():\n    global " + name + "\n" + "".join(
            "    " + line + "\n" for line in source.splitlines())
    core = tmp_path / "aegis_core"
    core.mkdir()
    for member in ("message_codec", "message_codec_store"):
        (core / (member + ".py")).write_text(source if member == module else "", encoding="utf-8")
    namespace = {"__name__": "aegis_core." + module}
    exec(compile(source, "planted-untaken.py", "exec"), namespace)
    assert name not in namespace
    assert codec_private_names(tmp_path, runtime_modules=()) == {name}
    (tmp_path / "tools").mkdir()
    for reach in ("from aegis_core." + module + " import " + name, "codec." + name, repr(name)):
        (tmp_path / "tools" / "probe.py").write_text(reach + "\n", encoding="utf-8")
        assert private_codec_reaches(tmp_path, codec_root=tmp_path, runtime_modules=()) == [
            ("tools/probe.py", 1, name)]


@pytest.mark.parametrize("source,name,minimum", [
    ("match 0:\n    case 1 as _hidden: pass\n", "_hidden", (3, 10)),
    ("class Public:\n    class Nested: pass\nPublic.Nested._asdict = 1\n", "_asdict", (3, 9)),
    ("class Public:\n    class Nested: pass\nif False:\n    Public.Nested._asdict = 1\n", "_asdict", (3, 9)),
])
def test_r11_argon_exact_source_bindings_are_inventoried_and_refused(tmp_path, source, name, minimum):
    if sys.version_info < minimum:
        pytest.skip("planted syntax requires Python " + ".".join(map(str, minimum)))
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "message_codec.py").write_text(source, encoding="utf-8")
    (core / "message_codec_store.py").write_text("", encoding="utf-8")
    namespace = {"__name__": "aegis_core.message_codec"}
    exec(compile(source, "argon-exact.py", "exec"), namespace)
    runtime = SimpleNamespace(**namespace)
    assert codec_private_names(tmp_path, runtime_modules=()) == {name}
    assert codec_private_names(tmp_path, runtime_modules=(runtime,)) == {name}
    (tmp_path / "tools").mkdir()
    for reach in ("codec." + name, "from aegis_core.message_codec import " + name, repr(name)):
        (tmp_path / "tools" / "probe.py").write_text(reach + "\n", encoding="utf-8")
        assert private_codec_reaches(tmp_path, codec_root=tmp_path, runtime_modules=(runtime,)) == [
            ("tools/probe.py", 1, name)]


@pytest.mark.parametrize("name", ["_make", "_asdict", "_replace", "_fields", "_field_defaults"])
@pytest.mark.parametrize("owner", ["module", "ordinary_class"])
def test_r11_argon_nonprotocol_runtime_bindings_are_not_discarded(tmp_path, name, owner):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "message_codec.py").write_text("", encoding="utf-8")
    (core / "message_codec_store.py").write_text("", encoding="utf-8")
    source = (name + " = 1\n" if owner == "module" else
              "class Public:\n    class Nested: pass\nPublic.Nested." + name + " = 1\n")
    namespace = {"__name__": "aegis_core.message_codec"}
    exec(compile(source, "argon-runtime.py", "exec"), namespace)
    runtime = SimpleNamespace(**namespace)
    assert codec_private_names(tmp_path, runtime_modules=(runtime,)) == {name}
    (tmp_path / "tools").mkdir()
    for reach in ("codec." + name, "from aegis_core.message_codec import " + name, repr(name)):
        (tmp_path / "tools" / "probe.py").write_text(reach + "\n", encoding="utf-8")
        assert private_codec_reaches(tmp_path, codec_root=tmp_path, runtime_modules=(runtime,)) == [
            ("tools/probe.py", 1, name)]


@pytest.mark.parametrize("name", ["_make", "_asdict", "_replace", "_fields", "_field_defaults"])
@pytest.mark.parametrize("statement,minimum", [
    ("def public():\n    global NAME\n    NAME = 1\n", (3, 9)),
    ("match 0:\n    case 1 as NAME: pass\n", (3, 10)),
    ("if False:\n    type NAME = int\n", (3, 12)),
])
def test_r11_argon_untaken_protocol_spellings_stay_private(tmp_path, name, statement, minimum):
    if sys.version_info < minimum:
        pytest.skip("planted syntax requires Python " + ".".join(map(str, minimum)))
    source = statement.replace("NAME", name)
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "message_codec.py").write_text(source, encoding="utf-8")
    (core / "message_codec_store.py").write_text("", encoding="utf-8")
    assert codec_private_names(tmp_path, runtime_modules=()) == {name}
    (tmp_path / "tools").mkdir()
    for reach in ("codec." + name, "from aegis_core.message_codec import " + name, repr(name)):
        (tmp_path / "tools" / "probe.py").write_text(reach + "\n", encoding="utf-8")
        assert private_codec_reaches(tmp_path, codec_root=tmp_path, runtime_modules=()) == [
            ("tools/probe.py", 1, name)]


@pytest.mark.parametrize("receiver", ["self", "cls"])
@pytest.mark.parametrize("statement", [
    "[x for mapping[[y for RECEIVER in ()]] in () for RECEIVER._hidden in ()]",
    "class Inner:\n    RECEIVER._hidden = 1",
    "class Inner:\n    [x for RECEIVER._hidden in ()]",
])
def test_r11_argon_exact_enclosing_receiver_stores_are_inventoried(tmp_path, receiver, statement):
    source = "class Public:\n    def method(" + receiver + "):\n" + "".join(
        "        " + line.replace("RECEIVER", receiver) + "\n" for line in statement.splitlines())
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "message_codec.py").write_text(source, encoding="utf-8")
    (core / "message_codec_store.py").write_text("", encoding="utf-8")
    assert codec_private_names(tmp_path, runtime_modules=()) == {"_hidden"}
    (tmp_path / "tools").mkdir()
    for reach in ("codec._hidden", "from aegis_core.message_codec import _hidden", "'_hidden'"):
        (tmp_path / "tools" / "probe.py").write_text(reach + "\n", encoding="utf-8")
        assert private_codec_reaches(tmp_path, codec_root=tmp_path, runtime_modules=()) == [
            ("tools/probe.py", 1, "_hidden")]


@pytest.mark.parametrize("statement", [
    "class Inner:\n    self = object()\n    self._hidden = 1",
    "class Inner:\n    def method(self):\n        self._hidden = 1",
])
def test_r11_argon_nested_class_bindings_are_receiver_independent(tmp_path, statement):
    source = "class Public:\n    def method(self):\n" + "".join(
        "        " + line + "\n" for line in statement.splitlines())
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "message_codec.py").write_text(source, encoding="utf-8")
    (core / "message_codec_store.py").write_text("", encoding="utf-8")
    assert codec_private_names(tmp_path, runtime_modules=()) == {"_hidden"}


@pytest.mark.parametrize("module", ["message_codec", "message_codec_store"])
@pytest.mark.parametrize("factory", ["function", "async", "method"])
@pytest.mark.parametrize("statement", [
    "_hidden = 1",
    "def _hidden(self): pass",
    "__slots__ = ('_hidden',)",
    "from json import loads as _hidden",
])
def test_r12_uncalled_factory_class_bindings_are_inventoried_and_refused(tmp_path, module, factory, statement):
    source = "def public():\n    class Result:\n" + "".join(
        "        " + line + "\n" for line in statement.splitlines()) + "    return Result\n"
    if factory == "async":
        source = "async " + source
    elif factory == "method":
        source = "class Public:\n" + "".join("    " + line + "\n" for line in source.splitlines())
    core = tmp_path / "aegis_core"
    core.mkdir()
    for name in ("message_codec", "message_codec_store"):
        (core / (name + ".py")).write_text(source if name == module else "", encoding="utf-8")
    assert codec_private_names(tmp_path, runtime_modules=()) == {"_hidden"}
    (tmp_path / "tools").mkdir()
    for reach in ("codec.public()._hidden", "from aegis_core." + module + " import _hidden", "'_hidden'"):
        (tmp_path / "tools" / "probe.py").write_text(reach + "\n", encoding="utf-8")
        assert private_codec_reaches(tmp_path, codec_root=tmp_path, runtime_modules=()) == [
            ("tools/probe.py", 1, "_hidden")]


@pytest.mark.parametrize("receiver", ["self", "cls"])
@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("expression", [
    "[None for RECEIVER._hidden in (1,)]",
    "{None for RECEIVER._hidden in (1,)}",
    "{None: None for RECEIVER._hidden in (1,)}",
    "(None for RECEIVER._hidden in (1,))",
])
def test_r12_class_receiver_shadowing_cannot_hide_binding_names(tmp_path, receiver, nested, expression):
    expression = expression.replace("RECEIVER", receiver)
    body = "class Deeper:\n    " + expression if nested else expression
    source = ("class Public:\n    def method(" + receiver + "):\n        class Inner:\n            "
              + receiver + " = None\n" + "".join("            " + line + "\n" for line in body.splitlines()))
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "message_codec.py").write_text(source, encoding="utf-8")
    (core / "message_codec_store.py").write_text("", encoding="utf-8")
    assert codec_private_names(tmp_path, runtime_modules=()) == {"_hidden"}
    (tmp_path / "tools").mkdir()
    for reach in ("obj.method(); obj._hidden", "from aegis_core.message_codec import _hidden", "'_hidden'"):
        (tmp_path / "tools" / "probe.py").write_text(reach + "\n", encoding="utf-8")
        assert private_codec_reaches(tmp_path, codec_root=tmp_path, runtime_modules=()) == [
            ("tools/probe.py", 1, "_hidden")]


@pytest.mark.parametrize("source,minimum", [
    ("def public():\n    _hidden = 1\n", (3, 9)),
    ("def public(_hidden): pass\n", (3, 9)),
    ("def public(_hidden, /): pass\n", (3, 9)),
    ("def public(*, _hidden): pass\n", (3, 9)),
    ("def public(*_hidden): pass\n", (3, 9)),
    ("def public(**_hidden): pass\n", (3, 9)),
    ("def public():\n    del _hidden\n", (3, 9)),
    ("def public():\n    del other._hidden\n", (3, 9)),
    ("def public():\n    other._hidden = 1\n", (3, 9)),
    ("def public():\n    global _hidden\n", (3, 9)),
    ("def public():\n    nonlocal _hidden\n", (3, 9)),
    ("def public():\n    marker = '_hidden'\n", (3, 9)),
    ("def public():\n    setattr(other, '_hidden', 1)\n", (3, 9)),
    ("def public[_hidden](): pass\n", (3, 12)),
    ("def public[*_hidden](): pass\n", (3, 12)),
    ("def public[**_hidden](): pass\n", (3, 12)),
    ("class Public[_hidden]: pass\n", (3, 12)),
    ("type Public[_hidden] = tuple[_hidden]\n", (3, 12)),
])
def test_r12_any_depth_binding_forms_are_inventoried_and_refused(tmp_path, source, minimum):
    if sys.version_info < minimum:
        pytest.skip("planted syntax requires Python " + ".".join(map(str, minimum)))
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "message_codec.py").write_text(source, encoding="utf-8")
    (core / "message_codec_store.py").write_text("", encoding="utf-8")
    assert codec_private_names(tmp_path, runtime_modules=()) == {"_hidden"}
    (tmp_path / "tools").mkdir()
    for reach in ("codec._hidden", "from aegis_core.message_codec import _hidden", "'_hidden'"):
        (tmp_path / "tools" / "probe.py").write_text(reach + "\n", encoding="utf-8")
        assert private_codec_reaches(tmp_path, codec_root=tmp_path, runtime_modules=()) == [
            ("tools/probe.py", 1, "_hidden")]


def test_r12_bare_underscore_dunders_and_nonidentifier_literals_are_excluded(tmp_path):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "message_codec.py").write_text(
        "def __public__(_):\n    _ = 1\n    del _\n    other._ = 1\n    other.__private__ = 1\n"
        "    markers = ('_', '__private__', '_not an identifier', '_with.dot')\n", encoding="utf-8")
    (core / "message_codec_store.py").write_text("", encoding="utf-8")
    assert codec_private_names(tmp_path, runtime_modules=()) == set()


@pytest.mark.parametrize("source,name", [
    ("def public():\n    _local = 1\n", "_local"),
    ("def public(_argument): pass\n", "_argument"),
])
def test_r12_function_locals_and_args_refuse_tools_reach(tmp_path, source, name):
    core = tmp_path / "aegis_core"
    core.mkdir()
    (core / "message_codec.py").write_text(source, encoding="utf-8")
    (core / "message_codec_store.py").write_text("", encoding="utf-8")
    assert codec_private_names(tmp_path, runtime_modules=()) == {name}
    (tmp_path / "tools").mkdir()
    for reach in ("codec." + name, "from aegis_core.message_codec import " + name, repr(name)):
        (tmp_path / "tools" / "probe.py").write_text(reach + "\n", encoding="utf-8")
        assert private_codec_reaches(tmp_path, codec_root=tmp_path, runtime_modules=()) == [
            ("tools/probe.py", 1, name)]
