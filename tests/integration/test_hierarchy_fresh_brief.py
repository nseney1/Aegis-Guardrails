"""Fresh-thread briefs through the CLI; records remain inert claims.

The real-dispatcher invariant table is the primary writer-release barrier.
Structural checks are secondary syntax allowlists: they do not prove Python
control flow, binding identity or absence of side effects. Runtime mutation
controls cover those subtler forms without treating an AST match as proof.
"""
import ast
import errno
import hashlib
import itertools
import json
import os
from pathlib import Path, PureWindowsPath
import shutil
import stat
import subprocess
import sys
from types import FunctionType, SimpleNamespace

import pytest

from tests.integration.test_hierarchy_mailbox import ROOT, invoke, message, pilot, receipt_fixture  # noqa: F401
from tests.integration.test_hierarchy_handoff import active_writer, handoff
from tests.integration.test_hierarchy_host_plan import write_plan
from tests.integration.test_hierarchy_lifecycle import Ledger, SOURCE, raw_request, request, pytestmark as lifecycle_only
from tests.integration.test_hierarchy_small_change_admission import SmallChange
from tools.hierarchy_mailbox import Mailbox, safe_path
import hierarchy_router as alias_router
from tools import hierarchy_fresh_brief as alias_fresh
import hierarchy_fresh_brief as portable_fresh
from tests.conftest import symlink_or_skip


TOOL = ROOT / "tools" / "hierarchy_fresh_brief.py"


R17_CHAIN_SHAPES = ("direct", "target-prefix", "two-nested", "ancestor-suffix")
R17_LEAF_OUTCOMES = ("absent", "enotdir", "eacces", "eio", "present")
R17_CHAIN_SETUP = r'''
import errno
from types import SimpleNamespace
ordinary, public, real = root / 'ordinary', root / 'public', root / 'real'
real.mkdir()
leaf = real / 'note.md'
if shape == 'direct':
    ordinary.unlink(); ordinary.mkdir()
    (ordinary / 'note.md').symlink_to(leaf)
elif shape == 'target-prefix':
    (public / 'note.md').unlink()
    (public / 'note.md').symlink_to(root / 'hop' / 'note.md')
    (root / 'hop').symlink_to(real, target_is_directory=True)
elif shape == 'two-nested':
    ordinary.unlink(); ordinary.mkdir()
    (ordinary / 'note.md').symlink_to(root / 'hop' / 'note.md')
    (root / 'hop').symlink_to(root / 'hop2', target_is_directory=True)
    (root / 'hop2').symlink_to(real, target_is_directory=True)
else:
    (real / 'sub').mkdir()
    leaf = real / 'sub' / 'note.md'
    ordinary.unlink()
    ordinary.symlink_to(root / 'hop' / 'sub', target_is_directory=True)
    (root / 'hop').symlink_to(real, target_is_directory=True)
if outcome != 'absent': leaf.write_bytes(b'public final leaf')
real_os, descriptors = fresh.os, {}
codes = dict(enotdir=errno.ENOTDIR, eacces=errno.EACCES, eio=errno.EIO, enoent=errno.ENOENT)
def actual(path, kwargs):
    if isinstance(path, int): return None
    value = Path(path)
    parent = descriptors.get(kwargs.get('dir_fd'))
    return parent / value if not value.is_absolute() and parent is not None else value
def failure(code):
    if code == 'no-errno': raise PermissionError('controlled proof failure')
    raise OSError(codes[code], real_os.strerror(codes[code]), str(leaf))
def stated(path, *args, **kwargs):
    if actual(path, kwargs) == leaf and outcome in ('enotdir', 'eacces', 'eio'):
        failure(outcome)
    return real_os.stat(path, *args, **kwargs)
def opened(path, *args, **kwargs):
    value = actual(path, kwargs)
    if outcome.startswith('proof-') and outcome != 'proof-result' and value == leaf.parent:
        failure(outcome[len('proof-'):])
    descriptor = real_os.open(path, *args, **kwargs)
    descriptors[descriptor] = value
    return descriptor
def closed(descriptor):
    descriptors.pop(descriptor, None)
    return real_os.close(descriptor)
fresh.os = SimpleNamespace(**{**vars(real_os), 'stat': stated, 'open': opened, 'close': closed})
if outcome == 'proof-result':
    original_lookup = fresh._LeafLookup
    class FailedResult(original_lookup):
        def __init__(self, kind, value, proof):
            if proof.leaf == leaf: raise MemoryError('controlled result allocation failure')
            super().__init__(kind, value, proof)
    fresh._LeafLookup = FailedResult
target = root / 'ordinary' / 'note.md'
'''


def r17_chain_probe(shape, outcome):
    # Both values come from the fixed test matrix, never from a request.
    assert shape in R17_CHAIN_SHAPES
    assert outcome in R17_LEAF_OUTCOMES or outcome in {
        "proof-enoent", "proof-enotdir", "proof-eacces", "proof-eio", "proof-no-errno", "proof-result"}
    return R9_PUBLIC_PROBE.replace("tools, fallback, root, seam, backend = sys.argv[1:]",
        "tools, fallback, root, seam, backend, fault = sys.argv[1:]").replace(
        "target = root / 'ordinary' / 'note.md'",
        "shape = " + repr(shape) + "\noutcome = " + repr(outcome) + "\n" + R17_CHAIN_SETUP)


@lifecycle_only
@pytest.mark.parametrize("shape", R17_CHAIN_SHAPES)
@pytest.mark.parametrize("outcome", R17_LEAF_OUTCOMES)
@pytest.mark.parametrize("seam", ["disposition", "resolve"])
@pytest.mark.parametrize("backend", ["native", "portable"])
@pytest.mark.parametrize("inert", [False, True])
def test_round17_pathname_final_leaf_keeps_baseline_bytes(tmp_path, shape, outcome, seam, backend, inert):
    if not portable_fresh._descriptor_capabilities() or portable_fresh._symlink_reader() is None:
        pytest.skip("bounded directory-relative link proof unavailable")
    consumer = "shared-" + seam if inert else seam
    if shape in {"direct", "two-nested"}:
        expected = R13_LEAF_GOLDENS[(consumer, False, backend)]
    elif outcome in {"eacces", "eio"}:
        expected = R10_PUBLIC_GOLDENS[(consumer, "link-to-denied" if outcome == "eacces" else "link-to-io", False, backend)]
    else:
        expected = R9_PUBLIC_GOLDENS[(consumer, "symlink", False, backend)]
    assert r9_public_probe(tmp_path, consumer, "symlink", False, backend,
        _probe=r17_chain_probe(shape, outcome)) == expected


@lifecycle_only
@pytest.mark.parametrize("shape", R17_CHAIN_SHAPES)
@pytest.mark.parametrize("fault", ["enoent", "enotdir", "eacces", "eio", "no-errno", "result"])
@pytest.mark.parametrize("seam", ["disposition", "resolve"])
@pytest.mark.parametrize("backend", ["native", "portable"])
def test_round17_parent_proof_failure_is_quarantined_and_consumed(tmp_path, shape, fault, seam, backend):
    if not portable_fresh._descriptor_capabilities() or portable_fresh._symlink_reader() is None:
        pytest.skip("bounded directory-relative link proof unavailable")
    probe = r17_chain_probe(shape, "proof-" + fault).replace(
        "print(json.dumps({'result': result}, sort_keys=True))", """
assert journal.refusals_for('hostile', consume=True)
assert journal.refusals_for('hostile', consume=True)
assert journal.refusals_for('healthy', consume=True) == []
journal.operation.verify()
assert journal.operation.path_guard._global_failure is None
print(json.dumps({'result': result}, sort_keys=True))
""")
    status, raw, stderr = r9_public_probe(tmp_path, seam, "symlink", False, backend, _probe=probe)
    assert status == 0 and stderr == b"", (status, raw, stderr)
    result = json.loads(raw)["result"]
    assert {"first", "healthy", "hostile"} <= set(result["requests"])
    assert result["unknown"] == {}
    assert result["refusals"]["hostile"]
    assert "healthy" not in result["refusals"]


def test_round17_only_final_leaf_lookup_assigns_leaf_refusal():
    tree = ast.parse(TOOL.read_text(encoding="utf-8"))
    assignments = []
    class Inventory(ast.NodeVisitor):
        def __init__(self): self.function = None
        def visit_FunctionDef(self, node):
            previous, self.function = self.function, node.name
            self.generic_visit(node)
            self.function = previous
        def visit_Attribute(self, node):
            if node.attr == "leaf_refusal" and isinstance(node.ctx, ast.Store):
                assignments.append(self.function)
            self.generic_visit(node)
    Inventory().visit(tree)
    assert assignments == ["_final_leaf_lookup"]


@lifecycle_only
@pytest.mark.parametrize("seam", ["disposition", "resolve"])
@pytest.mark.parametrize("backend", ["native", "portable"])
@pytest.mark.parametrize("nested", [False, True])
def test_round17_nested_leaf_witness_rejects_concurrent_replacement(tmp_path, monkeypatch, seam, backend, nested):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    if not portable_fresh._descriptor_capabilities() or portable_fresh._symlink_reader() is None:
        pytest.skip("bounded directory-relative link proof unavailable")
    world, linked, public, private, home, path = r14_trial(tmp_path, seam)
    real = tmp_path / "real"; real.mkdir()
    leaf = real / "note.md"
    (public / "note.md").unlink()
    symlink_or_skip(tmp_path / "hop" / "note.md", public / "note.md")
    if nested:
        symlink_or_skip(tmp_path / "hop2", tmp_path / "hop", target_is_directory=True)
        symlink_or_skip(real, tmp_path / "hop2", target_is_directory=True)
    else:
        symlink_or_skip(real, tmp_path / "hop", target_is_directory=True)
    entered, changed = Event(), Event()
    original = portable_fresh._final_leaf_lookup
    reached, descriptors = [], []
    def replace():
        assert entered.wait(10), "final nested leaf lookup was not reached"
        leaf.symlink_to(private, target_is_directory=True)
        changed.set()
    def lookup(proof):
        result = original(proof)
        if proof.leaf == leaf and not changed.is_set():
            assert result.kind == "absent"
            reached.append(proof.leaf_outcome); descriptors.append(proof.directory)
            entered.set()
            assert changed.wait(10), "nested leaf replacement did not complete"
        return result
    monkeypatch.setattr(alias_router, "_owner_home", lambda: home)
    monkeypatch.setattr(portable_fresh, "_reference_descriptors", lambda: backend == "native")
    monkeypatch.setattr(portable_fresh, "_final_leaf_lookup", lookup)
    with ThreadPoolExecutor(max_workers=1) as pool:
        mutation = pool.submit(replace)
        try:
            r14_assert_quarantined(world, path)
            assert reached
        finally:
            entered.set()
            mutation.result(timeout=15)
    for descriptor in set(descriptors):
        with pytest.raises(OSError) as error: os.fstat(descriptor)
        assert error.value.errno == errno.EBADF
    leaf.unlink(); leaf.write_bytes(b"healthy retry")
    r15_assert_healthy_retry(world)


def r15_trial(tmp_path,seam,shape):
    result=r14_trial(tmp_path,seam,"direct-leaf destination" if shape=="single" else "hop target")
    world,linked,public,private,home,path=result
    leaf=public/"note.md"
    if shape=="multi":
        leaf.unlink()
        leaf=public/"destination.md"
        leaf.write_bytes(b"public destination")
        symlink_or_skip(leaf,public/"note.md")
    return (*result,leaf)


def r15_assert_healthy_retry(world):
    operation=portable_fresh._Operation()
    journal=operation.lifecycle(world.ledger.path)
    _policy,state=journal.load()
    assert {"following","healthy"}<=set(state["requests"])
    assert journal.refusals_for("following")==[]
    assert journal.refusals_for("healthy")==[]
    operation.verify()
    assert operation.path_guard._global_failure is None


@lifecycle_only
@pytest.mark.parametrize("seam",["disposition","resolve"])
@pytest.mark.parametrize("backend",["native","portable"])
@pytest.mark.parametrize("shape",["single","multi"])
def test_round15_private_root_final_leaf_is_refused_before_a_second_metadata_probe(tmp_path,monkeypatch,seam,backend,shape):
    if not portable_fresh._descriptor_capabilities() or portable_fresh._symlink_reader() is None:
        pytest.skip("bounded directory-relative link proof unavailable")
    world,linked,public,private,home,path,leaf=r15_trial(tmp_path,seam,shape)
    leaf.unlink(); symlink_or_skip(private,leaf,target_is_directory=True)
    real_os=portable_fresh.os
    info=home.stat(); home_id=info.st_dev,info.st_ino
    touches=[]
    def metadata(value,*args,**kwargs):
        direct=not isinstance(value,int) and Path(value)==private
        relative=False
        if value==private.name and kwargs.get("dir_fd") is not None:
            parent=real_os.fstat(kwargs["dir_fd"])
            relative=(parent.st_dev,parent.st_ino)==home_id
        if direct or relative: touches.append("snapshot" if direct else "final leaf")
        return real_os.stat(value,*args,**kwargs)
    monkeypatch.setattr(alias_router,"_owner_home",lambda:home)
    monkeypatch.setattr(alias_router,"os",SimpleNamespace(**{**vars(real_os),"stat":metadata}))
    monkeypatch.setattr(portable_fresh,"os",SimpleNamespace(**{**vars(real_os),"stat":metadata}))
    monkeypatch.setattr(portable_fresh,"_reference_descriptors",lambda:backend=="native")
    r14_assert_quarantined(world,path)
    assert touches==["snapshot"]


@lifecycle_only
@pytest.mark.parametrize("seam",["disposition","resolve"])
@pytest.mark.parametrize("backend",["native","portable"])
@pytest.mark.parametrize("fault",["enoent","eacces"])
@pytest.mark.parametrize("shape",["ordinary","single","multi"])
def test_round15_opened_parent_aba_is_part_of_the_final_witness(tmp_path,monkeypatch,seam,backend,fault,shape):
    from concurrent.futures import ThreadPoolExecutor
    from queue import Queue
    if not portable_fresh._descriptor_capabilities() or portable_fresh._symlink_reader() is None:
        pytest.skip("bounded directory-relative link proof unavailable")
    if fault=="eacces" and (not hasattr(os,"O_PATH") or os.geteuid()==0):
        pytest.skip("real leaf-denial witness requires O_PATH and an unprivileged runner")
    world,linked,public,private,home,path,leaf=r15_trial(tmp_path,seam,shape)
    leaf.unlink()
    symlink_or_skip(private,leaf,target_is_directory=True)
    alternate=tmp_path/"alternate"; alternate.mkdir()
    parked=tmp_path/"parked"
    alternate_identity=(alternate.stat().st_dev,alternate.stat().st_ino)
    if fault=="eacces": alternate.chmod(0)
    commands,acks=Queue(),Queue()
    real_os=portable_fresh.os
    operation,token=portable_fresh._proof_operation,portable_fresh._proof_token
    flags={"active":False,"swapped":False,"restored":False,"enabled":True}
    captured=[]
    def mutate():
        while True:
            command=commands.get(timeout=20)
            if command is None: return
            if command=="swap": public.rename(parked); alternate.rename(public)
            else: public.rename(alternate); parked.rename(public)
            acks.put(True)
    def signal(command):
        commands.put(command)
        assert acks.get(timeout=10),"parent mutation did not complete"
    def proof(guard,stage,action,*args,**kwargs):
        if flags["enabled"] and action is token and args[2]==leaf:
            flags.update(active=True,swapped=False,restored=False)
            try: return operation(guard,stage,action,*args,**kwargs)
            finally: flags["active"]=False
        return operation(guard,stage,action,*args,**kwargs)
    def stated(value,*args,**kwargs):
        if flags["active"] and not flags["swapped"] and not flags["restored"] and value==public.name and kwargs.get("dir_fd") is not None:
            signal("swap"); flags["swapped"]=True
        return real_os.stat(value,*args,**kwargs)
    def fstated(descriptor):
        info=real_os.fstat(descriptor)
        if flags["active"] and flags["swapped"] and not flags["restored"] and (info.st_dev,info.st_ino)==alternate_identity:
            signal("restore"); captured.append(descriptor); flags["restored"]=True
        return info
    monkeypatch.setattr(alias_router,"_owner_home",lambda:home)
    monkeypatch.setattr(portable_fresh,"_reference_descriptors",lambda:backend=="native")
    monkeypatch.setattr(portable_fresh,"_proof_operation",proof)
    monkeypatch.setattr(portable_fresh,"os",SimpleNamespace(**{**vars(real_os),"stat":stated,"fstat":fstated}))
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            mutation=pool.submit(mutate)
            try:
                r14_assert_quarantined(world,path)
                assert captured
                for descriptor in set(captured):
                    with pytest.raises(OSError) as error: real_os.fstat(descriptor)
                    assert error.value.errno==errno.EBADF
            finally:
                commands.put(None); mutation.result(timeout=25)
    finally:
        if parked.exists(): public.rename(alternate); parked.rename(public)
        alternate.chmod(0o700)
    flags["enabled"]=False
    leaf.unlink(); leaf.write_bytes(b"healthy retry")
    r15_assert_healthy_retry(world)


@lifecycle_only
@pytest.mark.parametrize("seam",["disposition","resolve"])
@pytest.mark.parametrize("backend",["native","portable"])
@pytest.mark.parametrize("fault",["enoent","eacces"])
@pytest.mark.parametrize("replacement",["private","file","directory"])
@pytest.mark.parametrize("shape",["ordinary","single","multi"])
def test_round15_leaf_outcome_is_revalidated_before_inert_scope(tmp_path,monkeypatch,seam,backend,fault,replacement,shape):
    from concurrent.futures import ThreadPoolExecutor
    from queue import Queue
    if not portable_fresh._descriptor_capabilities() or portable_fresh._symlink_reader() is None:
        pytest.skip("bounded directory-relative link proof unavailable")
    world,linked,public,private,home,path,leaf=r15_trial(tmp_path,seam,shape)
    leaf.unlink()
    commands,acks=Queue(),Queue()
    real_os=portable_fresh.os
    original,checked=portable_fresh._final_leaf_lookup,portable_fresh._reference_check
    flags={"inside":False,"enabled":True}
    reached=[]
    def reset():
        if leaf.is_symlink() or leaf.is_file(): leaf.unlink()
        elif leaf.is_dir(): leaf.rmdir()
    def mutate():
        while True:
            command=commands.get(timeout=20)
            if command is None: return
            reset()
            if command=="replace":
                if replacement=="private": leaf.symlink_to(private,target_is_directory=True)
                elif replacement=="file": leaf.write_bytes(b"replacement public file")
                else: leaf.mkdir()
            acks.put(True)
    def signal(command):
        commands.put(command)
        assert acks.get(timeout=10),"leaf mutation did not complete"
    def check(value,*args,**kwargs):
        if flags["enabled"] and Path(value)==Path(path): signal("reset")
        return checked(value,*args,**kwargs)
    def stated(value,*args,**kwargs):
        if flags["enabled"] and flags["inside"] and value==leaf.name and kwargs.get("dir_fd") is not None and fault=="eacces":
            raise PermissionError(errno.EACCES,os.strerror(errno.EACCES),value)
        return real_os.stat(value,*args,**kwargs)
    def lookup(proof):
        target=flags["enabled"] and proof.leaf==leaf and not leaf.exists() and not leaf.is_symlink()
        flags["inside"]=target
        try: result=original(proof)
        finally: flags["inside"]=False
        if target:
            assert result.kind==("absent" if fault=="enoent" else "error")
            reached.append(result.kind); signal("replace")
        return result
    monkeypatch.setattr(alias_router,"_owner_home",lambda:home)
    monkeypatch.setattr(portable_fresh,"_reference_descriptors",lambda:backend=="native")
    monkeypatch.setattr(portable_fresh,"_reference_check",check)
    monkeypatch.setattr(portable_fresh,"_final_leaf_lookup",lookup)
    monkeypatch.setattr(portable_fresh,"os",SimpleNamespace(**{**vars(real_os),"stat":stated}))
    with ThreadPoolExecutor(max_workers=1) as pool:
        mutation=pool.submit(mutate)
        try:
            r14_assert_quarantined(world,path)
            assert reached
        finally:
            commands.put(None); mutation.result(timeout=25)
    flags["enabled"]=False
    reset(); leaf.write_bytes(b"healthy retry")
    r15_assert_healthy_retry(world)


@lifecycle_only
@pytest.mark.parametrize("seam",["disposition","resolve"])
@pytest.mark.parametrize("backend",["native","portable"])
@pytest.mark.parametrize("hops",[1,2,3])
def test_round15_last_hop_destination_uses_the_final_leaf_witness(tmp_path,monkeypatch,seam,backend,hops):
    if not portable_fresh._descriptor_capabilities() or portable_fresh._symlink_reader() is None:
        pytest.skip("bounded directory-relative link proof unavailable")
    world,linked,public,private,home,path,leaf=r15_trial(tmp_path,seam,"single" if hops==1 else "multi")
    leaf.unlink()
    if hops==3:
        symlink_or_skip(public/"last.md",leaf)
        leaf=public/"last.md"
    reached=[]
    original=portable_fresh._final_leaf_lookup
    def lookup(proof):
        result=original(proof)
        if proof.leaf==leaf:
            assert result.kind=="absent"
            reached.append(proof.leaf_outcome)
        return result
    monkeypatch.setattr(alias_router,"_owner_home",lambda:home)
    monkeypatch.setattr(portable_fresh,"_reference_descriptors",lambda:backend=="native")
    monkeypatch.setattr(portable_fresh,"_final_leaf_lookup",lookup)
    r15_assert_healthy_retry(world)
    assert reached and all(outcome==("errno",errno.ENOENT) for outcome in reached)


@lifecycle_only
@pytest.mark.parametrize("seam,planned,backend",tuple(itertools.product(
    ("paths","scope","disposition","resolve","shared-disposition","shared-resolve"),
    (False,True),("native","portable"))))
@pytest.mark.parametrize("fault",["eio","eacces"])
def test_round15_proved_direct_leaf_errno_keeps_its_baseline_consumer(tmp_path,seam,planned,backend,fault):
    if backend=="native" and not portable_fresh._reference_descriptors(): pytest.skip("directory descriptors unavailable")
    probe=R13_LEAF_PROBE.replace("ordinary in value.parents or value == public / 'note.md'",
                                "value == public / 'note.md'")
    if fault=="eacces": probe=probe.replace("errno.EIO","errno.EACCES")
    assert r9_public_probe(tmp_path,seam,"link-to-io",planned,backend,_probe=probe)==R13_LEAF_GOLDENS[(seam,planned,backend)]


R15_DANGLING_PROBE= r'''
from pathlib import Path
root = Path(root)
ordinary=root/'ordinary'
ordinary.unlink()
ordinary.symlink_to(root/'missing',target_is_directory=True)
'''


@lifecycle_only
@pytest.mark.parametrize("backend",["native","portable"])
@pytest.mark.parametrize("code",[errno.EACCES,errno.EIO])
@pytest.mark.parametrize("stage",["suffix ancestor","direct-leaf destination"])
def test_round15_direct_leaf_proof_failure_keeps_original_diagnostic(tmp_path,monkeypatch,backend,code,stage):
    if not portable_fresh._descriptor_capabilities() or portable_fresh._symlink_reader() is None:
        pytest.skip("bounded directory-relative link proof unavailable")
    world,linked,public,private,home,path=r14_trial(tmp_path,"disposition","direct-leaf destination")
    original=portable_fresh._proof_operation
    reached=[]
    def fail(): raise OSError(code,"UNTRUSTED proof failure")
    def proof(guard,layer,action,*args,**kwargs):
        if layer==stage:
            reached.append(layer)
            return original(guard,layer,fail)
        return original(guard,layer,action,*args,**kwargs)
    monkeypatch.setattr(alias_router,"_owner_home",lambda:home)
    monkeypatch.setattr(portable_fresh,"_reference_descriptors",lambda:backend=="native")
    monkeypatch.setattr(portable_fresh,"_proof_operation",proof)
    operation=portable_fresh._Operation()
    with pytest.raises(alias_router.SymlinkPathError) as error: operation.path_guard.check(path)
    assert str(error.value)=="symlink paths are not supported: "+str(linked)
    assert reached and operation.path_guard._global_failure is None
    operation.verify()


@lifecycle_only
@pytest.mark.parametrize("backend",["native","portable"])
@pytest.mark.parametrize("code",[errno.ENOENT,errno.ENOTDIR,errno.EBADF,errno.ELOOP])
def test_round15_ignored_proof_errnos_keep_the_original_symlink_diagnostic(tmp_path,monkeypatch,backend,code):
    if not portable_fresh._descriptor_capabilities() or portable_fresh._symlink_reader() is None:
        pytest.skip("bounded directory-relative link proof unavailable")
    world,linked,public,private,home,path=r14_trial(tmp_path,"disposition")
    original=portable_fresh._proof_operation
    reached=[]
    def fail(): raise OSError(code,"UNTRUSTED proof failure")
    def proof(guard,stage,action,*args,**kwargs):
        if stage=="hop target":
            reached.append(stage)
            return original(guard,stage,fail)
        return original(guard,stage,action,*args,**kwargs)
    monkeypatch.setattr(alias_router,"_owner_home",lambda:home)
    monkeypatch.setattr(portable_fresh,"_reference_descriptors",lambda:backend=="native")
    monkeypatch.setattr(portable_fresh,"_proof_operation",proof)
    operation=portable_fresh._Operation()
    with pytest.raises(alias_router.SymlinkPathError) as error: operation.path_guard.check(path)
    assert str(error.value)=="symlink paths are not supported: "+str(linked)
    assert reached and operation.path_guard._global_failure is None
    operation.verify()


@lifecycle_only
@pytest.mark.parametrize("seam,planned,backend",tuple(itertools.product(
    ("check","exists","read","members","paths","scope","disposition","resolve",
     "shared-disposition","shared-resolve","worktree","scan_workspace","compose-file",
     "router:--lifecycle","router:--store","router:--recipes","compose:--root",
     "compose:--lifecycle","compose:--delivery-dir","verify:--path",
     "loop:--lifecycle","loop:--store","loop:--recipes","loop:--state-dir"),
    (False,True),("native","portable"))))
def test_round15_dangling_parent_keeps_ec27eebf_bytes(tmp_path,seam,planned,backend):
    if backend=="native" and not portable_fresh._reference_descriptors(): pytest.skip("directory descriptors unavailable")
    probe=R10_PUBLIC_PROBE.replace("root = Path(root)\n","root = Path(root)\n"+R15_DANGLING_PROBE).replace(
        "target if seam == 'worktree' else root","target")
    actual=r9_public_probe(tmp_path,seam,"symlink",planned,backend,_probe=probe)
    if seam not in {"paths","scope","disposition","resolve","shared-disposition","shared-resolve",
                    "worktree","scan_workspace"}:
        assert actual==R15_DANGLING_GOLDENS[(seam,planned,backend)]
        return
    # The later proof-layer ruling requires quarantine here. Preserve the
    # literal baseline diagnostic, without restoring the superseded GLOBAL/
    # UNKNOWN disposition or suppressing an unproved inert occurrence.
    assert actual[0]==0 and actual[2]==b""
    result=json.loads(actual[1])["result"]
    errors=result["refusals"]
    if isinstance(errors,dict):
        errors=[item[1] for rows in errors.values() for item in rows]
        assert "healthy" in result["requests"]
        assert result["unknown"]=={}
    expected=json.loads(R15_DANGLING_GOLDENS[("check",planned,backend)][1])["error"].encode()
    assert errors and all(value.encode()==expected for value in errors)


R15_DANGLING_GOLDENS = {('check', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('check', False, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('check', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('check', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('compose-file', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('compose-file', False, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('compose-file', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('compose-file', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('compose:--delivery-dir', False, 'native'): (2,
                                               b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                               b''),
 ('compose:--delivery-dir', False, 'portable'): (2,
                                                 b'{"error": "symlink paths are not supported: {CASE}/ordinary"'
                                                 b'}\n',
                                                 b''),
 ('compose:--delivery-dir', True, 'native'): (2,
                                              b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                              b''),
 ('compose:--delivery-dir', True, 'portable'): (2,
                                                b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                                b''),
 ('compose:--lifecycle', False, 'native'): (2,
                                            b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                            b''),
 ('compose:--lifecycle', False, 'portable'): (2,
                                              b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                              b''),
 ('compose:--lifecycle', True, 'native'): (2,
                                           b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                           b''),
 ('compose:--lifecycle', True, 'portable'): (2,
                                             b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                             b''),
 ('compose:--root', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('compose:--root', False, 'portable'): (2,
                                         b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                         b''),
 ('compose:--root', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('compose:--root', True, 'portable'): (2,
                                        b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                        b''),
 ('disposition', False, 'native'): (0,
                                    b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"f'
                                    b'irst": "lifecycle row UNKNOWN at event fault-event: symlink paths are not su'
                                    b'pported: {CASE}/ordinary"}}}\n',
                                    b''),
 ('disposition', False, 'portable'): (0,
                                      b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown":'
                                      b' {"first": "lifecycle row UNKNOWN at event fault-event: symlink paths ar'
                                      b'e not supported: {CASE}/ordinary"}}}\n',
                                      b''),
 ('disposition', True, 'native'): (0,
                                   b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"f'
                                   b'irst": "lifecycle row UNKNOWN at event fault-event: symlink paths are not su'
                                   b'pported: {CASE}/ordinary"}}}\n',
                                   b''),
 ('disposition', True, 'portable'): (0,
                                     b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown":'
                                     b' {"first": "lifecycle row UNKNOWN at event fault-event: symlink paths ar'
                                     b'e not supported: {CASE}/ordinary"}}}\n',
                                     b''),
 ('exists', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('exists', False, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('exists', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('exists', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('loop:--lifecycle', False, 'native'): (2,
                                         b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                         b''),
 ('loop:--lifecycle', False, 'portable'): (2,
                                           b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                           b''),
 ('loop:--lifecycle', True, 'native'): (2,
                                        b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                        b''),
 ('loop:--lifecycle', True, 'portable'): (2,
                                          b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                          b''),
 ('loop:--recipes', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('loop:--recipes', False, 'portable'): (2,
                                         b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                         b''),
 ('loop:--recipes', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('loop:--recipes', True, 'portable'): (2,
                                        b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                        b''),
 ('loop:--state-dir', False, 'native'): (2,
                                         b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                         b''),
 ('loop:--state-dir', False, 'portable'): (2,
                                           b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                           b''),
 ('loop:--state-dir', True, 'native'): (2,
                                        b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                        b''),
 ('loop:--state-dir', True, 'portable'): (2,
                                          b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                          b''),
 ('loop:--store', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('loop:--store', False, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('loop:--store', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('loop:--store', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('members', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('members', False, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('members', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('members', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('paths', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('paths', False, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('paths', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('paths', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('read', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('read', False, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('read', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('read', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('resolve', False, 'native'): (0,
                                b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"first'
                                b'": "lifecycle row UNKNOWN at event fault-event: symlink paths are not supported:'
                                b' {CASE}/ordinary"}}}\n',
                                b''),
 ('resolve', False, 'portable'): (0,
                                  b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"f'
                                  b'irst": "lifecycle row UNKNOWN at event fault-event: symlink paths are not su'
                                  b'pported: {CASE}/ordinary"}}}\n',
                                  b''),
 ('resolve', True, 'native'): (0,
                               b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"first'
                               b'": "lifecycle row UNKNOWN at event fault-event: symlink paths are not supported:'
                               b' {CASE}/ordinary"}}}\n',
                               b''),
 ('resolve', True, 'portable'): (0,
                                 b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"f'
                                 b'irst": "lifecycle row UNKNOWN at event fault-event: symlink paths are not su'
                                 b'pported: {CASE}/ordinary"}}}\n',
                                 b''),
 ('router:--lifecycle', False, 'native'): (2,
                                           b'{"error":"symlink paths are not supported: {CASE}/ordinary","executi'
                                           b'on_enabled":false,"source":"arguments","state":"hold"}\n',
                                           b''),
 ('router:--lifecycle', False, 'portable'): (2,
                                             b'{"error":"symlink paths are not supported: {CASE}/ordinary","exe'
                                             b'cution_enabled":false,"source":"arguments","state":"hold"}\n',
                                             b''),
 ('router:--lifecycle', True, 'native'): (2,
                                          b'{"error":"symlink paths are not supported: {CASE}/ordinary","executi'
                                          b'on_enabled":false,"source":"arguments","state":"hold"}\n',
                                          b''),
 ('router:--lifecycle', True, 'portable'): (2,
                                            b'{"error":"symlink paths are not supported: {CASE}/ordinary","executi'
                                            b'on_enabled":false,"source":"arguments","state":"hold"}\n',
                                            b''),
 ('router:--recipes', False, 'native'): (2,
                                         b'{"error":"symlink paths are not supported: {CASE}/ordinary","executi'
                                         b'on_enabled":false,"source":"arguments","state":"hold"}\n',
                                         b''),
 ('router:--recipes', False, 'portable'): (2,
                                           b'{"error":"symlink paths are not supported: {CASE}/ordinary","executi'
                                           b'on_enabled":false,"source":"arguments","state":"hold"}\n',
                                           b''),
 ('router:--recipes', True, 'native'): (2,
                                        b'{"error":"symlink paths are not supported: {CASE}/ordinary","execution_e'
                                        b'nabled":false,"source":"arguments","state":"hold"}\n',
                                        b''),
 ('router:--recipes', True, 'portable'): (2,
                                          b'{"error":"symlink paths are not supported: {CASE}/ordinary","executi'
                                          b'on_enabled":false,"source":"arguments","state":"hold"}\n',
                                          b''),
 ('router:--store', False, 'native'): (2,
                                       b'{"error":"symlink paths are not supported: {CASE}/ordinary","execution_e'
                                       b'nabled":false,"source":"arguments","state":"hold"}\n',
                                       b''),
 ('router:--store', False, 'portable'): (2,
                                         b'{"error":"symlink paths are not supported: {CASE}/ordinary","executi'
                                         b'on_enabled":false,"source":"arguments","state":"hold"}\n',
                                         b''),
 ('router:--store', True, 'native'): (2,
                                      b'{"error":"symlink paths are not supported: {CASE}/ordinary","execution_e'
                                      b'nabled":false,"source":"arguments","state":"hold"}\n',
                                      b''),
 ('router:--store', True, 'portable'): (2,
                                        b'{"error":"symlink paths are not supported: {CASE}/ordinary","execution_e'
                                        b'nabled":false,"source":"arguments","state":"hold"}\n',
                                        b''),
 ('scan_workspace', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('scan_workspace', False, 'portable'): (2,
                                         b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                         b''),
 ('scan_workspace', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('scan_workspace', True, 'portable'): (2,
                                        b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                        b''),
 ('scope', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('scope', False, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('scope', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('scope', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('shared-disposition', False, 'native'): (0,
                                           b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostil'
                                           b'e"], "unknown": {}}}\n',
                                           b''),
 ('shared-disposition', False, 'portable'): (0,
                                             b'{"result": {"refusals": {}, "requests": ["first", "healthy", "ho'
                                             b'stile"], "unknown": {}}}\n',
                                             b''),
 ('shared-disposition', True, 'native'): (0,
                                          b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostil'
                                          b'e"], "unknown": {}}}\n',
                                          b''),
 ('shared-disposition', True, 'portable'): (0,
                                            b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostil'
                                            b'e"], "unknown": {}}}\n',
                                            b''),
 ('shared-resolve', False, 'native'): (0,
                                       b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"],'
                                       b' "unknown": {}}}\n',
                                       b''),
 ('shared-resolve', False, 'portable'): (0,
                                         b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostil'
                                         b'e"], "unknown": {}}}\n',
                                         b''),
 ('shared-resolve', True, 'native'): (0,
                                      b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"],'
                                      b' "unknown": {}}}\n',
                                      b''),
 ('shared-resolve', True, 'portable'): (0,
                                        b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"],'
                                        b' "unknown": {}}}\n',
                                        b''),
 ('verify:--path', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('verify:--path', False, 'portable'): (2,
                                        b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                        b''),
 ('verify:--path', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('verify:--path', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('worktree', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('worktree', False, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('worktree', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('worktree', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b'')}


# The list is deliberately explicit: legacy readers are outside this classifier graph.
R14_CLASSIFIER_FUNCTIONS = (
    "_proof_operation", "_final_leaf_lookup", "_private_symlink_target",
    "_resolve_public_chain", "_lookup_chain_leaf", "_proof_parent", "_proof_check", "_proof_recheck",
    "_proof_token", "_proof_link", "_link_snapshot", "_stable_link",
    "_symlink_reader", "_symlink_reader.read", "_proof_parent_marks", "_disposition",
    "_diagnostic_error", "_walk_error", "_recheck_final_witness", "_LeafLookup.__init__",
    "_ProvedChain.proved", "_LinkLookupFailure.proved",
)
R14_PROOF_STAGES = ("prefix ancestor","link","hop target","traversal prefix",
                   "post-traversal","suffix ancestor","direct-leaf destination")
R14_PROOF_ERRORS = ("enoent","enotdir","eacces","eio","eloop","permission-no-errno")


def test_round14_classifier_has_only_two_exception_boundaries():
    tree=ast.parse(TOOL.read_text(encoding="utf-8"))
    functions={}
    class Inventory(ast.NodeVisitor):
        def __init__(self): self.names=[]
        def scoped(self,node):
            self.names.append(node.name)
            if isinstance(node,ast.FunctionDef): functions[".".join(self.names)]=node
            self.generic_visit(node); self.names.pop()
        visit_FunctionDef=scoped
        visit_ClassDef=scoped
    Inventory().visit(tree)
    assert set(R14_CLASSIFIER_FUNCTIONS)<=set(functions)
    family={"OSError","IOError","FileNotFoundError","NotADirectoryError","PermissionError",
            "Exception","BaseException"}
    for name in R14_CLASSIFIER_FUNCTIONS:
        if name in {"_proof_operation","_final_leaf_lookup"}: continue
        for node in ast.walk(functions[name]):
            if isinstance(node,ast.ExceptHandler):
                caught={item.id for item in ast.walk(node.type) if isinstance(item,ast.Name)} if node.type else family
                # A bare re-raise for descriptor cleanup never decides a layer.
                if caught=={"BaseException"} and any(isinstance(x,ast.Raise) and x.exc is None for x in node.body):
                    continue
                assert not caught&family,(name,node.lineno,caught)


def r14_trial(tmp_path,seam,stage="hop target"):
    from tests.integration.test_hierarchy_router import Loop
    world=Loop(tmp_path); world.team("engine"); world.team("docs")
    world.approved(request("healthy",team="docs"))
    linked,public,home=tmp_path/"l1",tmp_path/"public",tmp_path/"owner"
    private=home/".codex"
    for directory in (linked,public,private,public/"sub",public/"step",public/"base"):
        directory.mkdir(parents=True,exist_ok=True)
    (public/"note.md").write_bytes(b"public fixture")
    (private/"note.md").write_bytes(b"controlled private fixture")
    if stage=="direct-leaf destination": path=str(linked)
    elif stage=="suffix ancestor":
        (linked/"sub"/"priv_link").mkdir(parents=True)
        (public/"sub"/"priv_link").mkdir()
        path=str(linked/"sub"/"priv_link"/"note.md")
    else: path=str(linked/"note.md")
    first=request("first"); world.ledger.publish(first)
    following=request("following",paths=[path])
    extra={}
    if seam=="resolve":
        world.ledger.event("disposition",status="HOLD",resolution={"kind":"blocked","owner":"engine/coordinator",
            "next_decision":"review","condition":"reviewed","evidence":world.ledger.evidence},**world.ledger.target(first))
        extra["blocker_sha256"]=portable_fresh.digest(world.ledger.status()["requests"]["first"]["resolution"])
    world.ledger.event(seam,**({"status":"FINAL"} if seam=="disposition" else extra),
        resolution={"kind":"next","request":raw_request(following),"evidence":[{"path":path,"sha256":"0"*64}]},
        **world.ledger.target(first))
    world.ledger.approve(following)
    if stage=="suffix ancestor":
        (linked/"sub"/"priv_link").rmdir(); (linked/"sub").rmdir()
    linked.rmdir()
    target=(public/"note.md" if stage=="direct-leaf destination" else
            public/"step"/".."/"base" if stage in {"traversal prefix","post-traversal"} else public)
    symlink_or_skip(target,linked,target_is_directory=stage!="direct-leaf destination")
    return world,linked,public,private,home,path


def r14_assert_quarantined(world,path):
    operation=portable_fresh._Operation(); journal=operation.lifecycle(world.ledger.path)
    _policy,state=journal.load()
    assert "healthy" in state["requests"]
    assert journal.refusals_for("healthy")==[]
    assert journal.refusals_for("following")
    for _ in range(2):
        assert journal.refusals_for("following",consume=True)
        brief=portable_fresh.Brief(_operation=operation)
        portable_fresh.lifecycle_records(brief,world.ledger.path,portable_fresh.parse_time("2030-01-01T00:00:00Z"))
        assert path not in json.dumps(brief.sections["Approved scope"])
    operation.verify()
    assert operation.path_guard._global_failure is None
    return operation,journal


@lifecycle_only
@pytest.mark.parametrize("seam",["disposition","resolve"])
@pytest.mark.parametrize("backend",["native","portable"])
@pytest.mark.parametrize("damage",["removed","file","suffix"])
def test_round14_real_unproved_ancestors_never_reach_scope(tmp_path,monkeypatch,seam,backend,damage):
    if not portable_fresh._descriptor_capabilities(): pytest.skip("directory descriptors unavailable")
    if damage=="suffix" and os.geteuid()==0: pytest.skip("mode-000 witness requires an unprivileged runner")
    stage="suffix ancestor" if damage=="suffix" else "hop target"
    world,linked,public,private,home,path=r14_trial(tmp_path,seam,stage)
    monkeypatch.setattr(alias_router,"_owner_home",lambda:home)
    monkeypatch.setattr(portable_fresh,"_reference_descriptors",lambda:backend=="native")
    linked.unlink()
    if damage=="suffix":
        # l1/sub/priv_link/note.md: the suffix ancestor hides the link.
        (public/"sub"/"priv_link").rmdir()
        denied=public/"sub"
        symlink_or_skip(private,denied/"priv_link",target_is_directory=True)
        symlink_or_skip(public,linked,target_is_directory=True)
        denied.chmod(0)
    else:
        staging=tmp_path/"staging"; staging.mkdir()
        symlink_or_skip(private,staging/"priv_link",target_is_directory=True)
        symlink_or_skip(staging/"priv_link",linked,target_is_directory=True)
        (staging/"priv_link").unlink(); staging.rmdir()
        if damage=="file": staging.write_bytes(b"replacement regular file")
    try: r14_assert_quarantined(world,path)
    finally:
        if damage=="suffix": denied.chmod(0o700)


@lifecycle_only
@pytest.mark.parametrize("seam",["disposition","resolve"])
@pytest.mark.parametrize("backend",["native","portable"])
@pytest.mark.parametrize("stage",R14_PROOF_STAGES)
@pytest.mark.parametrize("fault",R14_PROOF_ERRORS)
def test_round14_every_proof_failure_is_persistent_and_row_local(tmp_path,monkeypatch,seam,backend,stage,fault):
    if not portable_fresh._descriptor_capabilities(): pytest.skip("directory descriptors unavailable")
    world,linked,public,private,home,path=r14_trial(tmp_path,seam,stage)
    monkeypatch.setattr(alias_router,"_owner_home",lambda:home)
    monkeypatch.setattr(portable_fresh,"_reference_descriptors",lambda:backend=="native")
    original=portable_fresh._proof_operation
    reached=[]
    codes={"enoent":errno.ENOENT,"enotdir":errno.ENOTDIR,"eacces":errno.EACCES,"eio":errno.EIO,"eloop":errno.ELOOP}
    def failed(*args,**kwargs):
        if fault=="permission-no-errno": raise PermissionError("controlled proof failure")
        raise OSError(codes[fault],"controlled proof failure")
    def injected(guard,layer,action,*args,**kwargs):
        if layer==stage:
            reached.append(layer)
            return original(guard,layer,failed)
        return original(guard,layer,action,*args,**kwargs)
    monkeypatch.setattr(portable_fresh,"_proof_operation",injected)
    operation,journal=r14_assert_quarantined(world,path)
    assert reached
    healthy=tmp_path/"healthy-retry.md"; healthy.write_bytes(b"independent healthy capture")
    retry=portable_fresh._Operation(); assert retry.read(healthy)[1]==b"independent healthy capture"
    retry.verify()


@lifecycle_only
@pytest.mark.parametrize("seam",["disposition","resolve"])
@pytest.mark.parametrize("backend",["native","portable"])
@pytest.mark.parametrize("replacement",["private","public"])
def test_round14_suffix_replacement_after_leaf_lookup_invalidates_the_whole_token(tmp_path,monkeypatch,seam,backend,replacement):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    if not portable_fresh._descriptor_capabilities(): pytest.skip("directory descriptors unavailable")
    world,linked,public,private,home,path=r14_trial(tmp_path,seam,"suffix ancestor")
    monkeypatch.setattr(alias_router,"_owner_home",lambda:home)
    monkeypatch.setattr(portable_fresh,"_reference_descriptors",lambda:backend=="native")
    original=portable_fresh._final_leaf_lookup
    entered,changed=Event(),Event()
    alternate=tmp_path/"alternate"; (alternate/"priv_link").mkdir(parents=True)
    parked=tmp_path/"parked"
    def replace():
        assert entered.wait(10),"final lookup did not reach the mutation boundary"
        (public/"sub").rename(parked)
        (public/"sub").symlink_to(private if replacement=="private" else alternate,target_is_directory=True)
        changed.set()
    def lookup(proof):
        result=original(proof)
        if proof.leaf==public/"sub"/"priv_link"/"note.md" and not changed.is_set():
            entered.set(); assert changed.wait(10),"ancestor replacement did not complete"
        return result
    monkeypatch.setattr(portable_fresh,"_final_leaf_lookup",lookup)
    with ThreadPoolExecutor(max_workers=1) as pool:
        mutation=pool.submit(replace)
        try: operation,journal=r14_assert_quarantined(world,path)
        finally:
            entered.set()
            mutation.result(timeout=15)
    assert journal.refusals_for("following",consume=True)
    assert operation.path_guard._global_failure is None


@lifecycle_only
def test_round14_failed_result_allocation_releases_the_proved_token(tmp_path,monkeypatch):
    if not portable_fresh._descriptor_capabilities(): pytest.skip("directory descriptors unavailable")
    world,linked,public,private,home,path=r14_trial(tmp_path,"disposition")
    monkeypatch.setattr(alias_router,"_owner_home",lambda:home)
    original=portable_fresh._ProofValue
    descriptors=[]
    class AllocationFailure(original):
        def __init__(self,value):
            if isinstance(value,portable_fresh._ProvedChain) and value.directory is not None:
                descriptors.append(value.directory)
                raise MemoryError("controlled proof-result allocation failure")
            super().__init__(value)
    monkeypatch.setattr(portable_fresh,"_ProofValue",AllocationFailure)
    try:
        r14_assert_quarantined(world,path)
        assert descriptors
        for descriptor in set(descriptors):
            with pytest.raises(OSError) as error: os.fstat(descriptor)
            assert error.value.errno==errno.EBADF
    finally:
        for descriptor in set(descriptors):
            try: os.close(descriptor)
            except OSError: pass


def test_round14_final_leaf_lookup_requires_a_live_proved_token():
    with pytest.raises(ValueError,match="^final lookup requires a live proved-chain token$"):
        portable_fresh._final_leaf_lookup(object())


@lifecycle_only
@pytest.mark.parametrize("seam",["disposition","resolve"])
@pytest.mark.parametrize("backend",["native","portable"])
@pytest.mark.parametrize("shape",["outer","leaf"])
@pytest.mark.parametrize("level",[2,3])
def test_round14_argon_nested_hop_targets_are_proof_until_complete(tmp_path,monkeypatch,seam,backend,shape,level):
    if not portable_fresh._descriptor_capabilities(): pytest.skip("directory descriptors unavailable")
    if os.geteuid()==0: pytest.skip("mode-000 witness requires an unprivileged runner")
    world,linked,public,private,home,path=r14_trial(tmp_path,seam)
    monkeypatch.setattr(alias_router,"_owner_home",lambda:home)
    monkeypatch.setattr(portable_fresh,"_reference_descriptors",lambda:backend=="native")
    denied=tmp_path/"denied"; denied.mkdir()
    symlink_or_skip(private,denied/"priv_link",target_is_directory=True)
    hop2,hop3=tmp_path/"hop2",tmp_path/"hop3"
    if level==3:
        symlink_or_skip(denied,hop3,target_is_directory=True)
        symlink_or_skip(hop3,hop2,target_is_directory=True)
    else: symlink_or_skip(denied,hop2,target_is_directory=True)
    if shape=="outer":
        linked.unlink(); symlink_or_skip(hop2/"priv_link",linked,target_is_directory=True)
    else:
        (public/"note.md").unlink()
        # Keep the denied component in the proof layer: the pathname ruling
        # permits an inert final-leaf EACCES after all parents are proved.
        symlink_or_skip(hop2/"priv_link"/"note.md",public/"note.md")
    denied.chmod(0)
    try: r14_assert_quarantined(world,path)
    finally: denied.chmod(0o700)


@lifecycle_only
@pytest.mark.parametrize("seam",["disposition","resolve"])
@pytest.mark.parametrize("backend",["native","portable"])
@pytest.mark.parametrize("site",["target","ancestor"])
@pytest.mark.parametrize("replacement",["directory","private"])
def test_round14_argon_resolved_directory_rechecked_before_errno_suppression(tmp_path,monkeypatch,seam,backend,site,replacement):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from queue import Queue
    if not portable_fresh._descriptor_capabilities(): pytest.skip("directory descriptors unavailable")
    if not hasattr(os,"O_PATH"): pytest.skip("leaf-denial witness requires O_PATH directory handles")
    if os.geteuid()==0: pytest.skip("mode-000 witness requires an unprivileged runner")
    world,linked,public,private,home,path=r14_trial(tmp_path,seam)
    monkeypatch.setattr(alias_router,"_owner_home",lambda:home)
    monkeypatch.setattr(portable_fresh,"_reference_descriptors",lambda:backend=="native")
    container=tmp_path/"container"; target=container/"target_dir"; target.mkdir(parents=True)
    linked.unlink(); symlink_or_skip(target,linked,target_is_directory=True)
    original,checked=portable_fresh._LinkLookupFailure,portable_fresh._reference_check
    changed=Event()
    mutations,acknowledgments=Queue(),Queue()
    reached=[]
    alternate=tmp_path/"alternate"; alternate.mkdir()
    if site=="ancestor": (alternate/"target_dir").mkdir()
    value=target if site=="target" else container
    parked=value.with_name(value.name+".parked")
    def restore():
        if parked.exists():
            if value.is_symlink(): value.unlink()
            else: value.rename(alternate)
            parked.rename(value)
            changed.clear()
    def check(value_path,*args,**kwargs):
        if Path(value_path)==Path(path): restore()
        return checked(value_path,*args,**kwargs)
    def replace():
        while mutations.get(timeout=15) is not None:
            value.rename(parked)
            if replacement=="private": value.symlink_to(private,target_is_directory=True)
            else: alternate.rename(value)
            changed.set()
            acknowledgments.put(True)
    class InterruptedProof(original):
        def proved(self,guard):
            assert self.error.errno==errno.EACCES
            if not changed.is_set():
                mutations.put(True)
                assert acknowledgments.get(timeout=10),"directory replacement did not complete"
                reached.append(True)
            return super().proved(guard)
    monkeypatch.setattr(portable_fresh,"_LinkLookupFailure",InterruptedProof)
    monkeypatch.setattr(portable_fresh,"_reference_check",check)
    target.chmod(0)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            mutation=pool.submit(replace)
            try:
                r14_assert_quarantined(world,path)
                assert reached
            finally:
                mutations.put(None)
                mutation.result(timeout=15)
    finally:
        restore()
        target.chmod(0o700)


R14_FINAL_SEAMS=("check","exists","read","members","paths","scope","disposition","resolve",
                 "shared-disposition","shared-resolve","worktree","scan_workspace")


@lifecycle_only
@pytest.mark.parametrize("seam,planned,backend,fault",tuple(itertools.product(
    R14_FINAL_SEAMS,(False,True),("native","portable"),("enoent","enotdir"))))
def test_round14_final_leaf_absence_keeps_ec27eebf_bytes(tmp_path,seam,planned,backend,fault):
    if backend=="native" and not portable_fresh._reference_descriptors(): pytest.skip("directory descriptors unavailable")
    probe=R10_PUBLIC_PROBE.replace("errno.EIO","errno.ENOENT" if fault=="enoent" else "errno.ENOTDIR")
    assert r9_public_probe(tmp_path,seam,"link-to-io",planned,backend,_probe=probe)==R14_FINAL_GOLDENS[(seam,planned,backend,fault)]


R14_FINAL_GOLDENS = {('check', False, 'native', 'enoent'): (2,
                                        b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                        b''),
 ('check', False, 'native', 'enotdir'): (2,
                                         b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                         b''),
 ('check', False, 'portable', 'enoent'): (2,
                                          b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                          b''),
 ('check', False, 'portable', 'enotdir'): (2,
                                           b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                           b''),
 ('check', True, 'native', 'enoent'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('check', True, 'native', 'enotdir'): (2,
                                        b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                        b''),
 ('check', True, 'portable', 'enoent'): (2,
                                         b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                         b''),
 ('check', True, 'portable', 'enotdir'): (2,
                                          b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                          b''),
 ('disposition', False, 'native', 'enoent'): (0,
                                              b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "u'
                                              b'nknown": {"first": "lifecycle row UNKNOWN at event fault-event: '
                                              b'symlink paths are not supported: {CASE}/ordinary"}}}\n',
                                              b''),
 ('disposition', False, 'native', 'enotdir'): (0,
                                               b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "u'
                                               b'nknown": {"first": "lifecycle row UNKNOWN at event fault-event: '
                                               b'symlink paths are not supported: {CASE}/ordinary"}}}\n',
                                               b''),
 ('disposition', False, 'portable', 'enoent'): (0,
                                                b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "u'
                                                b'nknown": {"first": "lifecycle row UNKNOWN at event fault-event: '
                                                b'symlink paths are not supported: {CASE}/ordinary"}}}\n',
                                                b''),
 ('disposition', False, 'portable', 'enotdir'): (0,
                                                 b'{"result": {"refusals": {}, "requests": ["first", "healthy"]'
                                                 b', "unknown": {"first": "lifecycle row UNKNOWN at event fault'
                                                 b'-event: symlink paths are not supported: {CASE}/ordinary"}}}\n',
                                                 b''),
 ('disposition', True, 'native', 'enoent'): (0,
                                             b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "u'
                                             b'nknown": {"first": "lifecycle row UNKNOWN at event fault-event: '
                                             b'symlink paths are not supported: {CASE}/ordinary"}}}\n',
                                             b''),
 ('disposition', True, 'native', 'enotdir'): (0,
                                              b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "u'
                                              b'nknown": {"first": "lifecycle row UNKNOWN at event fault-event: '
                                              b'symlink paths are not supported: {CASE}/ordinary"}}}\n',
                                              b''),
 ('disposition', True, 'portable', 'enoent'): (0,
                                               b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "u'
                                               b'nknown": {"first": "lifecycle row UNKNOWN at event fault-event: '
                                               b'symlink paths are not supported: {CASE}/ordinary"}}}\n',
                                               b''),
 ('disposition', True, 'portable', 'enotdir'): (0,
                                                b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "u'
                                                b'nknown": {"first": "lifecycle row UNKNOWN at event fault-event: '
                                                b'symlink paths are not supported: {CASE}/ordinary"}}}\n',
                                                b''),
 ('exists', False, 'native', 'enoent'): (2,
                                         b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                         b''),
 ('exists', False, 'native', 'enotdir'): (2,
                                          b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                          b''),
 ('exists', False, 'portable', 'enoent'): (2,
                                           b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                           b''),
 ('exists', False, 'portable', 'enotdir'): (2,
                                            b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                            b''),
 ('exists', True, 'native', 'enoent'): (2,
                                        b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                        b''),
 ('exists', True, 'native', 'enotdir'): (2,
                                         b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                         b''),
 ('exists', True, 'portable', 'enoent'): (2,
                                          b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                          b''),
 ('exists', True, 'portable', 'enotdir'): (2,
                                           b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                           b''),
 ('members', False, 'native', 'enoent'): (2,
                                          b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                          b''),
 ('members', False, 'native', 'enotdir'): (2,
                                           b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                           b''),
 ('members', False, 'portable', 'enoent'): (2,
                                            b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                            b''),
 ('members', False, 'portable', 'enotdir'): (2,
                                             b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                             b''),
 ('members', True, 'native', 'enoent'): (2,
                                         b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                         b''),
 ('members', True, 'native', 'enotdir'): (2,
                                          b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                          b''),
 ('members', True, 'portable', 'enoent'): (2,
                                           b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                           b''),
 ('members', True, 'portable', 'enotdir'): (2,
                                            b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                            b''),
 ('paths', False, 'native', 'enoent'): (2,
                                        b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                        b''),
 ('paths', False, 'native', 'enotdir'): (2,
                                         b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                         b''),
 ('paths', False, 'portable', 'enoent'): (2,
                                          b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                          b''),
 ('paths', False, 'portable', 'enotdir'): (2,
                                           b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                           b''),
 ('paths', True, 'native', 'enoent'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('paths', True, 'native', 'enotdir'): (2,
                                        b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                        b''),
 ('paths', True, 'portable', 'enoent'): (2,
                                         b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                         b''),
 ('paths', True, 'portable', 'enotdir'): (2,
                                          b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                          b''),
 ('read', False, 'native', 'enoent'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('read', False, 'native', 'enotdir'): (2,
                                        b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                        b''),
 ('read', False, 'portable', 'enoent'): (2,
                                         b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                         b''),
 ('read', False, 'portable', 'enotdir'): (2,
                                          b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                          b''),
 ('read', True, 'native', 'enoent'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('read', True, 'native', 'enotdir'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('read', True, 'portable', 'enoent'): (2,
                                        b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                        b''),
 ('read', True, 'portable', 'enotdir'): (2,
                                         b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                         b''),
 ('resolve', False, 'native', 'enoent'): (0,
                                          b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unkno'
                                          b'wn": {"first": "lifecycle row UNKNOWN at event fault-event: symlink '
                                          b'paths are not supported: {CASE}/ordinary"}}}\n',
                                          b''),
 ('resolve', False, 'native', 'enotdir'): (0,
                                           b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unkno'
                                           b'wn": {"first": "lifecycle row UNKNOWN at event fault-event: symlink '
                                           b'paths are not supported: {CASE}/ordinary"}}}\n',
                                           b''),
 ('resolve', False, 'portable', 'enoent'): (0,
                                            b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unkno'
                                            b'wn": {"first": "lifecycle row UNKNOWN at event fault-event: symlink '
                                            b'paths are not supported: {CASE}/ordinary"}}}\n',
                                            b''),
 ('resolve', False, 'portable', 'enotdir'): (0,
                                             b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "u'
                                             b'nknown": {"first": "lifecycle row UNKNOWN at event fault-event: '
                                             b'symlink paths are not supported: {CASE}/ordinary"}}}\n',
                                             b''),
 ('resolve', True, 'native', 'enoent'): (0,
                                         b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unkno'
                                         b'wn": {"first": "lifecycle row UNKNOWN at event fault-event: symlink '
                                         b'paths are not supported: {CASE}/ordinary"}}}\n',
                                         b''),
 ('resolve', True, 'native', 'enotdir'): (0,
                                          b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unkno'
                                          b'wn": {"first": "lifecycle row UNKNOWN at event fault-event: symlink '
                                          b'paths are not supported: {CASE}/ordinary"}}}\n',
                                          b''),
 ('resolve', True, 'portable', 'enoent'): (0,
                                           b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unkno'
                                           b'wn": {"first": "lifecycle row UNKNOWN at event fault-event: symlink '
                                           b'paths are not supported: {CASE}/ordinary"}}}\n',
                                           b''),
 ('resolve', True, 'portable', 'enotdir'): (0,
                                            b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unkno'
                                            b'wn": {"first": "lifecycle row UNKNOWN at event fault-event: symlink '
                                            b'paths are not supported: {CASE}/ordinary"}}}\n',
                                            b''),
 ('scan_workspace', False, 'native', 'enoent'): (2,
                                                 b'{"error": "symlink paths are not supported: {CASE}/ordinary"'
                                                 b'}\n',
                                                 b''),
 ('scan_workspace', False, 'native', 'enotdir'): (2,
                                                  b'{"error": "symlink paths are not supported: {CASE}/ordinary"'
                                                  b'}\n',
                                                  b''),
 ('scan_workspace', False, 'portable', 'enoent'): (2,
                                                   b'{"error": "symlink paths are not supported: {CASE}/ordinary"'
                                                   b'}\n',
                                                   b''),
 ('scan_workspace', False, 'portable', 'enotdir'): (2,
                                                    b'{"error": "symlink paths are not supported: {CASE}/ordinary"'
                                                    b'}\n',
                                                    b''),
 ('scan_workspace', True, 'native', 'enoent'): (2,
                                                b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                                b''),
 ('scan_workspace', True, 'native', 'enotdir'): (2,
                                                 b'{"error": "symlink paths are not supported: {CASE}/ordinary"'
                                                 b'}\n',
                                                 b''),
 ('scan_workspace', True, 'portable', 'enoent'): (2,
                                                  b'{"error": "symlink paths are not supported: {CASE}/ordinary"'
                                                  b'}\n',
                                                  b''),
 ('scan_workspace', True, 'portable', 'enotdir'): (2,
                                                   b'{"error": "symlink paths are not supported: {CASE}/ordinary"'
                                                   b'}\n',
                                                   b''),
 ('scope', False, 'native', 'enoent'): (2,
                                        b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                        b''),
 ('scope', False, 'native', 'enotdir'): (2,
                                         b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                         b''),
 ('scope', False, 'portable', 'enoent'): (2,
                                          b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                          b''),
 ('scope', False, 'portable', 'enotdir'): (2,
                                           b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                           b''),
 ('scope', True, 'native', 'enoent'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('scope', True, 'native', 'enotdir'): (2,
                                        b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                        b''),
 ('scope', True, 'portable', 'enoent'): (2,
                                         b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                         b''),
 ('scope', True, 'portable', 'enotdir'): (2,
                                          b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                          b''),
 ('shared-disposition', False, 'native', 'enoent'): (0,
                                                     b'{"result": {"refusals": {}, "requests": ["first", "healt'
                                                     b'hy", "hostile"], "unknown": {}}}\n',
                                                     b''),
 ('shared-disposition', False, 'native', 'enotdir'): (0,
                                                      b'{"result": {"refusals": {}, "requests": ["first", "healt'
                                                      b'hy", "hostile"], "unknown": {}}}\n',
                                                      b''),
 ('shared-disposition', False, 'portable', 'enoent'): (0,
                                                       b'{"result": {"refusals": {}, "requests": ["first", "healt'
                                                       b'hy", "hostile"], "unknown": {}}}\n',
                                                       b''),
 ('shared-disposition', False, 'portable', 'enotdir'): (0,
                                                        b'{"result": {"refusals": {}, "requests": ["first", "healt'
                                                        b'hy", "hostile"], "unknown": {}}}\n',
                                                        b''),
 ('shared-disposition', True, 'native', 'enoent'): (0,
                                                    b'{"result": {"refusals": {}, "requests": ["first", "healthy",'
                                                    b' "hostile"], "unknown": {}}}\n',
                                                    b''),
 ('shared-disposition', True, 'native', 'enotdir'): (0,
                                                     b'{"result": {"refusals": {}, "requests": ["first", "healt'
                                                     b'hy", "hostile"], "unknown": {}}}\n',
                                                     b''),
 ('shared-disposition', True, 'portable', 'enoent'): (0,
                                                      b'{"result": {"refusals": {}, "requests": ["first", "healt'
                                                      b'hy", "hostile"], "unknown": {}}}\n',
                                                      b''),
 ('shared-disposition', True, 'portable', 'enotdir'): (0,
                                                       b'{"result": {"refusals": {}, "requests": ["first", "healt'
                                                       b'hy", "hostile"], "unknown": {}}}\n',
                                                       b''),
 ('shared-resolve', False, 'native', 'enoent'): (0,
                                                 b'{"result": {"refusals": {}, "requests": ["first", "healthy",'
                                                 b' "hostile"], "unknown": {}}}\n',
                                                 b''),
 ('shared-resolve', False, 'native', 'enotdir'): (0,
                                                  b'{"result": {"refusals": {}, "requests": ["first", "healthy",'
                                                  b' "hostile"], "unknown": {}}}\n',
                                                  b''),
 ('shared-resolve', False, 'portable', 'enoent'): (0,
                                                   b'{"result": {"refusals": {}, "requests": ["first", "healthy",'
                                                   b' "hostile"], "unknown": {}}}\n',
                                                   b''),
 ('shared-resolve', False, 'portable', 'enotdir'): (0,
                                                    b'{"result": {"refusals": {}, "requests": ["first", "healthy",'
                                                    b' "hostile"], "unknown": {}}}\n',
                                                    b''),
 ('shared-resolve', True, 'native', 'enoent'): (0,
                                                b'{"result": {"refusals": {}, "requests": ["first", "healthy", "ho'
                                                b'stile"], "unknown": {}}}\n',
                                                b''),
 ('shared-resolve', True, 'native', 'enotdir'): (0,
                                                 b'{"result": {"refusals": {}, "requests": ["first", "healthy",'
                                                 b' "hostile"], "unknown": {}}}\n',
                                                 b''),
 ('shared-resolve', True, 'portable', 'enoent'): (0,
                                                  b'{"result": {"refusals": {}, "requests": ["first", "healthy",'
                                                  b' "hostile"], "unknown": {}}}\n',
                                                  b''),
 ('shared-resolve', True, 'portable', 'enotdir'): (0,
                                                   b'{"result": {"refusals": {}, "requests": ["first", "healthy",'
                                                   b' "hostile"], "unknown": {}}}\n',
                                                   b''),
 ('worktree', False, 'native', 'enoent'): (2,
                                           b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                           b''),
 ('worktree', False, 'native', 'enotdir'): (2,
                                            b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                            b''),
 ('worktree', False, 'portable', 'enoent'): (2,
                                             b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                             b''),
 ('worktree', False, 'portable', 'enotdir'): (2,
                                              b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                              b''),
 ('worktree', True, 'native', 'enoent'): (2,
                                          b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                          b''),
 ('worktree', True, 'native', 'enotdir'): (2,
                                           b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                           b''),
 ('worktree', True, 'portable', 'enoent'): (2,
                                            b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                            b''),
 ('worktree', True, 'portable', 'enotdir'): (2,
                                             b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                             b'')}


# Filled from an ec27eebf tools snapshot by the round-13 baseline capture.
R13_CONSUMER_GOLDENS = {('attachment', False, 'inputs'): (0,
                                   b'{"healthy_capture": "e21a21f88e72fedf876c98e7e2492391ae5643f37ce4687f310efd73b79'
                                   b'f1e8d", "unverified": "[Errno 13] Permission denied: \'{CASE}/inputs/note.md\''
                                   b'"}\n',
                                   b''),
 ('closing-report', False, 'inputs'): (0,
                                       b'{"held": {}, "report_error": "[Errno 13] Permission denied: \'{CASE}/inputs/n'
                                       b'ote.md\'", "requests": null, "routed": ["damaged", "healthy"]}\n',
                                       b''),
 ('deliver', False, 'mailbox'): (0,
                                 b'{"delivered": false, "failure": {"detail": "[Errno 13] Permission denied: \'{CASE'
                                 b'}/engine/mailbox/.write.lock\'", "reason": "delivery_error"}}\n',
                                 b''),
 ('evidence', False, 'inputs'): (0,
                                 b'{"healthy_capture": "e21a21f88e72fedf876c98e7e2492391ae5643f37ce4687f310efd73b79f1e8'
                                 b'd", "kinds": ["unverified_evidence"]}\n',
                                 b''),
 ('loop-once', True, 'plan'): (3,
                               b'{"reports": [{"holds": [{"detail": "[Errno 13] Permission denied: \'{CASE}/inputs/not'
                               b'e.md\'", "kind": "planning_exclusions_unavailable", "step": "dispatch"}, {"detail": "'
                               b'[Errno 13] Permission denied: \'{CASE}/inputs/note.md\'", "kind": "planning_exclusions'
                               b'_unavailable", "step": "dispatch"}], "pass_id": 1, "steps": [{"exit": 0, "state": "o'
                               b'k", "step": "router_status"}, {"state": "skipped", "step": "route"}, {"exit": 2, "st'
                               b'ate": "hold", "step": "dispatch"}, {"state": "skipped", "step": "sweep"}, {"exit": 0'
                               b', "state": "ok", "step": "run_open"}]}], "run_open_calls": 1}\n',
                               b''),
 ('loop-once', True, 'request'): (3,
                                  b'{"reports": [{"holds": [{"detail": "[Errno 13] Permission denied: \'{CASE}/inputs'
                                  b'/note.md\'", "kind": "planning_exclusions_unavailable", "step": "dispatch"}], "pa'
                                  b'ss_id": 1, "steps": [{"exit": 0, "state": "ok", "step": "router_status"}, {"stat'
                                  b'e": "skipped", "step": "route"}, {"state": "skipped", "step": "sweep"}, {"exit":'
                                  b' 0, "state": "ok", "step": "run_open"}]}], "run_open_calls": 1}\n',
                                  b''),
 ('loop-run', True, 'plan'): (3,
                              b'{"reports": [{"holds": [{"detail": "[Errno 13] Permission denied: \'{CASE}/inputs/not'
                              b'e.md\'", "kind": "planning_exclusions_unavailable", "step": "dispatch"}, {"detail": "'
                              b'[Errno 13] Permission denied: \'{CASE}/inputs/note.md\'", "kind": "planning_exclusions'
                              b'_unavailable", "step": "dispatch"}], "pass_id": 1, "steps": [{"exit": 0, "state": "o'
                              b'k", "step": "router_status"}, {"state": "skipped", "step": "route"}, {"exit": 2, "st'
                              b'ate": "hold", "step": "dispatch"}, {"state": "skipped", "step": "sweep"}, {"exit": 0'
                              b', "state": "ok", "step": "run_open"}]}, {"holds": [{"detail": "[Errno 13] Permission'
                              b' denied: \'{CASE}/inputs/note.md\'", "kind": "planning_exclusions_unavailable", "step"'
                              b': "dispatch"}, {"detail": "[Errno 13] Permission denied: \'{CASE}/inputs/note.md\'", "'
                              b'kind": "planning_exclusions_unavailable", "step": "dispatch"}], "pass_id": 2, "steps'
                              b'": [{"exit": 0, "state": "ok", "step": "router_status"}, {"state": "skipped", "step"'
                              b': "route"}, {"exit": 2, "state": "hold", "step": "dispatch"}, {"state": "skipped", "'
                              b'step": "sweep"}, {"exit": 0, "state": "ok", "step": "run_open"}]}], "run_open_calls"'
                              b': 2}\n',
                              b''),
 ('loop-run', True, 'request'): (3,
                                 b'{"reports": [{"holds": [{"detail": "[Errno 13] Permission denied: \'{CASE}/inputs'
                                 b'/note.md\'", "kind": "planning_exclusions_unavailable", "step": "dispatch"}], "pa'
                                 b'ss_id": 1, "steps": [{"exit": 0, "state": "ok", "step": "router_status"}, {"state": '
                                 b'"skipped", "step": "route"}, {"state": "skipped", "step": "sweep"}, {"exit": 0, "sta'
                                 b'te": "ok", "step": "run_open"}]}, {"holds": [{"detail": "[Errno 13] Permission denie'
                                 b'd: \'{CASE}/inputs/note.md\'", "kind": "planning_exclusions_unavailable", "step": '
                                 b'"dispatch"}], "pass_id": 2, "steps": [{"exit": 0, "state": "ok", "step": "router_sta'
                                 b'tus"}, {"state": "skipped", "step": "route"}, {"state": "skipped", "step": "sweep"},'
                                 b' {"exit": 0, "state": "ok", "step": "run_open"}]}], "run_open_calls": 2}\n',
                                 b''),
 ('receipts', False, 'inputs'): (0,
                                 b'{"healthy_capture": "e21a21f88e72fedf876c98e7e2492391ae5643f37ce4687f310efd73b79f1e8'
                                 b'd", "refused": "[Errno 13] Permission denied: \'{CASE}/delivery/delivered/engine/'
                                 b'orchestrator\'"}\n',
                                 b''),
 ('route', False, 'across'): (0,
                              b'{"requests": [{"detail": "[Errno 13] Permission denied: \'{CASE}/engine/mailbox/acros'
                              b's/front-door\'", "reason": "team_mailbox_unreadable", "request_id": "damaged", "state'
                              b'": "held"}, {"request_id": "healthy", "state": "routed"}], "routed": ["healthy"]}\n',
                              b''),
 ('route', False, 'bindings'): (0,
                                b'{"requests": [{"detail": "[Errno 13] Permission denied: \'{CASE}/engine/mailbox/bindi'
                                b'ngs/engine/router\'", "reason": "team_mailbox_unreadable", "request_id": "damaged", "'
                                b'state": "held"}, {"request_id": "healthy", "state": "routed"}], "routed": ["healthy"'
                                b']}\n',
                                b''),
 ('route', False, 'mailbox'): (0,
                               b'{"requests": [{"detail": "symlink paths are not supported: {CASE}/engine/mailbox", "'
                               b'reason": "team_mailbox_unreadable", "request_id": "damaged", "state": "held"}, {"req'
                               b'uest_id": "healthy", "state": "routed"}], "routed": ["healthy"]}\n',
                               b''),
 ('route', False, 'team'): (0,
                            b'{"requests": [{"detail": "[Errno 13] Permission denied: \'{CASE}/engine/mailbox/engine/fr'
                            b'ont-door\'", "reason": "team_mailbox_unreadable", "request_id": "damaged", "state": "held'
                            b'"}, {"request_id": "healthy", "state": "routed"}], "routed": ["healthy"]}\n',
                            b''),
 ('route', True, 'across'): (0,
                             b'{"requests": [{"detail": "[Errno 13] Permission denied: \'{CASE}/engine/mailbox/acros'
                             b's/front-door\'", "reason": "team_mailbox_unreadable", "request_id": "damaged", "state'
                             b'": "held"}, {"request_id": "healthy", "state": "routed"}], "routed": ["healthy"]}\n',
                             b''),
 ('route', True, 'bindings'): (0,
                               b'{"requests": [{"detail": "[Errno 13] Permission denied: \'{CASE}/engine/mailbox/bindi'
                               b'ngs/engine/router\'", "reason": "team_mailbox_unreadable", "request_id": "damaged", "'
                               b'state": "held"}, {"request_id": "healthy", "state": "routed"}], "routed": ["healthy"'
                               b']}\n',
                               b''),
 ('route', True, 'mailbox'): (0,
                              b'{"requests": [{"detail": "symlink paths are not supported: {CASE}/engine/mailbox", "'
                              b'reason": "team_mailbox_unreadable", "request_id": "damaged", "state": "held"}, {"req'
                              b'uest_id": "healthy", "state": "routed"}], "routed": ["healthy"]}\n',
                              b''),
 ('route', True, 'team'): (0,
                           b'{"requests": [{"detail": "[Errno 13] Permission denied: \'{CASE}/engine/mailbox/engine/fr'
                           b'ont-door\'", "reason": "team_mailbox_unreadable", "request_id": "damaged", "state": "held'
                           b'"}, {"request_id": "healthy", "state": "routed"}], "routed": ["healthy"]}\n',
                           b''),
 ('row', False, 'inputs'): (0,
                            b'{"small_changes": [{"detail": "[Errno 13] Permission denied: \'{CASE}/inputs/note.md\''
                            b'", "reason": "small_change_configuration", "request_id": "engine-partial", "state": "hel'
                            b'd"}]}\n',
                            b''),
 ('row', True, 'inputs'): (0,
                           b'{"small_changes": [{"detail": "[Errno 13] Permission denied: \'{CASE}/inputs/note.md\'", "'
                           b'reason": "small_change_configuration", "request_id": "engine-partial", "state": "held"}]'
                           b'}\n',
                           b''),
 ('status', False, 'across'): (0,
                               b'{"requests": [{"detail": "[Errno 13] Permission denied: \'{CASE}/engine/mailbox/acros'
                               b's/front-door\'", "reason": "team_mailbox_unreadable", "request_id": "damaged", "state'
                               b'": "held"}, {"request_id": "healthy", "state": "ready"}]}\n',
                               b''),
 ('status', False, 'bindings'): (0,
                                 b'{"requests": [{"detail": "[Errno 13] Permission denied: \'{CASE}/engine/mailbox/b'
                                 b'indings/engine/router\'", "reason": "team_mailbox_unreadable", "request_id": "dam'
                                 b'aged", "state": "held"}, {"request_id": "healthy", "state": "ready"}]}\n',
                                 b''),
 ('status', False, 'mailbox'): (0,
                                b'{"requests": [{"detail": "symlink paths are not supported: {CASE}/engine/mailbox", "'
                                b'reason": "team_mailbox_unreadable", "request_id": "damaged", "state": "held"}, {"req'
                                b'uest_id": "healthy", "state": "ready"}]}\n',
                                b''),
 ('status', False, 'team'): (0,
                             b'{"requests": [{"detail": "[Errno 13] Permission denied: \'{CASE}/engine/mailbox/engin'
                             b'e/front-door\'", "reason": "team_mailbox_unreadable", "request_id": "damaged", "state'
                             b'": "held"}, {"request_id": "healthy", "state": "ready"}]}\n',
                             b''),
 ('status', True, 'across'): (0,
                              b'{"requests": [{"detail": "[Errno 13] Permission denied: \'{CASE}/engine/mailbox/acros'
                              b's/front-door\'", "reason": "team_mailbox_unreadable", "request_id": "damaged", "state'
                              b'": "held"}, {"request_id": "healthy", "state": "ready"}]}\n',
                              b''),
 ('status', True, 'bindings'): (0,
                                b'{"requests": [{"detail": "[Errno 13] Permission denied: \'{CASE}/engine/mailbox/bindi'
                                b'ngs/engine/router\'", "reason": "team_mailbox_unreadable", "request_id": "damaged", "'
                                b'state": "held"}, {"request_id": "healthy", "state": "ready"}]}\n',
                                b''),
 ('status', True, 'mailbox'): (0,
                               b'{"requests": [{"detail": "symlink paths are not supported: {CASE}/engine/mailbox", "'
                               b'reason": "team_mailbox_unreadable", "request_id": "damaged", "state": "held"}, {"req'
                               b'uest_id": "healthy", "state": "ready"}]}\n',
                               b''),
 ('status', True, 'team'): (0,
                            b'{"requests": [{"detail": "[Errno 13] Permission denied: \'{CASE}/engine/mailbox/engine/fr'
                            b'ont-door\'", "reason": "team_mailbox_unreadable", "request_id": "damaged", "state": "held'
                            b'"}, {"request_id": "healthy", "state": "ready"}]}\n',
                            b'')}
R13_CONSUMER_PROBE = r'''
import contextlib, io, json, os, sys
from pathlib import Path
from types import SimpleNamespace
tools, fallback, raw = sys.argv[1:]
sys.path[:0] = [tools, fallback]
config = json.loads(raw)
root = Path(config['root'])
import hierarchy_fresh_brief as fresh
import hierarchy_router as router
import hierarchy_lifecycle as life
import hierarchy_workspace as workspace
router._owner_home = lambda: root / 'owner'
target = root / 'inputs' / 'note.md'
seam = config['seam']
def captured_main(module,args):
    with io.BytesIO() as raw:
        with io.TextIOWrapper(raw,encoding='utf-8') as output:
            with contextlib.redirect_stdout(output): code = module.main(args)
            output.flush()
            captured = raw.getvalue()
    return code,captured
def damage_inputs():
    source = root / 'inputs'
    if not source.is_symlink():
        source.rename(root / 'original-inputs')
        source.symlink_to(root / 'denied', target_is_directory=True)
def rows(value):
    return [{k: row[k] for k in ('request_id','state','reason','detail') if k in row}
            for row in value or []]
def project(value):
    if 'error' in value:
        return {'error': value['error']}
    result = {}
    if 'requests' in value: result['requests'] = rows(value['requests']) if value['requests'] is not None else None
    if 'routed' in value: result['routed'] = [r['request_id'] for r in value['routed']]
    for key in ('report_error', 'held'):
        if key in value: result[key] = value[key]
    if 'small_changes' in value: result['small_changes'] = rows(value['small_changes'])
    return result
answer = {}
code = 0
try:
    if seam in ('status','route','closing-report','row'):
        if seam == 'closing-report':
            damage_inputs()
            original_report = router.report
            def closing(*args, **kwargs):
                fresh.file_ref(target)
                return original_report(*args, **kwargs)
            router.report = closing
        if seam == 'row':
            import hierarchy_small_change_dispatch as dispatch
            original_progress = dispatch.Row.progress
            def progress(self,*args,**kwargs):
                damage_inputs()
                self.operation.read(target)
                return original_progress(self,*args,**kwargs)
            dispatch.Row.progress = progress
        command = 'dispatch' if seam == 'row' else 'route' if seam != 'status' else 'status'
        args = ['--lifecycle',config['journal'],'--store',config['store'],command,'--wait','0']
        if command == 'route': args += ['--actor','router-1','--evidence-only']
        if command == 'dispatch': args += ['--recipes',str(root/'inputs'/'note.md'),'--evidence-only']
        code,output = captured_main(router,args)
        answer = project(json.loads(output))
    elif seam == 'deliver':
        ledger = workspace.Store(config['store']).load()
        value, failure = router.deliver(life.Lifecycle(config['journal']),ledger,'router-1','damaged',0)
        answer = {'delivered': value is not None, 'failure': failure}
    elif seam in ('evidence','attachment','receipts'):
        operation = fresh._Operation()
        active = operation.path_guard.active() if hasattr(operation.path_guard,'active') else contextlib.nullcontext()
        with active:
            if seam == 'evidence':
                brief = fresh.Brief(_operation=operation)
                brief.evidence({'path':str(target),'sha256':'0'*64},
                    {'path':str(root/'origin'),'sha256':'0'*64})
                answer = {'kinds':[item['kind'] for item in brief.sections['Evidence references']]}
                operation.verify()
            elif seam == 'attachment':
                mailbox = fresh._CapturedMailbox(config['mailbox'],_operation=operation)
                try: fresh._unread_attachment(mailbox,{'path':str(target),'sha256':'0'*64})
                except fresh.UnverifiedAttachment as error: answer = {'unverified':str(error)}
                else: answer = {'unverified':None}
                operation.verify()
            else:
                mailbox = fresh._CapturedMailbox(config['mailbox'],_operation=operation)
                try: mailbox.delivery_receipts(root/'delivery','delivered','engine/orchestrator',{})
                except (ValueError,OSError) as error: answer = {'refused':str(error)}
                else: answer = {'refused':None}
            answer['healthy_capture'] = fresh._Operation().read(root/'healthy.md')[0]['sha256']
    elif seam.startswith('loop-'):
        import hierarchy_loop as loop
        calls = []
        def child(tool,args,decoder,planned=None):
            calls.append(tool)
            if tool == 'jobs': return 0, {'rows':[]}, '', None
            if tool == 'sweep': return 0, {'rows':[],'still_unread':[],'root_queue':[],'root_time':[]}, '', None
            return 0, {'router':'router-1','requests':[]}, '', None
        loop.run_child = child
        ticks = [0]
        def tick():
            ticks[0] += 6
            return ticks[0]
        loop.time = SimpleNamespace(**{**vars(loop.time),'monotonic':tick})
        plan = root/'inputs'/'note.md' if config['damage']=='plan' else root/'dispatcher-host-plan.json'
        args = ['--lifecycle',config['journal'],'--store',config['store'],'--recipes',config['recipes'],
                '--state-dir',str(root/'state'),'--dispatcher-host-plan',str(plan),seam[5:]]
        if seam == 'loop-run': args += ['--interval','5','--passes','2']
        code,output = captured_main(loop,args)
        reports = [json.loads(line) for line in output.splitlines()]
        answer = {'reports':[{'pass_id':r['pass_id'], 'steps':[{k:s[k] for k in ('step','state','exit') if k in s}
                    for s in r.get('steps',[])], 'holds':[{k:h[k] for k in ('step','kind','detail') if k in h}
                    for h in r.get('holds',[])]} if 'pass_id' in r else r for r in reports],
                  'run_open_calls':calls.count('jobs')}
    else: raise AssertionError(seam)
except (ValueError,OSError) as error:
    answer = {'error':str(error)}
    code = 2
print(json.dumps(answer,sort_keys=True))
sys.exit(code)
'''


def r13_consumer_probe(tmp_path, seam, planned=False, damage="inputs", *, tools=None):
    """Identical public fixture and entry point for baseline capture and history-free tests."""
    from tests.integration.test_hierarchy_router import Loop
    from tests.integration.test_hierarchy_small_change_dispatch import DispatchWorld, modelled_loop_plan
    import hierarchy_hosts
    tmp_path.mkdir(parents=True, exist_ok=True)
    world = DispatchWorld(tmp_path) if seam == "row" else Loop(tmp_path)
    mailbox = world.root if seam == "row" else world.team("engine")
    world.team("docs")
    if seam != "row": world.approved(request("damaged"))
    world.approved(request("healthy", team="docs"))
    inputs, denied = tmp_path / "inputs", tmp_path / "denied"
    inputs.mkdir(); denied.mkdir()
    (tmp_path / "healthy.md").write_bytes(b"healthy public reference")
    (inputs / "note.md").write_bytes(world.recipes_path.read_bytes() if seam == "row" else b"fixture target")
    recipes = world.recipes_path if seam == "row" else tmp_path / "recipes.json"
    if seam != "row": recipes.write_text("{}")
    modelled_loop_plan(tmp_path)
    if planned:
        for team, base in world.mailboxes.items():
            (base.parent / "host-plan.json").write_text(json.dumps(
                hierarchy_hosts.plan_record(team,"codex-cli","codex-cli",{},"0"*64)))
    if seam.startswith("loop-") and damage == "request":
        world.ledger.publish(request("scope-under-link",paths=[str(inputs/"note.md")]))
    replaced = None
    if seam in {"status","route","deliver"}:
        replaced = mailbox if damage == "mailbox" else mailbox / ("engine" if damage == "team" else damage)
    elif seam not in {"closing-report","row"}:
        replaced = inputs
    if seam == "receipts":
        replaced = tmp_path / "delivery" / "delivered"
        (replaced / "engine" / "orchestrator").mkdir(parents=True)
    if replaced is not None:
        replaced.rename(replaced.with_name(replaced.name+"-before"))
        symlink_or_skip(denied,replaced,target_is_directory=True)
    denied.chmod(0)
    config = dict(root=str(tmp_path),seam=seam,damage=damage,planned=planned,journal=str(world.ledger.path),
                  store=str(world.workspace.store),mailbox=str(mailbox),recipes=str(recipes))
    try:
        result = subprocess.run([sys.executable,"-I","-B","-c",R13_CONSUMER_PROBE,
            str(tools or ROOT/"tools"),str(ROOT/"tools"),json.dumps(config)],capture_output=True,timeout=45)
    finally:
        denied.chmod(0o700)
    return result.returncode,result.stdout.replace(os.fsencode(tmp_path),b"{CASE}"),result.stderr.replace(os.fsencode(tmp_path),b"{CASE}")


@lifecycle_only
@pytest.mark.parametrize("seam", ["evidence","attachment","receipts"])
def test_round13_optional_and_receipt_target_errors_match_baseline(tmp_path,seam):
    if os.geteuid()==0: pytest.skip("mode-000 witness requires an unprivileged runner")
    assert r13_consumer_probe(tmp_path,seam)==R13_CONSUMER_GOLDENS[(seam,False,"inputs")]


# Recorded from ec27eebf outside this checkout. Tests consume data, never Git history.
# CLI cases retain native capabilities; portable API cases exercise the reference
# fallback. Unsupported secure locking has its own refusal/probe test below.
R9_PUBLIC_GOLDENS = {('check', 'denied', False, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('check', 'denied', False, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('check', 'denied', True, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('check', 'denied', True, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('check', 'missing', False, 'native'): (0, b'{"result": false}\n', b''),
 ('check', 'missing', False, 'portable'): (0, b'{"result": false}\n', b''),
 ('check', 'missing', True, 'native'): (0, b'{"result": false}\n', b''),
 ('check', 'missing', True, 'portable'): (0, b'{"result": false}\n', b''),
 ('check', 'not-directory', False, 'native'): (0, b'{"result": false}\n', b''),
 ('check', 'not-directory', False, 'portable'): (0, b'{"result": false}\n', b''),
 ('check', 'not-directory', True, 'native'): (0, b'{"result": false}\n', b''),
 ('check', 'not-directory', True, 'portable'): (0, b'{"result": false}\n', b''),
 ('check', 'symlink', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('check', 'symlink', False, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('check', 'symlink', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('check', 'symlink', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('compose-file', 'denied', False, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/manifest.json\'"}\n', b''),
 ('compose-file', 'denied', True, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/manifest.json\'"}\n', b''),
 ('compose-file', 'missing', False, 'native'): (2, b'{"error": "[Errno 2] No such file or directory: \'ordinary\'"}\n', b''),
 ('compose-file', 'missing', True, 'native'): (2, b'{"error": "[Errno 2] No such file or directory: \'ordinary\'"}\n', b''),
 ('compose-file', 'not-directory', False, 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'{CASE}/ordinary/manifest.json\'"}\n', b''),
 ('compose-file', 'not-directory', True, 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'{CASE}/ordinary/manifest.json\'"}\n', b''),
 ('compose-file', 'symlink', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('compose-file', 'symlink', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('compose:--delivery-dir', 'denied', False, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('compose:--delivery-dir', 'denied', True, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('compose:--delivery-dir', 'missing', False, 'native'): (2, b'{"error": "lifecycle directory unavailable: {CASE}/missing-journal"}\n', b''),
 ('compose:--delivery-dir', 'missing', True, 'native'): (2, b'{"error": "lifecycle directory unavailable: {CASE}/missing-journal"}\n', b''),
 ('compose:--delivery-dir', 'not-directory', False, 'native'): (2, b'{"error": "lifecycle directory unavailable: {CASE}/missing-journal"}\n', b''),
 ('compose:--delivery-dir', 'not-directory', True, 'native'): (2, b'{"error": "lifecycle directory unavailable: {CASE}/missing-journal"}\n', b''),
 ('compose:--delivery-dir', 'symlink', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('compose:--delivery-dir', 'symlink', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('compose:--lifecycle', 'denied', False, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('compose:--lifecycle', 'denied', True, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('compose:--lifecycle', 'missing', False, 'native'): (2, b'{"error": "lifecycle directory unavailable: {CASE}/ordinary/note.md"}\n', b''),
 ('compose:--lifecycle', 'missing', True, 'native'): (2, b'{"error": "lifecycle directory unavailable: {CASE}/ordinary/note.md"}\n', b''),
 ('compose:--lifecycle', 'not-directory', False, 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('compose:--lifecycle', 'not-directory', True, 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('compose:--lifecycle', 'symlink', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('compose:--lifecycle', 'symlink', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('compose:--root', 'denied', False, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('compose:--root', 'denied', True, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('compose:--root', 'missing', False, 'native'): (2, b'{"error": "[Errno 2] No such file or directory: \'ordinary\'"}\n', b''),
 ('compose:--root', 'missing', True, 'native'): (2, b'{"error": "[Errno 2] No such file or directory: \'ordinary\'"}\n', b''),
 ('compose:--root', 'not-directory', False, 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'{CASE}/ordinary/note.md/manifest.json\'"}\n', b''),
 ('compose:--root', 'not-directory', True, 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'{CASE}/ordinary/note.md/manifest.json\'"}\n', b''),
 ('compose:--root', 'symlink', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('compose:--root', 'symlink', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('disposition', 'denied', False, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('disposition', 'denied', False, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('disposition', 'denied', True, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('disposition', 'denied', True, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('disposition', 'missing', False, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('disposition', 'missing', False, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('disposition', 'missing', True, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('disposition', 'missing', True, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('disposition', 'not-directory', False, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('disposition', 'not-directory', False, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('disposition', 'not-directory', True, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('disposition', 'not-directory', True, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('disposition', 'symlink', False, 'native'): (0,
                                               b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"first": "lifecycle row UNKNOWN at'
                                               b' event fault-event: symlink paths are not supported: {CASE}/ordinary"}}}\n',
                                               b''),
 ('disposition', 'symlink', False, 'portable'): (0,
                                                 b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"first": "lifecycle row UNKNOWN at'
                                                 b' event fault-event: symlink paths are not supported: {CASE}/ordinary"}}}\n',
                                                 b''),
 ('disposition', 'symlink', True, 'native'): (0,
                                              b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"first": "lifecycle row UNKNOWN at'
                                              b' event fault-event: symlink paths are not supported: {CASE}/ordinary"}}}\n',
                                              b''),
 ('disposition', 'symlink', True, 'portable'): (0,
                                                b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"first": "lifecycle row UNKNOWN at'
                                                b' event fault-event: symlink paths are not supported: {CASE}/ordinary"}}}\n',
                                                b''),
 ('exists', 'denied', False, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('exists', 'denied', False, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('exists', 'denied', True, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('exists', 'denied', True, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('exists', 'missing', False, 'native'): (0, b'{"result": false}\n', b''),
 ('exists', 'missing', False, 'portable'): (0, b'{"result": false}\n', b''),
 ('exists', 'missing', True, 'native'): (0, b'{"result": false}\n', b''),
 ('exists', 'missing', True, 'portable'): (0, b'{"result": false}\n', b''),
 ('exists', 'not-directory', False, 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('exists', 'not-directory', False, 'portable'): (2, b'{"error": "[Errno 20] Not a directory: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('exists', 'not-directory', True, 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('exists', 'not-directory', True, 'portable'): (2, b'{"error": "[Errno 20] Not a directory: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('exists', 'symlink', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('exists', 'symlink', False, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('exists', 'symlink', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('exists', 'symlink', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('loop:--lifecycle', 'denied', False, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('loop:--lifecycle', 'denied', True, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('loop:--lifecycle', 'missing', False, 'native'): (3, b'{"last": null, "schema": "aegis.loop-status/v1", "state": "not_running"}\n', b''),
 ('loop:--lifecycle', 'missing', True, 'native'): (3, b'{"last": null, "schema": "aegis.loop-status/v1", "state": "not_running"}\n', b''),
 ('loop:--lifecycle', 'not-directory', False, 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'{CASE}/ordinary/note.md.loop.lock\'"}\n', b''),
 ('loop:--lifecycle', 'not-directory', True, 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'{CASE}/ordinary/note.md.loop.lock\'"}\n', b''),
 ('loop:--lifecycle', 'symlink', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('loop:--lifecycle', 'symlink', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('loop:--recipes', 'denied', False, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('loop:--recipes', 'denied', True, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('loop:--recipes', 'missing', False, 'native'): (3, b'{"last": null, "schema": "aegis.loop-status/v1", "state": "not_running"}\n', b''),
 ('loop:--recipes', 'missing', True, 'native'): (3, b'{"last": null, "schema": "aegis.loop-status/v1", "state": "not_running"}\n', b''),
 ('loop:--recipes', 'not-directory', False, 'native'): (3, b'{"last": null, "schema": "aegis.loop-status/v1", "state": "not_running"}\n', b''),
 ('loop:--recipes', 'not-directory', True, 'native'): (3, b'{"last": null, "schema": "aegis.loop-status/v1", "state": "not_running"}\n', b''),
 ('loop:--recipes', 'symlink', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('loop:--recipes', 'symlink', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('loop:--state-dir', 'denied', False, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('loop:--state-dir', 'denied', True, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('loop:--state-dir', 'missing', False, 'native'): (3, b'{"last": null, "schema": "aegis.loop-status/v1", "state": "not_running"}\n', b''),
 ('loop:--state-dir', 'missing', True, 'native'): (3, b'{"last": null, "schema": "aegis.loop-status/v1", "state": "not_running"}\n', b''),
 ('loop:--state-dir', 'not-directory', False, 'native'): (3, b'{"last": null, "schema": "aegis.loop-status/v1", "state": "not_running"}\n', b''),
 ('loop:--state-dir', 'not-directory', True, 'native'): (3, b'{"last": null, "schema": "aegis.loop-status/v1", "state": "not_running"}\n', b''),
 ('loop:--state-dir', 'symlink', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('loop:--state-dir', 'symlink', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('loop:--store', 'denied', False, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('loop:--store', 'denied', True, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('loop:--store', 'missing', False, 'native'): (3, b'{"last": null, "schema": "aegis.loop-status/v1", "state": "not_running"}\n', b''),
 ('loop:--store', 'missing', True, 'native'): (3, b'{"last": null, "schema": "aegis.loop-status/v1", "state": "not_running"}\n', b''),
 ('loop:--store', 'not-directory', False, 'native'): (3, b'{"last": null, "schema": "aegis.loop-status/v1", "state": "not_running"}\n', b''),
 ('loop:--store', 'not-directory', True, 'native'): (3, b'{"last": null, "schema": "aegis.loop-status/v1", "state": "not_running"}\n', b''),
 ('loop:--store', 'symlink', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('loop:--store', 'symlink', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('members', 'denied', False, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('members', 'denied', False, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('members', 'denied', True, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('members', 'denied', True, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('members', 'missing', False, 'native'): (2, b'{"error": "[Errno 2] No such file or directory: \'ordinary\'"}\n', b''),
 ('members', 'missing', False, 'portable'): (2, b'{"error": "[Errno 2] No such file or directory: \'{CASE}/ordinary\'"}\n', b''),
 ('members', 'missing', True, 'native'): (2, b'{"error": "[Errno 2] No such file or directory: \'ordinary\'"}\n', b''),
 ('members', 'missing', True, 'portable'): (2, b'{"error": "[Errno 2] No such file or directory: \'{CASE}/ordinary\'"}\n', b''),
 ('members', 'not-directory', False, 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'ordinary\'"}\n', b''),
 ('members', 'not-directory', False, 'portable'): (2, b'{"error": "reference parent must be a directory: {CASE}/ordinary"}\n', b''),
 ('members', 'not-directory', True, 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'ordinary\'"}\n', b''),
 ('members', 'not-directory', True, 'portable'): (2, b'{"error": "reference parent must be a directory: {CASE}/ordinary"}\n', b''),
 ('members', 'symlink', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('members', 'symlink', False, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('members', 'symlink', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('members', 'symlink', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('paths', 'denied', False, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('paths', 'denied', False, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('paths', 'denied', True, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('paths', 'denied', True, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('paths', 'missing', False, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["healthy", "hostile"], "unknown": {}}}\n', b''),
 ('paths', 'missing', False, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["healthy", "hostile"], "unknown": {}}}\n', b''),
 ('paths', 'missing', True, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["healthy", "hostile"], "unknown": {}}}\n', b''),
 ('paths', 'missing', True, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["healthy", "hostile"], "unknown": {}}}\n', b''),
 ('paths', 'not-directory', False, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["healthy", "hostile"], "unknown": {}}}\n', b''),
 ('paths', 'not-directory', False, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["healthy", "hostile"], "unknown": {}}}\n', b''),
 ('paths', 'not-directory', True, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["healthy", "hostile"], "unknown": {}}}\n', b''),
 ('paths', 'not-directory', True, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["healthy", "hostile"], "unknown": {}}}\n', b''),
 ('paths', 'symlink', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('paths', 'symlink', False, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('paths', 'symlink', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('paths', 'symlink', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('read', 'denied', False, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('read', 'denied', False, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('read', 'denied', True, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('read', 'denied', True, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('read', 'missing', False, 'native'): (2, b'{"error": "[Errno 2] No such file or directory: \'ordinary\'"}\n', b''),
 ('read', 'missing', False, 'portable'): (2, b'{"error": "[Errno 2] No such file or directory: \'{CASE}/ordinary\'"}\n', b''),
 ('read', 'missing', True, 'native'): (2, b'{"error": "[Errno 2] No such file or directory: \'ordinary\'"}\n', b''),
 ('read', 'missing', True, 'portable'): (2, b'{"error": "[Errno 2] No such file or directory: \'{CASE}/ordinary\'"}\n', b''),
 ('read', 'not-directory', False, 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'ordinary\'"}\n', b''),
 ('read', 'not-directory', False, 'portable'): (2, b'{"error": "reference parent must be a directory: {CASE}/ordinary"}\n', b''),
 ('read', 'not-directory', True, 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'ordinary\'"}\n', b''),
 ('read', 'not-directory', True, 'portable'): (2, b'{"error": "reference parent must be a directory: {CASE}/ordinary"}\n', b''),
 ('read', 'symlink', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('read', 'symlink', False, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('read', 'symlink', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('read', 'symlink', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('resolve', 'denied', False, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('resolve', 'denied', False, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('resolve', 'denied', True, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('resolve', 'denied', True, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('resolve', 'missing', False, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('resolve', 'missing', False, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('resolve', 'missing', True, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('resolve', 'missing', True, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('resolve', 'not-directory', False, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('resolve', 'not-directory', False, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('resolve', 'not-directory', True, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('resolve', 'not-directory', True, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('resolve', 'symlink', False, 'native'): (0,
                                           b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"first": "lifecycle row UNKNOWN at eve'
                                           b'nt fault-event: symlink paths are not supported: {CASE}/ordinary"}}}\n',
                                           b''),
 ('resolve', 'symlink', False, 'portable'): (0,
                                             b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"first": "lifecycle row UNKNOWN at eve'
                                             b'nt fault-event: symlink paths are not supported: {CASE}/ordinary"}}}\n',
                                             b''),
 ('resolve', 'symlink', True, 'native'): (0,
                                          b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"first": "lifecycle row UNKNOWN at eve'
                                          b'nt fault-event: symlink paths are not supported: {CASE}/ordinary"}}}\n',
                                          b''),
 ('resolve', 'symlink', True, 'portable'): (0,
                                            b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"first": "lifecycle row UNKNOWN at eve'
                                            b'nt fault-event: symlink paths are not supported: {CASE}/ordinary"}}}\n',
                                            b''),
 ('router:--lifecycle', 'denied', False, 'native'): (2,
                                                     b'{"error":"[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'","execution_enabled":false,"source'
                                                     b'":"arguments","state":"hold"}\n',
                                                     b''),
 ('router:--lifecycle', 'denied', True, 'native'): (2,
                                                    b'{"error":"[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'","execution_enabled":false,"source'
                                                    b'":"arguments","state":"hold"}\n',
                                                    b''),
 ('router:--lifecycle', 'missing', False, 'native'): (2,
                                                      b'{"error":"[Errno 2] No such file or directory: \'{CASE}/ordinary/note.md/.write.lock\'","execution_ena'
                                                      b'bled":false,"source":"journal","state":"hold"}\n',
                                                      b''),
 ('router:--lifecycle', 'missing', True, 'native'): (2,
                                                     b'{"error":"[Errno 2] No such file or directory: \'{CASE}/ordinary/note.md/.write.lock\'","execution_ena'
                                                     b'bled":false,"source":"journal","state":"hold"}\n',
                                                     b''),
 ('router:--lifecycle', 'not-directory', False, 'native'): (2,
                                                            b'{"error":"[Errno 20] Not a directory: \'{CASE}/ordinary/note.md/.write.lock\'","execution_enab'
                                                            b'led":false,"source":"journal","state":"hold"}\n',
                                                            b''),
 ('router:--lifecycle', 'not-directory', True, 'native'): (2,
                                                           b'{"error":"[Errno 20] Not a directory: \'{CASE}/ordinary/note.md/.write.lock\'","execution_enabled"'
                                                           b':false,"source":"journal","state":"hold"}\n',
                                                           b''),
 ('router:--lifecycle', 'symlink', False, 'native'): (2,
                                                      b'{"error":"symlink paths are not supported: {CASE}/ordinary","execution_enabled":false,"source":"argu'
                                                      b'ments","state":"hold"}\n',
                                                      b''),
 ('router:--lifecycle', 'symlink', True, 'native'): (2,
                                                     b'{"error":"symlink paths are not supported: {CASE}/ordinary","execution_enabled":false,"source":"argument'
                                                     b's","state":"hold"}\n',
                                                     b''),
 ('router:--recipes', 'denied', False, 'native'): (2,
                                                   b'{"error":"[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'","execution_enabled":false,"source":"a'
                                                   b'rguments","state":"hold"}\n',
                                                   b''),
 ('router:--recipes', 'denied', True, 'native'): (2,
                                                  b'{"error":"[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'","execution_enabled":false,"source":"a'
                                                  b'rguments","state":"hold"}\n',
                                                  b''),
 ('router:--recipes', 'missing', False, 'native'): (0,
                                                    b'{"authenticated":false,"escalations":[],"execution_enabled":false,"identity":"configured","requests":[],'
                                                    b'"router":"router-1","schema":"aegis.router-status/v1"}\n',
                                                    b''),
 ('router:--recipes', 'missing', True, 'native'): (0,
                                                   b'{"authenticated":false,"escalations":[],"execution_enabled":false,"identity":"configured","requests":[],'
                                                   b'"router":"router-1","schema":"aegis.router-status/v1"}\n',
                                                   b''),
 ('router:--recipes', 'not-directory', False, 'native'): (0,
                                                          b'{"authenticated":false,"escalations":[],"execution_enabled":false,"identity":"configured","reque'
                                                          b'sts":[],"router":"router-1","schema":"aegis.router-status/v1"}\n',
                                                          b''),
 ('router:--recipes', 'not-directory', True, 'native'): (0,
                                                         b'{"authenticated":false,"escalations":[],"execution_enabled":false,"identity":"configured","requests"'
                                                         b':[],"router":"router-1","schema":"aegis.router-status/v1"}\n',
                                                         b''),
 ('router:--recipes', 'symlink', False, 'native'): (2,
                                                    b'{"error":"symlink paths are not supported: {CASE}/ordinary","execution_enabled":false,"source":"argument'
                                                    b's","state":"hold"}\n',
                                                    b''),
 ('router:--recipes', 'symlink', True, 'native'): (2,
                                                   b'{"error":"symlink paths are not supported: {CASE}/ordinary","execution_enabled":false,"source":"argument'
                                                   b's","state":"hold"}\n',
                                                   b''),
 ('router:--store', 'denied', False, 'native'): (2,
                                                 b'{"error":"[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'","execution_enabled":false,"source":"a'
                                                 b'rguments","state":"hold"}\n',
                                                 b''),
 ('router:--store', 'denied', True, 'native'): (2,
                                                b'{"error":"[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'","execution_enabled":false,"source":"a'
                                                b'rguments","state":"hold"}\n',
                                                b''),
 ('router:--store', 'missing', False, 'native'): (2,
                                                  b'{"error":"captured directory disappeared: {CASE}/ordinary/note.md/events","execution_enabled":false,"sou'
                                                  b'rce":"store","state":"hold"}\n',
                                                  b''),
 ('router:--store', 'missing', True, 'native'): (2,
                                                 b'{"error":"captured directory disappeared: {CASE}/ordinary/note.md/events","execution_enabled":false,"source"'
                                                 b':"store","state":"hold"}\n',
                                                 b''),
 ('router:--store', 'not-directory', False, 'native'): (2,
                                                        b'{"error":"workspace store is not initialized","execution_enabled":false,"source":"store","state":"ho'
                                                        b'ld"}\n',
                                                        b''),
 ('router:--store', 'not-directory', True, 'native'): (2,
                                                       b'{"error":"workspace store is not initialized","execution_enabled":false,"source":"store","state":"ho'
                                                       b'ld"}\n',
                                                       b''),
 ('router:--store', 'symlink', False, 'native'): (2,
                                                  b'{"error":"symlink paths are not supported: {CASE}/ordinary","execution_enabled":false,"source":"argument'
                                                  b's","state":"hold"}\n',
                                                  b''),
 ('router:--store', 'symlink', True, 'native'): (2,
                                                 b'{"error":"symlink paths are not supported: {CASE}/ordinary","execution_enabled":false,"source":"arguments","'
                                                 b'state":"hold"}\n',
                                                 b''),
 ('scan_workspace', 'denied', False, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('scan_workspace', 'denied', False, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('scan_workspace', 'denied', True, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('scan_workspace', 'denied', True, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('scan_workspace', 'missing', False, 'native'): (2, b'{"error": "scan workspace does not match lane worktree"}\n', b''),
 ('scan_workspace', 'missing', False, 'portable'): (2, b'{"error": "scan workspace does not match lane worktree"}\n', b''),
 ('scan_workspace', 'missing', True, 'native'): (2, b'{"error": "scan workspace does not match lane worktree"}\n', b''),
 ('scan_workspace', 'missing', True, 'portable'): (2, b'{"error": "scan workspace does not match lane worktree"}\n', b''),
 ('scan_workspace', 'not-directory', False, 'native'): (2, b'{"error": "scan workspace does not match lane worktree"}\n', b''),
 ('scan_workspace', 'not-directory', False, 'portable'): (2, b'{"error": "scan workspace does not match lane worktree"}\n', b''),
 ('scan_workspace', 'not-directory', True, 'native'): (2, b'{"error": "scan workspace does not match lane worktree"}\n', b''),
 ('scan_workspace', 'not-directory', True, 'portable'): (2, b'{"error": "scan workspace does not match lane worktree"}\n', b''),
 ('scan_workspace', 'symlink', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('scan_workspace', 'symlink', False, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('scan_workspace', 'symlink', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('scan_workspace', 'symlink', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('scope', 'denied', False, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('scope', 'denied', False, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('scope', 'denied', True, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('scope', 'denied', True, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('scope', 'missing', False, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["healthy", "hostile"], "unknown": {}}}\n', b''),
 ('scope', 'missing', False, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["healthy", "hostile"], "unknown": {}}}\n', b''),
 ('scope', 'missing', True, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["healthy", "hostile"], "unknown": {}}}\n', b''),
 ('scope', 'missing', True, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["healthy", "hostile"], "unknown": {}}}\n', b''),
 ('scope', 'not-directory', False, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["healthy", "hostile"], "unknown": {}}}\n', b''),
 ('scope', 'not-directory', False, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["healthy", "hostile"], "unknown": {}}}\n', b''),
 ('scope', 'not-directory', True, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["healthy", "hostile"], "unknown": {}}}\n', b''),
 ('scope', 'not-directory', True, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["healthy", "hostile"], "unknown": {}}}\n', b''),
 ('scope', 'symlink', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('scope', 'symlink', False, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('scope', 'symlink', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('scope', 'symlink', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('shared-disposition', 'denied', False, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-disposition', 'denied', False, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-disposition', 'denied', True, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-disposition', 'denied', True, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-disposition', 'missing', False, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-disposition', 'missing', False, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-disposition', 'missing', True, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-disposition', 'missing', True, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-disposition', 'not-directory', False, 'native'): (0,
                                                            b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n',
                                                            b''),
 ('shared-disposition', 'not-directory', False, 'portable'): (0,
                                                              b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n',
                                                              b''),
 ('shared-disposition', 'not-directory', True, 'native'): (0,
                                                           b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n',
                                                           b''),
 ('shared-disposition', 'not-directory', True, 'portable'): (0,
                                                             b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n',
                                                             b''),
 ('shared-disposition', 'symlink', False, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-disposition', 'symlink', False, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-disposition', 'symlink', True, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-disposition', 'symlink', True, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-resolve', 'denied', False, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-resolve', 'denied', False, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-resolve', 'denied', True, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-resolve', 'denied', True, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-resolve', 'missing', False, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-resolve', 'missing', False, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-resolve', 'missing', True, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-resolve', 'missing', True, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-resolve', 'not-directory', False, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-resolve', 'not-directory', False, 'portable'): (0,
                                                          b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n',
                                                          b''),
 ('shared-resolve', 'not-directory', True, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-resolve', 'not-directory', True, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-resolve', 'symlink', False, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-resolve', 'symlink', False, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-resolve', 'symlink', True, 'native'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('shared-resolve', 'symlink', True, 'portable'): (0, b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "unknown": {}}}\n', b''),
 ('verify:--path', 'denied', False, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('verify:--path', 'denied', True, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('verify:--path', 'missing', False, 'native'): (2, b'{"error": "[Errno 2] No such file or directory: \'ordinary\'"}\n', b''),
 ('verify:--path', 'missing', True, 'native'): (2, b'{"error": "[Errno 2] No such file or directory: \'ordinary\'"}\n', b''),
 ('verify:--path', 'not-directory', False, 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'ordinary\'"}\n', b''),
 ('verify:--path', 'not-directory', True, 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'ordinary\'"}\n', b''),
 ('verify:--path', 'symlink', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('verify:--path', 'symlink', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('worktree', 'denied', False, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('worktree', 'denied', False, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('worktree', 'denied', True, 'native'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('worktree', 'denied', True, 'portable'): (2, b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}\n', b''),
 ('worktree', 'missing', False, 'native'): (0, b'{"result": {"refusals": []}}\n', b''),
 ('worktree', 'missing', False, 'portable'): (0, b'{"result": {"refusals": []}}\n', b''),
 ('worktree', 'missing', True, 'native'): (0, b'{"result": {"refusals": []}}\n', b''),
 ('worktree', 'missing', True, 'portable'): (0, b'{"result": {"refusals": []}}\n', b''),
 ('worktree', 'not-directory', False, 'native'): (0, b'{"result": {"refusals": []}}\n', b''),
 ('worktree', 'not-directory', False, 'portable'): (0, b'{"result": {"refusals": []}}\n', b''),
 ('worktree', 'not-directory', True, 'native'): (0, b'{"result": {"refusals": []}}\n', b''),
 ('worktree', 'not-directory', True, 'portable'): (0, b'{"result": {"refusals": []}}\n', b''),
 ('worktree', 'symlink', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('worktree', 'symlink', False, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('worktree', 'symlink', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b''),
 ('worktree', 'symlink', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n', b'')}
R9_WITNESS_GOLDENS = {('members', 'not-directory', 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'ordinary\'", "type": "CaptureChanged"}\n', b''),
 ('members', 'not-directory', 'portable'): (2, b'{"error": "reference parent must be a directory: {CASE}/ordinary", "type": "CaptureChanged"}\n', b''),
 ('members', 'symlink', 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'ordinary\'", "type": "CaptureChanged"}\n', b''),
 ('members', 'symlink', 'portable'): (2, b'{"error": "reference parent must be a directory: {CASE}/ordinary", "type": "CaptureChanged"}\n', b''),
 ('read', 'not-directory', 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'ordinary\'", "type": "CaptureChanged"}\n', b''),
 ('read', 'not-directory', 'portable'): (2, b'{"error": "reference parent must be a directory: {CASE}/ordinary", "type": "CaptureChanged"}\n', b''),
 ('read', 'symlink', 'native'): (2, b'{"error": "[Errno 20] Not a directory: \'ordinary\'", "type": "CaptureChanged"}\n', b''),
 ('read', 'symlink', 'portable'): (2, b'{"error": "reference parent must be a directory: {CASE}/ordinary", "type": "CaptureChanged"}\n', b'')}
R9_WITNESS_PROBE = "\nimport json, os, sys\nfrom pathlib import Path\ntools, fallback, case, action, fault, backend = sys.argv[1:]\nsys.path[:0] = [tools, fallback]\nimport hierarchy_fresh_brief as fresh\nif backend == 'portable': fresh._reference_descriptors = lambda: False\ncase = Path(case); case.mkdir(parents=True, exist_ok=True)\nparent = case/'ordinary'; parent.mkdir()\nnote = parent/'note.md'; note.write_bytes(b'public note')\noperation = fresh._Operation()\nif action == 'read': operation.read(note)\nelse: operation.entries(parent)\nparent.rename(case/'original')\nif fault == 'symlink': parent.symlink_to(case/'original', target_is_directory=True)\nelse: parent.write_text('ordinary file')\ntry:\n    operation.verify()\nexcept (ValueError,OSError) as error:\n    print(json.dumps({'error':str(error),'type':type(error).__name__},sort_keys=True))\n    sys.exit(2)\nprint('{}')\n"

R9_PUBLIC_SEAMS = (
    "check", "exists", "read", "members", "paths", "scope", "disposition", "resolve",
    "shared-disposition", "shared-resolve", "worktree", "scan_workspace", "compose-file",
    "router:--lifecycle", "router:--store", "router:--recipes", "compose:--root",
    "compose:--lifecycle", "compose:--delivery-dir", "verify:--path",
    "loop:--lifecycle", "loop:--store", "loop:--recipes", "loop:--state-dir",
)
R9_PUBLIC_PROBE = r'''
import json, os, sys
from pathlib import Path
tools, fallback, root, seam, backend = sys.argv[1:]
sys.path[:0] = [tools, fallback]
import hierarchy_fresh_brief as fresh
import hierarchy_mailbox as protocol
if backend == 'portable':
    fresh._reference_descriptors = lambda: False
root = Path(root)
target = root / 'ordinary' / 'note.md'
try:
    if seam == 'check':
        if hasattr(fresh, '_reference_check'):
            result = fresh._Operation().path_guard.check(target) is not None
        else:
            protocol.safe_path(target)
            result = os.path.lexists(target)
    elif seam == 'exists': result = fresh._Operation().exists(target)
    elif seam == 'read': result = fresh._Operation().read(target)[0]
    elif seam == 'members': result = fresh._Operation()._members(target)[1]
    elif seam in ('worktree', 'scan_workspace'):
        mailbox = fresh._CapturedMailbox(root / 'mailbox')
        mailbox._stored_message_paths, mailbox._stored_message_refusals = set(), []
        readiness = dict(worktree=str(target if seam == 'worktree' else root),
            scan_workspace=str(target), branch='feature/fixture', base_revision='a'*40,
            lease_ref='refs/aegis/lanes/fixture', lease_oid='b'*40,
            lease_expires_at='2099-01-01T00:00:00Z', owned_paths=['src/**'],
            scan_evidence='fixture scan', hook_evidence='fixture hook', enforcement_tier='advisory')
        mailbox.readiness(readiness, observe=False)
        result = {'refusals': mailbox._stored_message_refusals}
    elif seam in ('paths', 'scope', 'disposition', 'resolve', 'shared-disposition', 'shared-resolve'):
        journal = fresh._Operation().lifecycle(root / 'lifecycle')
        policy, state = journal.load()
        result = dict(requests=sorted(state['requests']), unknown=journal.unknown_rows,
                      refusals=journal.private_refusals)
    else:
        family, flag = ('compose', '--root') if seam == 'compose-file' else seam.split(':')
        value = str(root / 'ordinary') if seam == 'compose-file' else str(target)
        if family == 'router':
            import hierarchy_router as module
            args = ['--lifecycle', str(root/'lifecycle'), '--store', str(root/'store'),
                    'status', '--recipes', str(root/'recipes.json'), '--wait', '0']
        elif family == 'loop':
            import hierarchy_loop as module
            args = ['--lifecycle', str(root/'lifecycle'), '--store', str(root/'store'),
                    '--recipes', str(root/'recipes.json'), '--state-dir', str(root/'state'), 'status']
        elif family == 'compose':
            module = fresh
            args = ['compose', '--root', str(root/'mailbox'), '--initiative', 'a',
                    '--endpoint', 'a/orchestrator', '--lifecycle', str(root/'missing-journal'),
                    '--delivery-dir', str(root/'delivery'), '--as-of', '2030-01-01T00:00:00Z']
        else:
            module = fresh
            args = ['verify', '--path', str(target), '--sha256', '0'*64]
        args[args.index(flag)+1] = value
        sys.exit(module.main(args))
except (ValueError, OSError, TypeError, KeyError) as error:
    print(json.dumps({'error': str(error)}, sort_keys=True))
    sys.exit(2)
print(json.dumps({'result': result}, sort_keys=True))
'''


def r9_public_probe(tmp_path, seam, fault, planned, backend, *, tools=None, _probe=None):
    """Same real fixture/entry point for recorded baseline and history-free tests."""
    from tests.integration.test_hierarchy_router import Loop
    import hierarchy_hosts
    tmp_path.mkdir(parents=True, exist_ok=True)
    ordinary = tmp_path / "ordinary"
    ordinary.mkdir()
    (ordinary / "note.md").write_text("public fixture")
    (tmp_path / "recipes.json").write_text("{}")
    mailbox = tmp_path / "mailbox"
    mailbox.mkdir()
    (mailbox / "manifest.json").write_text(json.dumps({"schema": "aegis.hierarchy-pilot/v1",
        "endpoints": {"a/front-door": {}, "a/orchestrator": {}}, "counterparts": [], "writer_limit": 3}))
    if planned:
        (tmp_path / "host-plan.json").write_text(json.dumps(
            hierarchy_hosts.plan_record("a", "codex-cli", "codex-cli", {}, "0" * 64)))
    if seam.startswith(("router:", "loop:")):
        Loop(tmp_path)
    elif seam in {"paths", "scope", "disposition", "resolve", "shared-disposition", "shared-resolve"}:
        ledger = Ledger(tmp_path)
        bad = request("hostile", paths=[str(ordinary / "note.md")])
        ledger.publish(request("healthy"))
        if seam == "scope":
            change = SmallChange(ledger, bad)
            change.plan["plan"]["path_scopes"] = [bad["paths"]]
            change.register()
        elif seam.endswith(("disposition", "resolve")):
            first = request("first")
            ledger.publish(first)
            kind, extra = seam.split("-")[-1], {}
            if kind == "resolve":
                ledger.event("disposition", status="HOLD", resolution={"kind": "blocked", "owner": "engine/coordinator",
                    "next_decision": "review", "condition": "reviewed", "evidence": ledger.evidence}, **ledger.target(first))
                extra["blocker_sha256"] = alias_fresh.digest(ledger.status()["requests"]["first"]["resolution"])
            evidence = [{"path": bad["paths"][0], "sha256": "0" * 64}] if seam.startswith("shared-") else ledger.evidence
            ledger.event(kind, identifier="fault-event", **({"status": "FINAL"} if kind == "disposition" else extra),
                resolution={"kind": "next", "request": raw_request(bad), "evidence": evidence}, **ledger.target(first))
        else:
            ledger.publish(bad)
    if fault in {"symlink", "link-to-denied", "link-to-io"}:
        public = tmp_path / "public"
        ordinary.rename(public)
        symlink_or_skip(public, ordinary, target_is_directory=True)
        if fault == "link-to-denied":
            public.chmod(0)
    elif fault == "not-directory":
        (ordinary / "note.md").unlink()
        ordinary.rmdir()
        ordinary.write_text("ordinary file")
    elif fault == "missing":
        (ordinary / "note.md").unlink()
        ordinary.rmdir()
    else:
        assert fault == "denied"
        ordinary.chmod(0)
    try:
        result = subprocess.run([sys.executable, "-I", "-B", "-c", _probe or R9_PUBLIC_PROBE,
            str(tools or ROOT / "tools"), str(ROOT / "tools"), str(tmp_path), seam, backend,
            *([fault] if _probe is not None else [])],
            capture_output=True, timeout=30)
    finally:
        if fault == "denied": ordinary.chmod(0o700)
        if fault == "link-to-denied": public.chmod(0o700)
    return result.returncode, result.stdout.replace(os.fsencode(tmp_path), b"{CASE}"), result.stderr.replace(os.fsencode(tmp_path), b"{CASE}")


@lifecycle_only
@pytest.mark.parametrize("seam,fault,planned,backend", tuple(R9_PUBLIC_GOLDENS),
    ids=["%s-%s-%s-%s" % (seam, fault, "planned" if planned else "no-plan", backend)
         for seam, fault, planned, backend in R9_PUBLIC_GOLDENS])
def test_round9_public_path_differential_goldens(tmp_path, seam, fault, planned, backend):
    import hierarchy_fresh_brief as fresh
    if backend == "native" and not fresh._reference_descriptors(): pytest.skip("directory descriptors unavailable")
    if fault == "denied" and os.geteuid() == 0: pytest.skip("mode-000 witness requires an unprivileged runner")
    expected = R9_PUBLIC_GOLDENS[(seam, fault, planned, backend)]
    assert r9_public_probe(tmp_path, seam, fault, planned, backend) == expected


@lifecycle_only
@pytest.mark.parametrize("action,fault,backend", tuple(R9_WITNESS_GOLDENS))
def test_round9_captured_public_parent_failure_bytes(tmp_path, action, fault, backend):
    import hierarchy_fresh_brief as fresh
    if backend == "native":
        if not sys.platform.startswith("linux"): pytest.skip("native errno goldens were recorded on Linux")
        if not fresh._reference_descriptors(): pytest.skip("directory descriptors unavailable")
    if fault == "symlink":
        target, link = tmp_path / "capability-target", tmp_path / "capability-link"
        target.mkdir()
        symlink_or_skip(target, link, target_is_directory=True)
        link.unlink()
        target.rmdir()
    result = subprocess.run([sys.executable, "-I", "-B", "-c", R9_WITNESS_PROBE,
        str(ROOT / "tools"), str(ROOT / "tools"), str(tmp_path), action, fault, backend],
        capture_output=True, timeout=30)
    actual = result.returncode, result.stdout.replace(os.fsencode(tmp_path), b"{CASE}"), result.stderr
    assert actual == R9_WITNESS_GOLDENS[action, fault, backend]


@lifecycle_only
@pytest.mark.parametrize("field", ["paths", "scope"])
@pytest.mark.parametrize("spelling", ["home-suffix", "alias-target", "two-hop"])
def test_round9_private_link_chain_quarantines_only_its_row(tmp_path, monkeypatch, field, spelling):
    from concurrent.futures import ThreadPoolExecutor
    import hierarchy_fresh_brief as fresh
    if not fresh._reference_descriptors() or fresh._symlink_reader() is None:
        pytest.skip("bounded descriptor-relative link reader unavailable")
    home, linked, platform_alias = tmp_path / "owner", tmp_path / "linked", tmp_path / "platform-alias"
    private = home / ".codex"
    private.mkdir(parents=True)
    platform_alias.mkdir()
    linked.mkdir()
    target = linked / ".codex/auth.json" if spelling == "home-suffix" else linked / "auth.json"
    ledger = Ledger(tmp_path)
    bad = request("hostile", paths=[str(target)])
    ledger.publish(request("healthy"))
    if field == "scope":
        change = SmallChange(ledger, bad)
        change.plan["plan"]["path_scopes"] = [bad["paths"]]
        change.register()
    else:
        ledger.publish(bad)
    linked.rmdir()
    if spelling == "two-hop":
        symlink_or_skip(private, tmp_path / "second", target_is_directory=True)
    destination = {"home-suffix": home, "alias-target": platform_alias, "two-hop": tmp_path / "second"}[spelling]
    symlink_or_skip(destination, linked, target_is_directory=True)
    identity, real_os, descriptors, accesses = private.stat(), fresh.os, {}, []
    def actual(path, kwargs):
        return Path(path) if Path(path).is_absolute() else descriptors[kwargs["dir_fd"]] / path
    def observe(kind, value):
        if value == private or private in value.parents:
            accesses.append({"path": str(value), "kind": kind, "operation": id(fresh._PATH_GUARD.get())})
        assert not (private in value.parents or platform_alias in value.parents), (kind, value)
        if kind == "open": assert value not in {private, platform_alias}, value
    def stated(path, *args, **kwargs):
        value = actual(path, kwargs)
        observe("stat", value)
        if spelling == "alias-target" and value == platform_alias:
            return identity
        return real_os.stat(path, *args, **kwargs)
    def opened(path, *args, **kwargs):
        value = actual(path, kwargs)
        observe("open", value)
        descriptor = real_os.open(path, *args, **kwargs)
        descriptors[descriptor] = value
        return descriptor
    def closed(descriptor):
        descriptors.pop(descriptor, None)
        return real_os.close(descriptor)
    monkeypatch.setattr("hierarchy_router._owner_home", lambda: home)
    monkeypatch.setattr("hierarchy_router._home_declarations", lambda: (("ROUND9_HOME", ".codex"),))
    monkeypatch.setattr("hierarchy_router.os", SimpleNamespace(**{**vars(real_os), "stat": stated,
        "environ": {**os.environ, "ROUND9_HOME": str(private)}}))
    monkeypatch.setattr("hierarchy_fresh_brief.os", SimpleNamespace(**{**vars(real_os),
        "stat": stated, "open": opened, "close": closed}))
    owners = []
    def probe():
        operation = fresh._Operation()
        owners.append(operation)
        journal = operation.lifecycle(ledger.path)
        _policy, state = journal.load()
        assert set(state["requests"]) == {"hostile", "healthy"}
        for _ in range(2):
            assert journal.refusals_for("hostile", consume=True)
            assert journal.refusals_for("healthy") == []
            operation.verify()
    probe()
    with ThreadPoolExecutor(max_workers=2) as pool:
        for future in (pool.submit(probe), pool.submit(probe)): future.result(timeout=30)
    from tests.integration.test_hierarchy_small_change_dispatch import assert_private_root_probes
    assert_private_root_probes([private], accesses)
    assert not descriptors


# Exact ec27eebf records; only the case directory prefix is normalized.
R10_PUBLIC_GOLDENS = {('check', 'link-to-denied', False, 'native'): (2,
                                                b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                b'd\'"}\n',
                                                b''),
 ('check', 'link-to-denied', False, 'portable'): (2,
                                                  b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                  b'd\'"}\n',
                                                  b''),
 ('check', 'link-to-denied', True, 'native'): (2,
                                               b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}'
                                               b'\n',
                                               b''),
 ('check', 'link-to-denied', True, 'portable'): (2,
                                                 b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                 b'd\'"}\n',
                                                 b''),
 ('check', 'link-to-io', False, 'native'): (2,
                                            b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}\n',
                                            b''),
 ('check', 'link-to-io', False, 'portable'): (2,
                                              b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}'
                                              b'\n',
                                              b''),
 ('check', 'link-to-io', True, 'native'): (2,
                                           b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}\n',
                                           b''),
 ('check', 'link-to-io', True, 'portable'): (2,
                                             b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}'
                                             b'\n',
                                             b''),
 ('compose-file', 'link-to-denied', False, 'native'): (2,
                                                       b'{"error": "symlink paths are not supported: {CASE}/ordinary"'
                                                       b'}\n',
                                                       b''),
 ('compose-file', 'link-to-denied', True, 'native'): (2,
                                                      b'{"error": "symlink paths are not supported: {CASE}/ordinary"'
                                                      b'}\n',
                                                      b''),
 ('compose-file', 'link-to-io', False, 'native'): (2,
                                                   b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                                   b''),
 ('compose-file', 'link-to-io', True, 'native'): (2,
                                                  b'{"error": "symlink paths are not supported: {CASE}/ordinary"}\n',
                                                  b''),
 ('compose:--delivery-dir', 'link-to-denied', False, 'native'): (2,
                                                                 b'{"error": "[Errno 13] Permission denied: \'{CASE}'
                                                                 b'/ordinary/note.md\'"}\n',
                                                                 b''),
 ('compose:--delivery-dir', 'link-to-denied', True, 'native'): (2,
                                                                b'{"error": "[Errno 13] Permission denied: \'{CASE}/ord'
                                                                b'inary/note.md\'"}\n',
                                                                b''),
 ('compose:--delivery-dir', 'link-to-io', False, 'native'): (2,
                                                             b'{"error": "[Errno 5] Input/output error: \'{CASE}/ord'
                                                             b'inary/note.md\'"}\n',
                                                             b''),
 ('compose:--delivery-dir', 'link-to-io', True, 'native'): (2,
                                                            b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinar'
                                                            b'y/note.md\'"}\n',
                                                            b''),
 ('compose:--lifecycle', 'link-to-denied', False, 'native'): (2,
                                                              b'{"error": "[Errno 13] Permission denied: \'{CASE}/ord'
                                                              b'inary/note.md\'"}\n',
                                                              b''),
 ('compose:--lifecycle', 'link-to-denied', True, 'native'): (2,
                                                             b'{"error": "[Errno 13] Permission denied: \'{CASE}/ord'
                                                             b'inary/note.md\'"}\n',
                                                             b''),
 ('compose:--lifecycle', 'link-to-io', False, 'native'): (2,
                                                          b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinar'
                                                          b'y/note.md\'"}\n',
                                                          b''),
 ('compose:--lifecycle', 'link-to-io', True, 'native'): (2,
                                                         b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinar'
                                                         b'y/note.md\'"}\n',
                                                         b''),
 ('compose:--root', 'link-to-denied', False, 'native'): (2,
                                                         b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinar'
                                                         b'y/note.md\'"}\n',
                                                         b''),
 ('compose:--root', 'link-to-denied', True, 'native'): (2,
                                                        b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/no'
                                                        b'te.md\'"}\n',
                                                        b''),
 ('compose:--root', 'link-to-io', False, 'native'): (2,
                                                     b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/no'
                                                     b'te.md\'"}\n',
                                                     b''),
 ('compose:--root', 'link-to-io', True, 'native'): (2,
                                                    b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.m'
                                                    b'd\'"}\n',
                                                    b''),
 ('disposition', 'link-to-denied', False, 'native'): (2,
                                                      b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/no'
                                                      b'te.md\'"}\n',
                                                      b''),
 ('disposition', 'link-to-denied', False, 'portable'): (2,
                                                        b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/no'
                                                        b'te.md\'"}\n',
                                                        b''),
 ('disposition', 'link-to-denied', True, 'native'): (2,
                                                     b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/no'
                                                     b'te.md\'"}\n',
                                                     b''),
 ('disposition', 'link-to-denied', True, 'portable'): (2,
                                                       b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/no'
                                                       b'te.md\'"}\n',
                                                       b''),
 ('disposition', 'link-to-io', False, 'native'): (2,
                                                  b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.m'
                                                  b'd\'"}\n',
                                                  b''),
 ('disposition', 'link-to-io', False, 'portable'): (2,
                                                    b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.m'
                                                    b'd\'"}\n',
                                                    b''),
 ('disposition', 'link-to-io', True, 'native'): (2,
                                                 b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.m'
                                                 b'd\'"}\n',
                                                 b''),
 ('disposition', 'link-to-io', True, 'portable'): (2,
                                                   b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.m'
                                                   b'd\'"}\n',
                                                   b''),
 ('exists', 'link-to-denied', False, 'native'): (2,
                                                 b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                 b'd\'"}\n',
                                                 b''),
 ('exists', 'link-to-denied', False, 'portable'): (2,
                                                   b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                   b'd\'"}\n',
                                                   b''),
 ('exists', 'link-to-denied', True, 'native'): (2,
                                                b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                b'd\'"}\n',
                                                b''),
 ('exists', 'link-to-denied', True, 'portable'): (2,
                                                  b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                  b'd\'"}\n',
                                                  b''),
 ('exists', 'link-to-io', False, 'native'): (2,
                                             b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}'
                                             b'\n',
                                             b''),
 ('exists', 'link-to-io', False, 'portable'): (2,
                                               b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}'
                                               b'\n',
                                               b''),
 ('exists', 'link-to-io', True, 'native'): (2,
                                            b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}\n',
                                            b''),
 ('exists', 'link-to-io', True, 'portable'): (2,
                                              b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}'
                                              b'\n',
                                              b''),
 ('loop:--lifecycle', 'link-to-denied', False, 'native'): (2,
                                                           b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinar'
                                                           b'y/note.md\'"}\n',
                                                           b''),
 ('loop:--lifecycle', 'link-to-denied', True, 'native'): (2,
                                                          b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinar'
                                                          b'y/note.md\'"}\n',
                                                          b''),
 ('loop:--lifecycle', 'link-to-io', False, 'native'): (2,
                                                       b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/no'
                                                       b'te.md\'"}\n',
                                                       b''),
 ('loop:--lifecycle', 'link-to-io', True, 'native'): (2,
                                                      b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/no'
                                                      b'te.md\'"}\n',
                                                      b''),
 ('loop:--recipes', 'link-to-denied', False, 'native'): (2,
                                                         b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinar'
                                                         b'y/note.md\'"}\n',
                                                         b''),
 ('loop:--recipes', 'link-to-denied', True, 'native'): (2,
                                                        b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/no'
                                                        b'te.md\'"}\n',
                                                        b''),
 ('loop:--recipes', 'link-to-io', False, 'native'): (2,
                                                     b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/no'
                                                     b'te.md\'"}\n',
                                                     b''),
 ('loop:--recipes', 'link-to-io', True, 'native'): (2,
                                                    b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.m'
                                                    b'd\'"}\n',
                                                    b''),
 ('loop:--state-dir', 'link-to-denied', False, 'native'): (2,
                                                           b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinar'
                                                           b'y/note.md\'"}\n',
                                                           b''),
 ('loop:--state-dir', 'link-to-denied', True, 'native'): (2,
                                                          b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinar'
                                                          b'y/note.md\'"}\n',
                                                          b''),
 ('loop:--state-dir', 'link-to-io', False, 'native'): (2,
                                                       b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/no'
                                                       b'te.md\'"}\n',
                                                       b''),
 ('loop:--state-dir', 'link-to-io', True, 'native'): (2,
                                                      b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/no'
                                                      b'te.md\'"}\n',
                                                      b''),
 ('loop:--store', 'link-to-denied', False, 'native'): (2,
                                                       b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/no'
                                                       b'te.md\'"}\n',
                                                       b''),
 ('loop:--store', 'link-to-denied', True, 'native'): (2,
                                                      b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/no'
                                                      b'te.md\'"}\n',
                                                      b''),
 ('loop:--store', 'link-to-io', False, 'native'): (2,
                                                   b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.m'
                                                   b'd\'"}\n',
                                                   b''),
 ('loop:--store', 'link-to-io', True, 'native'): (2,
                                                  b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.m'
                                                  b'd\'"}\n',
                                                  b''),
 ('members', 'link-to-denied', False, 'native'): (2,
                                                  b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                  b'd\'"}\n',
                                                  b''),
 ('members', 'link-to-denied', False, 'portable'): (2,
                                                    b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                    b'd\'"}\n',
                                                    b''),
 ('members', 'link-to-denied', True, 'native'): (2,
                                                 b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                 b'd\'"}\n',
                                                 b''),
 ('members', 'link-to-denied', True, 'portable'): (2,
                                                   b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                   b'd\'"}\n',
                                                   b''),
 ('members', 'link-to-io', False, 'native'): (2,
                                              b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}'
                                              b'\n',
                                              b''),
 ('members', 'link-to-io', False, 'portable'): (2,
                                                b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.m'
                                                b'd\'"}\n',
                                                b''),
 ('members', 'link-to-io', True, 'native'): (2,
                                             b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}'
                                             b'\n',
                                             b''),
 ('members', 'link-to-io', True, 'portable'): (2,
                                               b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}'
                                               b'\n',
                                               b''),
 ('paths', 'link-to-denied', False, 'native'): (2,
                                                b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                b'd\'"}\n',
                                                b''),
 ('paths', 'link-to-denied', False, 'portable'): (2,
                                                  b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                  b'd\'"}\n',
                                                  b''),
 ('paths', 'link-to-denied', True, 'native'): (2,
                                               b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}'
                                               b'\n',
                                               b''),
 ('paths', 'link-to-denied', True, 'portable'): (2,
                                                 b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                 b'd\'"}\n',
                                                 b''),
 ('paths', 'link-to-io', False, 'native'): (2,
                                            b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}\n',
                                            b''),
 ('paths', 'link-to-io', False, 'portable'): (2,
                                              b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}'
                                              b'\n',
                                              b''),
 ('paths', 'link-to-io', True, 'native'): (2,
                                           b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}\n',
                                           b''),
 ('paths', 'link-to-io', True, 'portable'): (2,
                                             b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}'
                                             b'\n',
                                             b''),
 ('read', 'link-to-denied', False, 'native'): (2,
                                               b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}'
                                               b'\n',
                                               b''),
 ('read', 'link-to-denied', False, 'portable'): (2,
                                                 b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                 b'd\'"}\n',
                                                 b''),
 ('read', 'link-to-denied', True, 'native'): (2,
                                              b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}'
                                              b'\n',
                                              b''),
 ('read', 'link-to-denied', True, 'portable'): (2,
                                                b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                b'd\'"}\n',
                                                b''),
 ('read', 'link-to-io', False, 'native'): (2,
                                           b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}\n',
                                           b''),
 ('read', 'link-to-io', False, 'portable'): (2,
                                             b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}'
                                             b'\n',
                                             b''),
 ('read', 'link-to-io', True, 'native'): (2,
                                          b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}\n',
                                          b''),
 ('read', 'link-to-io', True, 'portable'): (2,
                                            b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}\n',
                                            b''),
 ('resolve', 'link-to-denied', False, 'native'): (2,
                                                  b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                  b'd\'"}\n',
                                                  b''),
 ('resolve', 'link-to-denied', False, 'portable'): (2,
                                                    b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                    b'd\'"}\n',
                                                    b''),
 ('resolve', 'link-to-denied', True, 'native'): (2,
                                                 b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                 b'd\'"}\n',
                                                 b''),
 ('resolve', 'link-to-denied', True, 'portable'): (2,
                                                   b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                   b'd\'"}\n',
                                                   b''),
 ('resolve', 'link-to-io', False, 'native'): (2,
                                              b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}'
                                              b'\n',
                                              b''),
 ('resolve', 'link-to-io', False, 'portable'): (2,
                                                b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.m'
                                                b'd\'"}\n',
                                                b''),
 ('resolve', 'link-to-io', True, 'native'): (2,
                                             b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}'
                                             b'\n',
                                             b''),
 ('resolve', 'link-to-io', True, 'portable'): (2,
                                               b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}'
                                               b'\n',
                                               b''),
 ('router:--lifecycle', 'link-to-denied', False, 'native'): (2,
                                                             b'{"error":"[Errno 13] Permission denied: \'{CASE}/ordi'
                                                             b'nary/note.md\'","execution_enabled":false,"source":"a'
                                                             b'rguments","state":"hold"}\n',
                                                             b''),
 ('router:--lifecycle', 'link-to-denied', True, 'native'): (2,
                                                            b'{"error":"[Errno 13] Permission denied: \'{CASE}/ordinary'
                                                            b'/note.md\'","execution_enabled":false,"source":"arguments'
                                                            b'","state":"hold"}\n',
                                                            b''),
 ('router:--lifecycle', 'link-to-io', False, 'native'): (2,
                                                         b'{"error":"[Errno 5] Input/output error: \'{CASE}/ordinary'
                                                         b'/note.md\'","execution_enabled":false,"source":"arguments'
                                                         b'","state":"hold"}\n',
                                                         b''),
 ('router:--lifecycle', 'link-to-io', True, 'native'): (2,
                                                        b'{"error":"[Errno 5] Input/output error: \'{CASE}/ordinary/not'
                                                        b'e.md\'","execution_enabled":false,"source":"arguments","state'
                                                        b'":"hold"}\n',
                                                        b''),
 ('router:--recipes', 'link-to-denied', False, 'native'): (2,
                                                           b'{"error":"[Errno 13] Permission denied: \'{CASE}/ordinary'
                                                           b'/note.md\'","execution_enabled":false,"source":"arguments'
                                                           b'","state":"hold"}\n',
                                                           b''),
 ('router:--recipes', 'link-to-denied', True, 'native'): (2,
                                                          b'{"error":"[Errno 13] Permission denied: \'{CASE}/ordinary'
                                                          b'/note.md\'","execution_enabled":false,"source":"arguments'
                                                          b'","state":"hold"}\n',
                                                          b''),
 ('router:--recipes', 'link-to-io', False, 'native'): (2,
                                                       b'{"error":"[Errno 5] Input/output error: \'{CASE}/ordinary/not'
                                                       b'e.md\'","execution_enabled":false,"source":"arguments","state'
                                                       b'":"hold"}\n',
                                                       b''),
 ('router:--recipes', 'link-to-io', True, 'native'): (2,
                                                      b'{"error":"[Errno 5] Input/output error: \'{CASE}/ordinary/not'
                                                      b'e.md\'","execution_enabled":false,"source":"arguments","state'
                                                      b'":"hold"}\n',
                                                      b''),
 ('router:--store', 'link-to-denied', False, 'native'): (2,
                                                         b'{"error":"[Errno 13] Permission denied: \'{CASE}/ordinary'
                                                         b'/note.md\'","execution_enabled":false,"source":"arguments'
                                                         b'","state":"hold"}\n',
                                                         b''),
 ('router:--store', 'link-to-denied', True, 'native'): (2,
                                                        b'{"error":"[Errno 13] Permission denied: \'{CASE}/ordinary/not'
                                                        b'e.md\'","execution_enabled":false,"source":"arguments","state'
                                                        b'":"hold"}\n',
                                                        b''),
 ('router:--store', 'link-to-io', False, 'native'): (2,
                                                     b'{"error":"[Errno 5] Input/output error: \'{CASE}/ordinary/not'
                                                     b'e.md\'","execution_enabled":false,"source":"arguments","state'
                                                     b'":"hold"}\n',
                                                     b''),
 ('router:--store', 'link-to-io', True, 'native'): (2,
                                                    b'{"error":"[Errno 5] Input/output error: \'{CASE}/ordinary/note.md'
                                                    b'\'","execution_enabled":false,"source":"arguments","state":"hold"'
                                                    b'}\n',
                                                    b''),
 ('scan_workspace', 'link-to-denied', False, 'native'): (2,
                                                         b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinar'
                                                         b'y/note.md\'"}\n',
                                                         b''),
 ('scan_workspace', 'link-to-denied', False, 'portable'): (2,
                                                           b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinar'
                                                           b'y/note.md\'"}\n',
                                                           b''),
 ('scan_workspace', 'link-to-denied', True, 'native'): (2,
                                                        b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/no'
                                                        b'te.md\'"}\n',
                                                        b''),
 ('scan_workspace', 'link-to-denied', True, 'portable'): (2,
                                                          b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinar'
                                                          b'y/note.md\'"}\n',
                                                          b''),
 ('scan_workspace', 'link-to-io', False, 'native'): (2,
                                                     b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/no'
                                                     b'te.md\'"}\n',
                                                     b''),
 ('scan_workspace', 'link-to-io', False, 'portable'): (2,
                                                       b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/no'
                                                       b'te.md\'"}\n',
                                                       b''),
 ('scan_workspace', 'link-to-io', True, 'native'): (2,
                                                    b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.m'
                                                    b'd\'"}\n',
                                                    b''),
 ('scan_workspace', 'link-to-io', True, 'portable'): (2,
                                                      b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/no'
                                                      b'te.md\'"}\n',
                                                      b''),
 ('scope', 'link-to-denied', False, 'native'): (2,
                                                b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                b'd\'"}\n',
                                                b''),
 ('scope', 'link-to-denied', False, 'portable'): (2,
                                                  b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                  b'd\'"}\n',
                                                  b''),
 ('scope', 'link-to-denied', True, 'native'): (2,
                                               b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.md\'"}'
                                               b'\n',
                                               b''),
 ('scope', 'link-to-denied', True, 'portable'): (2,
                                                 b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                 b'd\'"}\n',
                                                 b''),
 ('scope', 'link-to-io', False, 'native'): (2,
                                            b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}\n',
                                            b''),
 ('scope', 'link-to-io', False, 'portable'): (2,
                                              b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}'
                                              b'\n',
                                              b''),
 ('scope', 'link-to-io', True, 'native'): (2,
                                           b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}\n',
                                           b''),
 ('scope', 'link-to-io', True, 'portable'): (2,
                                             b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}'
                                             b'\n',
                                             b''),
 ('shared-disposition', 'link-to-denied', False, 'native'): (0,
                                                             b'{"result": {"refusals": {}, "requests": ["first", "healt'
                                                             b'hy", "hostile"], "unknown": {}}}\n',
                                                             b''),
 ('shared-disposition', 'link-to-denied', False, 'portable'): (0,
                                                               b'{"result": {"refusals": {}, "requests": ["first", "h'
                                                               b'ealthy", "hostile"], "unknown": {}}}\n',
                                                               b''),
 ('shared-disposition', 'link-to-denied', True, 'native'): (0,
                                                            b'{"result": {"refusals": {}, "requests": ["first", "healt'
                                                            b'hy", "hostile"], "unknown": {}}}\n',
                                                            b''),
 ('shared-disposition', 'link-to-denied', True, 'portable'): (0,
                                                              b'{"result": {"refusals": {}, "requests": ["first", "h'
                                                              b'ealthy", "hostile"], "unknown": {}}}\n',
                                                              b''),
 ('shared-disposition', 'link-to-io', False, 'native'): (0,
                                                         b'{"result": {"refusals": {}, "requests": ["first", "healthy",'
                                                         b' "hostile"], "unknown": {}}}\n',
                                                         b''),
 ('shared-disposition', 'link-to-io', False, 'portable'): (0,
                                                           b'{"result": {"refusals": {}, "requests": ["first", "healt'
                                                           b'hy", "hostile"], "unknown": {}}}\n',
                                                           b''),
 ('shared-disposition', 'link-to-io', True, 'native'): (0,
                                                        b'{"result": {"refusals": {}, "requests": ["first", "healthy",'
                                                        b' "hostile"], "unknown": {}}}\n',
                                                        b''),
 ('shared-disposition', 'link-to-io', True, 'portable'): (0,
                                                          b'{"result": {"refusals": {}, "requests": ["first", "healt'
                                                          b'hy", "hostile"], "unknown": {}}}\n',
                                                          b''),
 ('shared-resolve', 'link-to-denied', False, 'native'): (0,
                                                         b'{"result": {"refusals": {}, "requests": ["first", "healthy",'
                                                         b' "hostile"], "unknown": {}}}\n',
                                                         b''),
 ('shared-resolve', 'link-to-denied', False, 'portable'): (0,
                                                           b'{"result": {"refusals": {}, "requests": ["first", "healt'
                                                           b'hy", "hostile"], "unknown": {}}}\n',
                                                           b''),
 ('shared-resolve', 'link-to-denied', True, 'native'): (0,
                                                        b'{"result": {"refusals": {}, "requests": ["first", "healthy",'
                                                        b' "hostile"], "unknown": {}}}\n',
                                                        b''),
 ('shared-resolve', 'link-to-denied', True, 'portable'): (0,
                                                          b'{"result": {"refusals": {}, "requests": ["first", "healt'
                                                          b'hy", "hostile"], "unknown": {}}}\n',
                                                          b''),
 ('shared-resolve', 'link-to-io', False, 'native'): (0,
                                                     b'{"result": {"refusals": {}, "requests": ["first", "healthy", "ho'
                                                     b'stile"], "unknown": {}}}\n',
                                                     b''),
 ('shared-resolve', 'link-to-io', False, 'portable'): (0,
                                                       b'{"result": {"refusals": {}, "requests": ["first", "healthy",'
                                                       b' "hostile"], "unknown": {}}}\n',
                                                       b''),
 ('shared-resolve', 'link-to-io', True, 'native'): (0,
                                                    b'{"result": {"refusals": {}, "requests": ["first", "healthy", "ho'
                                                    b'stile"], "unknown": {}}}\n',
                                                    b''),
 ('shared-resolve', 'link-to-io', True, 'portable'): (0,
                                                      b'{"result": {"refusals": {}, "requests": ["first", "healthy",'
                                                      b' "hostile"], "unknown": {}}}\n',
                                                      b''),
 ('verify:--path', 'link-to-denied', False, 'native'): (2,
                                                        b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/no'
                                                        b'te.md\'"}\n',
                                                        b''),
 ('verify:--path', 'link-to-denied', True, 'native'): (2,
                                                       b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/no'
                                                       b'te.md\'"}\n',
                                                       b''),
 ('verify:--path', 'link-to-io', False, 'native'): (2,
                                                    b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.m'
                                                    b'd\'"}\n',
                                                    b''),
 ('verify:--path', 'link-to-io', True, 'native'): (2,
                                                   b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.m'
                                                   b'd\'"}\n',
                                                   b''),
 ('worktree', 'link-to-denied', False, 'native'): (2,
                                                   b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                   b'd\'"}\n',
                                                   b''),
 ('worktree', 'link-to-denied', False, 'portable'): (2,
                                                     b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/no'
                                                     b'te.md\'"}\n',
                                                     b''),
 ('worktree', 'link-to-denied', True, 'native'): (2,
                                                  b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                  b'd\'"}\n',
                                                  b''),
 ('worktree', 'link-to-denied', True, 'portable'): (2,
                                                    b'{"error": "[Errno 13] Permission denied: \'{CASE}/ordinary/note.m'
                                                    b'd\'"}\n',
                                                    b''),
 ('worktree', 'link-to-io', False, 'native'): (2,
                                               b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}'
                                               b'\n',
                                               b''),
 ('worktree', 'link-to-io', False, 'portable'): (2,
                                                 b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.m'
                                                 b'd\'"}\n',
                                                 b''),
 ('worktree', 'link-to-io', True, 'native'): (2,
                                              b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.md\'"}'
                                              b'\n',
                                              b''),
 ('worktree', 'link-to-io', True, 'portable'): (2,
                                                b'{"error": "[Errno 5] Input/output error: \'{CASE}/ordinary/note.m'
                                                b'd\'"}\n',
                                                b'')}


@lifecycle_only
@pytest.mark.parametrize("seam,fault,planned,backend", tuple(R10_PUBLIC_GOLDENS),
    ids=["%s-%s-%s-%s" % (seam, fault, "planned" if planned else "no-plan", backend)
         for seam, fault, planned, backend in R10_PUBLIC_GOLDENS])
def test_round10_public_target_failure_matches_baseline(tmp_path, seam, fault, planned, backend):
    import hierarchy_fresh_brief as fresh
    if backend == "native" and not fresh._reference_descriptors():
        pytest.skip("directory descriptors unavailable")
    if fault == "link-to-denied" and os.geteuid() == 0:
        pytest.skip("mode-000 witness requires an unprivileged runner")
    expected = R10_PUBLIC_GOLDENS[(seam, fault, planned, backend)]
    assert r9_public_probe(tmp_path, seam, fault, planned, backend, _probe=R10_PUBLIC_PROBE) == expected



@lifecycle_only
@pytest.mark.parametrize("field", ["paths", "scope"])
@pytest.mark.parametrize("pivot_kind", ["public-link", "private-link", "missing", "not-directory"])
def test_round9_link_parent_traversal_resolves_before_normalizing(tmp_path, monkeypatch, field, pivot_kind):
    import hierarchy_fresh_brief as fresh
    if not fresh._reference_descriptors() or fresh._symlink_reader() is None:
        pytest.skip("bounded descriptor-relative link reader unavailable")
    home, public, linked = tmp_path / "owner", tmp_path / "public", tmp_path / "linked"
    for directory in (home / ".codex", home / "sub", public / ".codex", public / "sub", linked):
        directory.mkdir(parents=True, exist_ok=True)
    ledger = Ledger(tmp_path)
    ledger.publish(request("healthy"))
    hostile = request("hostile", paths=[str(linked / "auth.json")])
    if field == "scope":
        change = SmallChange(ledger, hostile)
        change.plan["plan"]["path_scopes"] = [hostile["paths"]]
        change.register()
    else:
        ledger.publish(hostile)
    pivot = home / "pivot"
    if pivot_kind.endswith("-link"):
        symlink_or_skip((public if pivot_kind == "public-link" else home) / "sub", pivot,
                        target_is_directory=True)
    elif pivot_kind == "not-directory":
        pivot.write_text("ordinary file")
    linked.rmdir()
    symlink_or_skip(str(pivot) + "/../.codex", linked, target_is_directory=True)
    monkeypatch.setattr("hierarchy_router._owner_home", lambda: home)
    operation = fresh._Operation()
    journal = operation.lifecycle(ledger.path)
    # Round 14 also quarantines a missing/non-directory traversal proof.
    if pivot_kind in {"private-link", "missing", "not-directory"}:
        _policy, state = journal.load()
        assert set(state["requests"]) == {"healthy", "hostile"}
        assert journal.refusals_for("hostile")
        assert journal.refusals_for("hostile", consume=True)
        assert journal.refusals_for("healthy") == []
        operation.verify()
        assert not operation.failed_validation
    else:
        expected = "symlink paths are not supported: " + str(linked)
        for attempt in (journal.load, operation.verify):
            with pytest.raises(alias_router.SymlinkPathError) as caught:
                attempt()
            assert str(caught.value).encode() == expected.encode()
        assert operation.failed_validation


@lifecycle_only
@pytest.mark.parametrize("destination_kind", ["public", "private"])
def test_round9_optional_evidence_parent_replacement_uses_owning_guard(tmp_path, monkeypatch, destination_kind):
    import hierarchy_fresh_brief as fresh
    if not fresh._reference_descriptors() or fresh._symlink_reader() is None:
        pytest.skip("bounded descriptor-relative link reader unavailable")
    home, linked, held, public = (tmp_path / name for name in ("owner", "linked", "held", "public"))
    private = home / ".codex"
    for directory in (private, linked, public):
        directory.mkdir(parents=True)
        (directory / "note.md").write_bytes(b"fixture evidence\n")
    capability = tmp_path / "symlink-capability"
    symlink_or_skip(public, capability, target_is_directory=True)
    capability.unlink()
    reference = ref(linked / "note.md")
    destination = private if destination_kind == "private" else public
    monkeypatch.setattr("hierarchy_router._owner_home", lambda: home)
    real_os, descriptors, observations = fresh.os, {}, []
    def actual(path, kwargs):
        return Path(path) if Path(path).is_absolute() else descriptors[kwargs["dir_fd"]] / path
    def stated(path, *args, **kwargs):
        value = actual(path, kwargs)
        assert private not in value.parents, value
        if value == linked:
            observations.append(value)
            if len(observations) == 2:
                linked.rename(held)
                linked.symlink_to(destination, target_is_directory=True)
        return real_os.stat(path, *args, **kwargs)
    def opened(path, *args, **kwargs):
        value = actual(path, kwargs)
        assert value != private and private not in value.parents, value
        descriptor = real_os.open(path, *args, **kwargs)
        descriptors[descriptor] = value
        return descriptor
    def closed(descriptor):
        descriptors.pop(descriptor, None)
        return real_os.close(descriptor)
    monkeypatch.setattr("hierarchy_fresh_brief.os", SimpleNamespace(**{**vars(real_os),
        "stat": stated, "open": opened, "close": closed}))
    brief = fresh.Brief()
    brief.evidence(reference, reference)
    assert len(observations) >= 2
    assert [row["kind"] for row in brief.sections["Evidence references"]] == ["unverified_evidence"]
    if destination_kind == "private":
        with pytest.raises(alias_router.PrivatePathError):
            brief.operation.verify()
        assert brief.operation.failed_validation
    else:
        brief.operation.verify()
        assert not brief.operation.failed_validation
    assert not descriptors


@lifecycle_only
@pytest.mark.parametrize("fault", ["policy", "identity"])
@pytest.mark.parametrize("site", ["verify", "prove", "evidence", "unread", "brief-preflight", "brief-content",
    "messages", "store", "case-insensitive", "case-default"])
def test_round9_global_policy_errors_survive_every_boundary(tmp_path, pilot, monkeypatch, fault, site):
    from concurrent.futures import ThreadPoolExecutor
    import hierarchy_fresh_brief as fresh
    import hierarchy_router as router
    import hierarchy_small_change_dispatch as dispatch
    from tests.integration.test_hierarchy_workspace import Workspace
    if not fresh._reference_descriptors(): pytest.skip("directory descriptors unavailable")
    root, _brief = pilot
    note = tmp_path / "fatal.md"
    note.write_bytes(b"fixture evidence\n")
    reference = {"path": str(note), "sha256": hashlib.sha256(note.read_bytes()).hexdigest()}
    operation = fresh._Operation()
    mailbox = fresh._CapturedMailbox(root, _operation=operation)
    if site == "verify": operation.read(note)
    if site == "messages": invoke(root, "publish", message(identifier="fatal-message"))
    if site == "store":
        workspace = Workspace(tmp_path)
        workspace.run("init", {"writer_limit": 3, "heavy_limit": 1})
        store = dispatch._CapturedStore(workspace.store, operation)
    brief = fresh.Brief(_operation=operation)
    error = (router.CapturedPolicyError("host-home configuration changed during capture") if fault == "policy"
             else ValueError("cannot determine private directory identity"))
    guard, original_current, injected, enabled = operation.path_guard, router._CapturedPathGuard.current, [], [True]
    def current(self):
        frame, frames = sys._getframe(1), []
        while frame is not None:
            frames.append((frame.f_code.co_name, frame.f_code.co_filename))
            frame = frame.f_back
        names = {name for name, _filename in frames}
        selected = {
            "verify": "verify" in names and "_reference_parent" in names,
            "evidence": "evidence" in names and "read" in names,
            "unread": "_unread_attachment" in names and "read" in names and "brief" not in names,
            "brief-preflight": "brief" in names and "read" not in names,
            "brief-content": "brief" in names and "read" in names,
            "messages": "declared_path" in names,
            "store": "_private_paths" in names and any(name == "load" and filename.endswith("hierarchy_small_change_dispatch.py")
                                                           for name, filename in frames),
            "case-insensitive": "_case_insensitive" in names and "_reference_parent" in names,
            "case-default": "_case_insensitive" in names and "_reference_parent" in names,
            "prove": "_case_insensitive" in names and "_reference_parent" in names,
        }[site]
        if self is guard and enabled[0] and selected:
            injected.append(site)
            if fault == "identity": guard._identity_error = error
            raise error
        return original_current(self)
    # The owned host-policy boundary, never pytest's global OS namespace.
    monkeypatch.setattr("hierarchy_router._CapturedPathGuard.current", current)
    def run():
        if site == "verify": operation.verify()
        elif site == "prove": operation.prove(lambda: router._case_insensitive(tmp_path, (), _guard=guard))
        elif site == "evidence": brief.evidence(reference, reference)
        elif site == "unread": fresh._unread_attachment(mailbox, reference)
        elif site.startswith("brief-"): mailbox.brief(reference)
        elif site == "messages": mailbox.messages()
        elif site == "store": store.load()
        elif site == "case-default":
            with operation.capture():
                router._case_insensitive(tmp_path, ())
        else:
            with operation.capture():
                router._case_insensitive(tmp_path, (), _guard=guard)
    with pytest.raises(type(error)) as caught:
        run()
    assert injected, site
    assert caught.value is error
    assert operation.failed_validation
    assert not brief.sections["Evidence references"]
    enabled[0], guard._identity_error = False, None
    def retry():
        with pytest.raises(type(error)) as caught:
            operation.verify()
        assert caught.value is error
    retry()
    with ThreadPoolExecutor(max_workers=2) as pool:
        for future in (pool.submit(retry), pool.submit(retry)): future.result(timeout=30)
    healthy = fresh._Operation()
    assert healthy.read(note)[0] == reference
    healthy.verify()


@lifecycle_only
@pytest.mark.parametrize("shape", ["cycle", "hop-limit"])
def test_round10_unproved_link_chains_are_bounded_and_quarantined(tmp_path, monkeypatch, shape):
    import hierarchy_fresh_brief as fresh
    if not fresh._reference_descriptors(): pytest.skip("directory descriptors unavailable")
    native_read = fresh._symlink_reader()
    if native_read is None: pytest.skip("bounded readlinkat unavailable")
    linked, private = tmp_path / "linked", tmp_path / "private"
    linked.mkdir()
    private.mkdir()
    ledger = Ledger(tmp_path)
    ledger.publish(request("healthy"))
    ledger.publish(request("hostile", paths=[str(linked / "auth.json")]))
    linked.rmdir()
    if shape == "cycle":
        symlink_or_skip(tmp_path / "second", linked, target_is_directory=True)
        symlink_or_skip(linked, tmp_path / "second", target_is_directory=True)
    else:
        for index in range(41):
            path = linked if index == 0 else tmp_path / ("hop-%d" % index)
            target = private if index == 40 else tmp_path / ("hop-%d" % (index + 1))
            symlink_or_skip(target, path, target_is_directory=True)
    real_os, live, sizes = fresh.os, set(), []
    def opened(path, *args, **kwargs):
        assert Path(path).name != private.name, "private target opened"
        descriptor = real_os.open(path, *args, **kwargs)
        live.add(descriptor)
        return descriptor
    def closed(descriptor):
        live.remove(descriptor)
        return real_os.close(descriptor)
    def read(directory, name, size):
        sizes.append(size)
        assert len(sizes) <= 40
        assert 0 < size <= 4096
        return native_read(directory, name, size)
    monkeypatch.setattr("hierarchy_router._owner_home", lambda: tmp_path / "owner")
    monkeypatch.setattr("hierarchy_router._home_declarations", lambda: (("ROUND9_HOME", ".codex"),))
    monkeypatch.setattr("hierarchy_router.os", SimpleNamespace(**{**vars(real_os),
        "environ": {**os.environ, "ROUND9_HOME": str(private)}}))
    monkeypatch.setattr("hierarchy_fresh_brief.os", SimpleNamespace(**{**vars(real_os), "open": opened, "close": closed}))
    monkeypatch.setattr("hierarchy_fresh_brief._symlink_reader", lambda: read)
    operation = fresh._Operation()
    journal = operation.lifecycle(ledger.path)
    expected = "symlink paths are not supported: " + str(linked)
    _policy, state = journal.load()
    assert set(state["requests"]) == {"healthy", "hostile"}
    assert journal.refusals_for("hostile") == [(str(linked / "auth.json"), expected)]
    assert journal.refusals_for("healthy") == []
    assert 0 < len(sizes) <= 40
    assert not live and not operation.failed_validation
    operation.verify()


@lifecycle_only
@pytest.mark.parametrize("fault", ["policy", "identity"])
def test_round9_global_fault_invalidates_every_capture_of_its_request(tmp_path, monkeypatch, fault):
    from concurrent.futures import ThreadPoolExecutor
    import hierarchy_fresh_brief as fresh
    import hierarchy_router as router
    private, note = tmp_path / "private", tmp_path / "note.md"
    private.mkdir()
    note.write_bytes(b"healthy independent evidence\n")
    environment = {**os.environ, "ROUND9_HOME": str(private)}
    real_os, denied = router.os, [fault == "identity"]
    def stated(path, *args, **kwargs):
        if Path(path) == private and denied[0]:
            raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(private))
        return real_os.stat(path, *args, **kwargs)
    monkeypatch.setattr("hierarchy_router._owner_home", lambda: tmp_path / "owner")
    monkeypatch.setattr("hierarchy_router._home_declarations", lambda: (("ROUND9_HOME", ".codex"),))
    monkeypatch.setattr("hierarchy_router.os", SimpleNamespace(**{**vars(real_os), "stat": stated, "environ": environment}))
    owner = fresh._Operation()
    expected_type = router.CapturedPolicyError if fault == "policy" else ValueError
    with owner.path_guard.active():
        first = fresh._Operation()
        if fault == "policy": environment["ROUND9_HOME"] = str(tmp_path / "changed")
        with pytest.raises(expected_type) as caught:
            first.prove(first.path_guard.identities)
        original = caught.value
        assert first.failed_validation
        denied[0], environment["ROUND9_HOME"] = False, str(private)
        siblings = [fresh._Operation(), fresh._Operation()]
        assert all(operation.path_guard is owner.path_guard for operation in siblings)
        def prove(operation):
            with pytest.raises(expected_type) as caught:
                operation.prove(lambda: None)
            assert caught.value is original
            assert operation.failed_validation
        with ThreadPoolExecutor(max_workers=2) as pool:
            for future in [pool.submit(prove, operation) for operation in siblings]: future.result(timeout=30)
        with pytest.raises(expected_type) as caught:
            owner.verify()
        assert caught.value is original and owner.failed_validation
    independent = fresh._Operation()
    independent.read(note)
    independent.verify()


@lifecycle_only
def test_round9_concurrent_captures_share_one_lazy_root_probe(tmp_path, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    import hierarchy_fresh_brief as fresh
    import hierarchy_router as router
    private = tmp_path / "private"
    private.mkdir()
    real_os, calls, second, start = router.os, [], threading.Event(), threading.Barrier(2)
    def stated(path, *args, **kwargs):
        if Path(path) == private:
            calls.append(private)
            if len(calls) == 1:
                # Model a slow OS boundary. The assertion is the probe count,
                # never elapsed time; a serialized reader needs no second call.
                second.wait(1)
            else:
                second.set()
        return real_os.stat(path, *args, **kwargs)
    monkeypatch.setattr("hierarchy_router._owner_home", lambda: tmp_path)
    monkeypatch.setattr("hierarchy_router._home_declarations", lambda: (("ROUND9_HOME", "private"),))
    monkeypatch.setattr("hierarchy_router.os", SimpleNamespace(**{**vars(real_os), "stat": stated,
        "environ": {**os.environ, "ROUND9_HOME": str(private)}}))
    owner = fresh._Operation()
    with owner.path_guard.active():
        children = [fresh._Operation(), fresh._Operation()]
    def prove(operation):
        start.wait(timeout=10)
        return operation.prove(operation.path_guard.identities)
    with ThreadPoolExecutor(max_workers=2) as pool:
        for future in [pool.submit(prove, operation) for operation in children]:
            assert future.result(timeout=30) is not None
    assert calls == [private]


@lifecycle_only
@pytest.mark.parametrize("fault", ["policy", "identity"])
def test_round9_an_ambient_failure_cannot_poison_an_independent_request(tmp_path, monkeypatch, fault):
    import hierarchy_fresh_brief as fresh
    import hierarchy_router as router
    private = tmp_path / "private"
    private.mkdir()
    environment = {**os.environ, "ROUND9_HOME": str(private)}
    real_os, denied = router.os, [fault == "identity"]
    def stated(path, *args, **kwargs):
        if Path(path) == private and denied[0]:
            raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(private))
        return real_os.stat(path, *args, **kwargs)
    monkeypatch.setattr("hierarchy_router._owner_home", lambda: tmp_path / "owner")
    monkeypatch.setattr("hierarchy_router._home_declarations", lambda: (("ROUND9_HOME", ".codex"),))
    monkeypatch.setattr("hierarchy_router.os", SimpleNamespace(**{**vars(real_os), "stat": stated, "environ": environment}))
    failed = fresh._Operation()
    if fault == "policy": environment["ROUND9_HOME"] = str(tmp_path / "changed")
    try:
        failed.prove(failed.path_guard.identities)
    except ValueError:
        assert failed.failed_validation
        denied[0], environment["ROUND9_HOME"] = False, str(private)
        independent = fresh._Operation()
        assert independent.path_guard is not failed.path_guard
        brief = fresh.Brief(_operation=independent)
        missing = {"path": str(tmp_path / "missing.md"), "sha256": "0" * 64}
        origin = {"path": str(tmp_path / "origin.json"), "sha256": "1" * 64}
        brief.evidence(missing, origin)
        assert not independent.failed_validation
        assert [row["kind"] for row in brief.sections["Evidence references"]] == ["unverified_evidence"]
        independent.verify()
    else:
        pytest.fail("global failure witness did not refuse")


@lifecycle_only
@pytest.mark.parametrize("field", ["paths", "scope", "disposition", "resolve"])
@pytest.mark.parametrize("backend", ["native", "unsupported"])
def test_round8_stored_public_symlink_stays_global(tmp_path, monkeypatch, field, backend):
    import hierarchy_fresh_brief as fresh
    if backend == "native" and not fresh._reference_descriptors():
        pytest.skip("directory descriptors unavailable")
    ledger = Ledger(tmp_path)
    linked, public = tmp_path / "linked", tmp_path / "public"
    linked.mkdir()
    public.mkdir()
    bad, healthy = request("hostile", paths=[str(linked / "file.py")]), request("healthy")
    ledger.publish(healthy)
    if field == "scope":
        change = SmallChange(ledger, bad)
        change.plan["plan"]["path_scopes"] = [bad["paths"]]
        change.register()
    elif field in {"disposition", "resolve"}:
        first = request("first")
        ledger.publish(first)
        extra = {}
        if field == "resolve":
            ledger.event("disposition", status="HOLD", resolution={"kind": "blocked", "owner": "engine/coordinator",
                "next_decision": "review", "condition": "reviewed", "evidence": ledger.evidence}, **ledger.target(first))
            extra["blocker_sha256"] = fresh.digest(ledger.status()["requests"]["first"]["resolution"])
        ledger.event(field, **({"status": "FINAL"} if field == "disposition" else extra),
            resolution={"kind": "next", "request": raw_request(bad), "evidence": ledger.evidence}, **ledger.target(first))
    else:
        ledger.publish(bad)
    linked.rmdir()
    symlink_or_skip(public, linked, target_is_directory=True)
    if backend == "unsupported":
        monkeypatch.setattr("hierarchy_fresh_brief._reference_descriptors", lambda: False)
    expected = "symlink paths are not supported: " + str(linked)
    def probe():
        operation = fresh._Operation()
        journal = operation.lifecycle(ledger.path)
        if field in {"disposition", "resolve"}:
            _policy, state = journal.load()
            assert set(state["requests"]) == {"first", "healthy"}
            assert journal.unknown_rows == {"first": "lifecycle row UNKNOWN at event event-%d: %s" % (ledger.counter, expected)}
            assert journal.private_refusals == {}
            operation.verify()
            return operation
        with pytest.raises(alias_router.SymlinkPathError) as caught:
            journal.load()
        assert str(caught.value).encode() == expected.encode()
        return operation
    owners = [probe()]
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as pool:
        owners += [future.result(timeout=30) for future in (pool.submit(probe), pool.submit(probe))]
    linked.unlink()
    linked.mkdir()
    for operation in owners:
        if field in {"disposition", "resolve"}:
            operation.verify()
            continue
        with pytest.raises(alias_router.SymlinkPathError) as caught:
            operation.verify()
        assert str(caught.value).encode() == expected.encode()


@lifecycle_only
@pytest.mark.parametrize("fault", ["oversize", "zero-size", "zero-inode", "lost-inode", "unavailable", "denied", "truncated"])
def test_round10_unproved_private_link_is_quarantined_and_closes_descriptors(tmp_path, monkeypatch, fault):
    import hierarchy_fresh_brief as fresh
    if not fresh._reference_descriptors(): pytest.skip("directory descriptors unavailable")
    ledger = Ledger(tmp_path)
    linked, private = tmp_path / "linked", tmp_path / "private"
    linked.mkdir()
    private.mkdir()
    ledger.publish(request("healthy"))
    ledger.publish(request("hostile", paths=[str(linked / "file.py")]))
    linked.rmdir()
    symlink_or_skip(private, linked, target_is_directory=True)
    real_os, live, reads = fresh.os, {}, []
    native_read = fresh._symlink_reader()
    if fault == "lost-inode" and native_read is None: pytest.skip("bounded readlinkat unavailable")
    def actual(path, kwargs):
        value = Path(path)
        return live[kwargs["dir_fd"]] / value if not value.is_absolute() and kwargs.get("dir_fd") is not None else value
    def opened(path, *args, **kwargs):
        value = actual(path, kwargs)
        assert value != linked and linked not in value.parents
        assert value != private and private not in value.parents
        descriptor = real_os.open(path, *args, **kwargs)
        live[descriptor] = value
        return descriptor
    def closed(descriptor):
        live.pop(descriptor, None)
        return real_os.close(descriptor)
    def stated(path, *args, **kwargs):
        info = real_os.stat(path, *args, **kwargs)
        if actual(path, kwargs) == linked and (fault in {"oversize", "zero-size", "zero-inode"} or fault == "lost-inode" and reads):
            size = fresh.MAX_SYMLINK_BYTES + 1 if fault == "oversize" else 0 if fault == "zero-size" else info.st_size
            return SimpleNamespace(st_dev=info.st_dev, st_ino=0 if fault in {"zero-inode", "lost-inode"} else info.st_ino, st_mode=info.st_mode,
                st_size=size,
                st_mtime_ns=info.st_mtime_ns, st_ctime_ns=info.st_ctime_ns)
        return info
    def read(directory, name, size):
        reads.append(size)
        assert 0 < size <= fresh.MAX_SYMLINK_BYTES
        if fault == "lost-inode": return native_read(directory, name, size)
        if fault == "denied": raise PermissionError("UNTRUSTED readlink failure")
        return os.fsencode(private) + b"/extra"
    def reader():
        if fault in {"oversize", "zero-size", "zero-inode"}:
            raise AssertionError("reader reached before declared-size refusal")
        return None if fault == "unavailable" else read
    monkeypatch.setattr("hierarchy_router._owner_home", lambda: tmp_path / "owner")
    monkeypatch.setattr("hierarchy_router._home_declarations", lambda: (("ROUND8_HOME", ".private"),))
    monkeypatch.setattr("hierarchy_router.os", SimpleNamespace(**{**vars(os),
        "environ": {**os.environ, "ROUND8_HOME": str(private)}}))
    monkeypatch.setattr("hierarchy_fresh_brief.os", SimpleNamespace(**{**vars(real_os),
        "stat": stated, "open": opened, "close": closed}))
    monkeypatch.setattr("hierarchy_fresh_brief._symlink_reader", reader)
    operation = fresh._Operation()
    journal = operation.lifecycle(ledger.path)
    expected = "symlink paths are not supported: " + str(linked)
    _policy, state = journal.load()
    assert set(state["requests"]) == {"healthy", "hostile"}
    assert journal.refusals_for("hostile") == [(str(linked / "file.py"), expected)]
    assert journal.refusals_for("healthy") == []
    operation.verify()
    assert not operation.failed_validation
    assert not live
    assert reads == ([] if fault in {"oversize", "zero-size", "zero-inode", "unavailable"} else [len(os.fsencode(private))])


@lifecycle_only
@pytest.mark.parametrize("changed", ["link", "parent", "inner-link"])
def test_round10_link_classification_quarantines_concurrent_replacement(tmp_path, monkeypatch, changed):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    import hierarchy_fresh_brief as fresh
    if not fresh._reference_descriptors(): pytest.skip("directory descriptors unavailable")
    native_read = fresh._symlink_reader()
    if native_read is None: pytest.skip("bounded readlinkat unavailable")
    ledger = Ledger(tmp_path)
    parent, private, public = tmp_path / "links", tmp_path / "private", tmp_path / "public"
    parent.mkdir()
    private.mkdir()
    public.mkdir()
    linked = parent / "linked"
    linked.mkdir()
    ledger.publish(request("healthy"))
    ledger.publish(request("hostile", paths=[str(linked / "file.py")]))
    linked.rmdir()
    second = tmp_path / "second"
    if changed == "inner-link": symlink_or_skip(private, second, target_is_directory=True)
    symlink_or_skip(public if changed == "link" else second if changed == "inner-link" else private,
                    linked, target_is_directory=True)
    entered, release = threading.Event(), threading.Event()
    def read(directory, name, size):
        raw = native_read(directory, name, size)
        if changed == "inner-link" and name != "second": return raw
        entered.set()
        assert release.wait(10), "link replacement was not released"
        return raw
    monkeypatch.setattr("hierarchy_router._owner_home", lambda: tmp_path / "owner")
    monkeypatch.setattr("hierarchy_router._home_declarations", lambda: (("ROUND8_HOME", ".private"),))
    monkeypatch.setattr("hierarchy_router.os", SimpleNamespace(**{**vars(os),
        "environ": {**os.environ, "ROUND8_HOME": str(private)}}))
    monkeypatch.setattr("hierarchy_fresh_brief._symlink_reader", lambda: read)
    operation = fresh._Operation()
    journal = operation.lifecycle(ledger.path)
    expected = "symlink paths are not supported: " + str(linked)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(journal.load)
        try:
            assert entered.wait(10), "link classifier did not reach the reader"
            if changed == "link":
                linked.unlink()
                symlink_or_skip(private, linked, target_is_directory=True)
            elif changed == "inner-link":
                second.unlink()
                symlink_or_skip(public, second, target_is_directory=True)
            else:
                parent.rename(tmp_path / "old-links")
                parent.mkdir()
                symlink_or_skip(public, linked, target_is_directory=True)
        finally:
            release.set()
        _policy, state = pending.result(timeout=30)
        assert set(state["requests"]) == {"healthy", "hostile"}
    assert journal.refusals_for("hostile") == [(str(linked / "file.py"), expected)]
    assert journal.refusals_for("healthy") == []
    assert not operation.failed_validation
    operation.verify()


@lifecycle_only
@pytest.mark.parametrize("spelling", ["firmlink", "absolute-symlink", "relative-symlink"])
@pytest.mark.parametrize("kind", ["disposition", "resolve"])
def test_round7_shared_evidence_path_does_not_exempt_successor_scope(tmp_path, monkeypatch, kind, spelling):
    import hierarchy_fresh_brief as fresh
    import hierarchy_lifecycle as life
    import hierarchy_workspace as workspace
    from tests.integration.test_hierarchy_router import Loop
    if not fresh._reference_descriptors(): pytest.skip("secure lock requires directory descriptors")
    world = Loop(tmp_path)
    world.team("engine")
    alias, private = tmp_path / "firmlink", tmp_path / "private"
    alias.mkdir()
    private.mkdir()
    first, healthy = request("first"), request("healthy")
    following = request("following", paths=[str(alias / "auth.json")])
    world.ledger.publish(first)
    world.approved(healthy)
    extra = {}
    if kind == "resolve":
        world.ledger.event("disposition", status="HOLD", resolution={"kind": "blocked",
            "owner": "engine/coordinator", "next_decision": "review", "condition": "reviewed",
            "evidence": world.ledger.evidence}, **world.ledger.target(first))
        extra["blocker_sha256"] = fresh.digest(world.ledger.status()["requests"]["first"]["resolution"])
    world.ledger.event(kind, **({"status": "FINAL"} if kind == "disposition" else extra),
        resolution={"kind": "next", "request": raw_request(following),
                    "evidence": [{"path": following["paths"][0], "sha256": "0" * 64}]},
        **world.ledger.target(first))
    world.ledger.approve(following)
    if spelling != "firmlink":
        alias.rmdir()
        target = private if spelling == "absolute-symlink" else os.path.relpath(private, alias.parent)
        symlink_or_skip(target, alias, target_is_directory=True)
    real_os, mark, descriptors = fresh.os, private.stat(), {}
    def actual(path, kwargs):
        value = Path(path)
        return descriptors[kwargs["dir_fd"]] / value if not value.is_absolute() and kwargs.get("dir_fd") is not None else value
    def stated(path, *args, **kwargs):
        value = actual(path, kwargs)
        if value == alias and spelling == "firmlink": return mark
        assert alias not in value.parents, "private descendant metadata"
        return real_os.stat(path, *args, **kwargs)
    def lstated(path, *args, **kwargs):
        if Path(path) == alias and spelling == "firmlink": return mark
        assert alias not in Path(path).parents, "private descendant metadata"
        return real_os.lstat(path, *args, **kwargs)
    def opened(path, *args, **kwargs):
        value = actual(path, kwargs)
        assert value != alias and alias not in value.parents, "private content open"
        descriptor = real_os.open(path, *args, **kwargs)
        descriptors[descriptor] = value
        return descriptor
    def closed(descriptor):
        descriptors.pop(descriptor, None)
        return real_os.close(descriptor)
    monkeypatch.setattr("hierarchy_router._owner_home", lambda: tmp_path / "owner")
    monkeypatch.setattr("hierarchy_router._home_declarations", lambda: (("ROUND7_HOME", ".private"),))
    monkeypatch.setattr("hierarchy_router.os", SimpleNamespace(**{**vars(os),
        "environ": {**os.environ, "ROUND7_HOME": str(private)}}))
    monkeypatch.setattr("hierarchy_fresh_brief.os", SimpleNamespace(**{**vars(real_os), "stat": stated, "lstat": lstated,
        "open": opened, "close": closed}))
    def probe():
        result = alias_router.status(life.Lifecycle(world.ledger.path), workspace.Store(world.workspace.store), 5)
        rows = {row["request_id"]: row for row in result["requests"]}
        assert (rows["following"]["state"], rows["following"].get("reason")) == ("held", "reference_unavailable")
        expected = ("owner-private host directory is not an input" if spelling == "firmlink"
                    else "symlink paths are not supported: " + str(alias))
        assert rows["following"]["detail"] == expected
        assert rows["healthy"]["state"] == "ready"
    for _ in range(2): probe()
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as pool:
        for future in [pool.submit(probe), pool.submit(probe)]: future.result(timeout=30)
    assert not descriptors


@lifecycle_only
@pytest.mark.parametrize("field", ["paths", "scope", "disposition", "resolve"])
@pytest.mark.parametrize("failure", ["not-directory", "denied", "changed"])
def test_round7_stored_walk_refusal_stays_with_its_row(tmp_path, monkeypatch, field, failure):
    import hierarchy_fresh_brief as fresh
    ledger = Ledger(tmp_path)
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    bad, healthy = request("hostile", paths=[str(blocked / "scope")]), request("healthy")
    ledger.publish(healthy)
    target = bad
    if field == "scope":
        change = SmallChange(ledger, bad)
        change.plan["plan"]["path_scopes"] = [bad["paths"]]
        change.register()
    elif field in {"disposition", "resolve"}:
        first = request("first")
        ledger.publish(first)
        extra = {}
        if field == "resolve":
            ledger.event("disposition", status="HOLD", resolution={"kind": "blocked", "owner": "engine/coordinator",
                "next_decision": "review", "condition": "reviewed", "evidence": ledger.evidence}, **ledger.target(first))
            extra["blocker_sha256"] = fresh.digest(ledger.status()["requests"]["first"]["resolution"])
        ledger.event(field, **({"status": "FINAL"} if field == "disposition" else extra),
            resolution={"kind": "next", "request": raw_request(bad), "evidence": ledger.evidence}, **ledger.target(first))
    else:
        ledger.publish(bad)
    if failure == "not-directory":
        blocked.rmdir()
        blocked.write_text("ordinary file")
    real_os = fresh.os
    def stated(path, *args, **kwargs):
        if Path(path).name == "blocked":
            if failure == "denied": raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(blocked))
            if failure == "changed": raise ValueError("reference parent changed while opening")
        return real_os.stat(path, *args, **kwargs)
    def lstated(path, *args, **kwargs):
        if Path(path).name == "blocked": return stated(path, *args, **kwargs)
        return real_os.lstat(path, *args, **kwargs)
    monkeypatch.setattr("hierarchy_fresh_brief.os", SimpleNamespace(**{**vars(real_os), "stat": stated, "lstat": lstated}))
    def probe():
        operation = fresh._Operation()
        journal = operation.lifecycle(ledger.path)
        if failure == "denied" or failure == "changed" and field not in {"disposition", "resolve"}:
            expected_type = PermissionError if failure == "denied" else ValueError
            expected = (str(PermissionError(errno.EACCES, os.strerror(errno.EACCES), bad["paths"][0]))
                        if failure == "denied" else "reference parent changed while opening")
            with pytest.raises(expected_type) as caught:
                journal.load()
            assert str(caught.value) == expected
            with pytest.raises(expected_type) as caught:
                operation.verify()
            assert str(caught.value) == expected
            return
        _policy, state = journal.load()
        if failure == "changed":
            assert set(state["requests"]) == {"first", "healthy"}
            assert journal.unknown_rows
            assert journal.private_refusals == {}
            operation.verify()
            return
        assert {target["id"], "healthy"} <= state["requests"].keys()
        assert target["id"] not in journal.unknown_rows
        for _ in range(2): assert journal.refusals_for(target["id"], consume=True) == []
        assert journal.refusals_for("healthy") == []
        operation.verify()
    probe()
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as pool:
        for future in [pool.submit(probe), pool.submit(probe)]: future.result(timeout=30)


@lifecycle_only
@pytest.mark.parametrize("failure", ["missing", "hash", "witness", "symlink"])
def test_round7_consumed_evidence_failure_latches_its_publishing_parent(tmp_path, failure):
    import hierarchy_fresh_brief as fresh
    ledger = Ledger(tmp_path)
    bad, healthy = request("hostile"), request("healthy")
    artifact = tmp_path / "row-evidence"
    artifact.write_bytes(b"valid evidence")
    reference = {"path": str(artifact), "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}
    ledger.ready(bad)
    event_path = sorted((ledger.path / "events").glob("*.json"))[-1]
    record = json.loads(event_path.read_text())
    record["envelope"]["event"]["gates"]["source"] = [reference]
    record["event_sha256"] = fresh.digest(record["envelope"])
    event_path.write_bytes(fresh.encoded(record) + b"\n")
    ledger.publish(healthy)
    operation = fresh._Operation()
    journal = operation.lifecycle(ledger.path)
    journal.load()
    if failure == "witness": assert journal.refusals_for("hostile", consume=True) == []
    if failure in {"missing", "symlink"}: artifact.unlink()
    if failure == "symlink":
        public = tmp_path / "public-evidence"
        public.write_bytes(b"valid evidence")
        symlink_or_skip(public, artifact)
    elif failure != "missing": artifact.write_bytes(b"changed evidence")
    first_failure = None
    for _ in range(2):
        refusals = journal.refusals_for("hostile", consume=True)
        assert refusals and operation.failed_validation
        if first_failure is None:
            first_failure = ("captured attachment identity/content metadata changed: " + str(artifact)
                             if failure == "witness" else refusals[0][1])
        with pytest.raises(FileNotFoundError if failure == "missing" else ValueError) as caught:
            operation.verify()
        assert str(caught.value) == first_failure
    def probe():
        owner = fresh._Operation()
        captured = owner.lifecycle(ledger.path)
        captured.load()
        assert captured.refusals_for("healthy", consume=True) == []
        owner.verify()
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as pool:
        for future in [pool.submit(probe), pool.submit(probe)]: future.result(timeout=30)
    if failure == "symlink": artifact.unlink()
    artifact.write_bytes(b"valid evidence")
    with pytest.raises(FileNotFoundError if failure == "missing" else ValueError) as caught:
        operation.verify()
    assert str(caught.value) == first_failure


@lifecycle_only
def test_round7_policy_authority_symlink_refuses_globally(tmp_path):
    import hierarchy_fresh_brief as fresh
    authority, public = tmp_path / "authority", tmp_path / "public"
    authority.mkdir()
    public.mkdir()
    ledger = Ledger(tmp_path, policy_changes={"authority": [{"path": str(authority / "auth.json"), "sha256": "0" * 64}]})
    ledger.publish(request("healthy"))
    authority.rmdir()
    symlink_or_skip(public, authority, target_is_directory=True)
    operation = fresh._Operation()
    captured = operation.lifecycle(ledger.path)
    expected = "symlink paths are not supported: " + str(authority)
    with pytest.raises(alias_router.SymlinkPathError) as caught:
        captured.load()
    assert str(caught.value) == expected
    authority.unlink()
    authority.mkdir()
    for _ in range(2):
        with pytest.raises(alias_router.SymlinkPathError) as caught:
            operation.verify()
        assert str(caught.value) == expected


@lifecycle_only
def test_round7_successor_policy_failure_is_global(tmp_path, monkeypatch):
    import hierarchy_fresh_brief as fresh
    ledger = Ledger(tmp_path)
    first = request("first")
    blocked, private = tmp_path / "blocked", tmp_path / "private"
    blocked.mkdir()
    private.mkdir()
    ledger.publish(first)
    following = request("following", paths=[str(blocked / "scope")])
    ledger.event("disposition", status="FINAL", resolution={"kind": "next", "request": raw_request(following),
                 "evidence": ledger.evidence}, **ledger.target(first))
    environment = {**os.environ, "ROUND7_HOME": str(private)}
    real_os = fresh.os
    def stated(path, *args, **kwargs):
        if Path(path).name == "blocked": environment["ROUND7_HOME"] = str(tmp_path / "changed-home")
        return real_os.stat(path, *args, **kwargs)
    monkeypatch.setattr("hierarchy_router._owner_home", lambda: tmp_path / "owner")
    monkeypatch.setattr("hierarchy_router._home_declarations", lambda: (("ROUND7_HOME", ".private"),))
    monkeypatch.setattr("hierarchy_router.os", SimpleNamespace(**{**vars(os), "environ": environment}))
    monkeypatch.setattr("hierarchy_fresh_brief.os", SimpleNamespace(**{**vars(real_os), "stat": stated}))
    operation = fresh._Operation()
    journal = operation.lifecycle(ledger.path)
    with pytest.raises(alias_router.CapturedPolicyError, match="^host-home configuration changed during capture$"):
        journal.load()
    environment["ROUND7_HOME"] = str(private)
    for _ in range(2):
        with pytest.raises(alias_router.CapturedPolicyError, match="^host-home configuration changed during capture$"):
            operation.verify()


@pytest.mark.parametrize("site", ["lifecycle", "lifecycle-direct", "mailbox", "store"])
def test_round6_failed_captured_constructor_latches_before_witnesses(tmp_path, monkeypatch, site):
    import hierarchy_fresh_brief as fresh
    import hierarchy_small_change_dispatch as dispatch
    private = tmp_path / "private"
    private.mkdir()
    monkeypatch.setattr("hierarchy_router._owner_home", lambda: tmp_path / "owner")
    monkeypatch.setattr("hierarchy_router._home_declarations", lambda: (("ROUND6_HOME", ".private"),))
    monkeypatch.setattr("hierarchy_router.os", SimpleNamespace(**{**vars(os),
        "environ": {**os.environ, "ROUND6_HOME": str(private)}}))
    operation = fresh._Operation()
    def construct():
        if site == "lifecycle": return operation.lifecycle(private)
        if site == "lifecycle-direct": return fresh._CapturedLifecycle(private, operation)
        if site == "mailbox": return fresh._CapturedMailbox(private, _operation=operation)
        return dispatch._CapturedStore(private, operation)
    for attempt in (construct, operation.verify, construct, operation.verify):
        with pytest.raises(ValueError, match="^owner-private host directory is not an input$"):
            attempt()
        assert operation.failed_validation
    assert operation.files == {} and operation.folders == {}
    fresh._Operation().verify()


@pytest.mark.parametrize("entry", ["inspect", "locate", "evidence"])
def test_round6_standalone_inspect_has_one_owning_snapshot(tmp_path, pilot, monkeypatch, entry):  # noqa: F811
    import hierarchy_fresh_brief as fresh
    private, target = tmp_path / "private", tmp_path / "note"
    private.mkdir()
    target.write_bytes(b"public fixture")
    reference = {"path": str(target), "sha256": hashlib.sha256(b"public fixture").hexdigest()}
    brief = fresh.Brief()
    for kind in ("one", "two"): brief.add(fresh.SECTIONS[0], kind, reference)
    raw = brief.render("a/orchestrator", "2026-01-01T00:00:00Z", 1)
    real_os, calls = alias_router.os, []
    def stated(path, *args, **kwargs):
        if not isinstance(path, int) and Path(path) == private: calls.append(path)
        return real_os.stat(path, *args, **kwargs)
    monkeypatch.setattr("hierarchy_router._owner_home", lambda: tmp_path / "owner")
    monkeypatch.setattr("hierarchy_router._home_declarations", lambda: (("ROUND6_HOME", ".private"),))
    monkeypatch.setattr("hierarchy_router.os", SimpleNamespace(**{**vars(real_os), "stat": stated,
        "environ": {**os.environ, "ROUND6_HOME": str(private)}}))
    for _ in range(2):
        calls.clear()
        if entry == "inspect": assert fresh.inspect(raw) == 2
        elif entry == "locate": assert fresh.locate(pilot[0], "a")[0].root == pilot[0]
        else:
            scoped = fresh.Brief(_authoritative=True)
            for _ in range(2): scoped.evidence(reference, reference)
            scoped.operation.verify()
        assert calls == [private], calls


@pytest.mark.parametrize("failed", [False, True])
def test_round6_concurrent_proofs_keep_request_identity_and_failure_local(tmp_path, monkeypatch, failed):
    from concurrent.futures import ThreadPoolExecutor
    from contextvars import ContextVar
    from threading import Barrier
    import hierarchy_fresh_brief as fresh
    import hierarchy_small_change_dispatch as dispatch
    private, public = tmp_path / "private", tmp_path / "public"
    private.mkdir(); public.mkdir()
    real_os, calls, request_id = alias_router.os, [], ContextVar("round6_request", default=None)
    def stated(path, *args, **kwargs):
        if not isinstance(path, int) and Path(path) == private: calls.append(request_id.get())
        return real_os.stat(path, *args, **kwargs)
    monkeypatch.setattr("hierarchy_router._owner_home", lambda: tmp_path / "owner")
    monkeypatch.setattr("hierarchy_router._home_declarations", lambda: (("ROUND6_HOME", ".private"),))
    monkeypatch.setattr("hierarchy_router.os", SimpleNamespace(**{**vars(real_os), "stat": stated,
        "environ": {**os.environ, "ROUND6_HOME": str(private)}}))
    ready = Barrier(2)
    def run(index):
        request_id.set(index)
        operation = fresh._Operation()
        ready.wait(timeout=10)
        def verification():
            dispatch.checked_path(public)
            operation.exists(public)
            if failed and index == 0: operation.read(private / "never-opened")
        if failed and index == 0:
            for _ in range(2):
                with pytest.raises(ValueError, match="^owner-private host directory is not an input$"):
                    operation.prove(verification)
            assert operation.failed_validation
        else:
            operation.prove(verification)
            assert not operation.failed_validation
        assert fresh._PATH_GUARD.get() is None
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(run, range(2)))
    assert sorted(calls) == [0, 1]


@lifecycle_only
def test_round6_policy_validation_uses_inert_guard_bound_paths(tmp_path, monkeypatch):
    import hierarchy_fresh_brief as fresh
    ledger = Ledger(tmp_path)
    ledger.publish(request("healthy"))
    def pinned_path(_value):
        raise AssertionError("pinned bottom-up safe_path reached during captured replay")
    monkeypatch.setattr("hierarchy_lifecycle.safe_path", pinned_path)
    operation = fresh._Operation()
    assert "healthy" in operation.lifecycle(ledger.path).load()[1]["requests"]
    operation.verify()


def test_round6_no_plan_optional_public_symlink_remains_unverified(tmp_path):
    import hierarchy_fresh_brief as fresh
    target, linked = tmp_path / "public.md", tmp_path / "linked.md"
    target.write_bytes(b"public fixture")
    symlink_or_skip(target, linked)
    brief = fresh.Brief()
    brief.evidence({"path": str(linked), "sha256": hashlib.sha256(target.read_bytes()).hexdigest()},
                   {"path": str(target), "sha256": hashlib.sha256(target.read_bytes()).hexdigest()})
    assert [row["kind"] for row in brief.sections["Evidence references"]] == ["unverified_evidence"]
    brief.operation.verify()


@lifecycle_only
@pytest.mark.parametrize("spelling", ["symlink", "firmlink"])
@pytest.mark.parametrize("field", ["paths", "scope", "evidence"])
def test_round6_stored_lifecycle_alias_is_row_local(tmp_path, monkeypatch, spelling, field):
    import hierarchy_fresh_brief as fresh
    ledger = Ledger(tmp_path)
    private, alias = tmp_path / "private", tmp_path / "alias"
    private.mkdir()
    if spelling == "symlink": symlink_or_skip(private, alias, target_is_directory=True)
    else: alias.mkdir()
    bad, healthy = request("bad-alias"), request("healthy")
    bad["paths"] = [str(alias / "auth.json")]
    # Publish valid source bytes first, then replace only the stored canonical capsule and chain digest.
    ledger.publish(healthy)
    if field == "scope":
        change = SmallChange(ledger, request("bad-alias"))
        change.register()
    else:
        ledger.publish(request("bad-alias"))
        if field == "evidence":
            ledger.approve(request("bad-alias"))
            ledger.admit(request("bad-alias"))
    event_path = sorted((ledger.path / "events").glob("*.json"))[-1]
    record = json.loads(event_path.read_text())
    if field == "paths": record["envelope"]["event"]["request"] = raw_request(bad)
    elif field == "evidence":
        record["envelope"]["event"]["gates"]["source"] = [{"path": str(alias / "auth.json"), "sha256": "0" * 64}]
    else:
        proposal = alias_fresh.life.raw_value(record["envelope"]["event"]["proposal"])
        proposal["request"] = raw_request(bad)
        proposal["plan"]["request_sha256"] = raw_request(bad)["sha256"]
        proposal["plan"]["path_scopes"] = [bad["paths"]]
        record["envelope"]["event"]["proposal"] = raw_request(proposal)
        record["envelope"]["event"]["request_sha256"] = raw_request(bad)["sha256"]
        publish_path = sorted((ledger.path / "events").glob("*.json"))[-2]
        published = json.loads(publish_path.read_text())
        published["envelope"]["event"]["request"] = raw_request(bad)
        published["event_sha256"] = alias_fresh.digest(published["envelope"])
        publish_path.write_bytes(alias_fresh.encoded(published) + b"\n")
        record["previous"] = alias_fresh.digest(published)
    record["event_sha256"] = alias_fresh.digest(record["envelope"])
    event_path.write_bytes(alias_fresh.encoded(record) + b"\n")
    monkeypatch.setattr("hierarchy_router._owner_home", lambda: tmp_path / "owner")
    monkeypatch.setattr("hierarchy_router._home_declarations", lambda: (("ROUND6_HOME", ".private"),))
    real_os, private_mark = fresh.os, private.stat()
    below, descriptors = [], {}
    def actual(path, kwargs):
        value = Path(path)
        return descriptors[kwargs["dir_fd"]] / value if not value.is_absolute() and kwargs.get("dir_fd") is not None else value
    def stated(path, *args, **kwargs):
        value = actual(path, kwargs)
        if alias in value.parents: below.append(value)
        if spelling == "firmlink" and value == alias: return private_mark
        return real_os.stat(path, *args, **kwargs)
    def lstated(path, *args, **kwargs):
        if alias in Path(path).parents: below.append(Path(path))
        if spelling == "firmlink" and Path(path) == alias: return private_mark
        return real_os.lstat(path, *args, **kwargs)
    def opened(path, *args, **kwargs):
        value = actual(path, kwargs)
        if value == alias or alias in value.parents: below.append(value)
        descriptor = real_os.open(path, *args, **kwargs)
        descriptors[descriptor] = value
        return descriptor
    def closed(descriptor):
        descriptors.pop(descriptor, None)
        return real_os.close(descriptor)
    monkeypatch.setattr("hierarchy_router.os", SimpleNamespace(**{**vars(os),
        "environ": {**os.environ, "ROUND6_HOME": str(private)}}))
    monkeypatch.setattr("hierarchy_fresh_brief.os", SimpleNamespace(**{**vars(real_os), "stat": stated, "lstat": lstated,
        "open": opened, "close": closed}))
    def pinned_path(_value):
        raise AssertionError("pinned bottom-up safe_path reached during captured replay")
    monkeypatch.setattr("hierarchy_lifecycle.safe_path", pinned_path)
    for _ in range(2):
        operation = fresh._Operation()
        journal = operation.lifecycle(ledger.path)
        _policy, state = journal.load()
        assert {"bad-alias", "healthy"} <= state["requests"].keys()
        assert journal.refusals_for("bad-alias", consume=True)
        assert journal.refusals_for("bad-alias", consume=True)
        assert journal.refusals_for("healthy") == []
        if field == "evidence":
            with pytest.raises(alias_router.SymlinkPathError if spelling == "symlink" else alias_router.PrivatePathError):
                operation.verify()
        else:
            operation.verify()
    assert below == []
    assert descriptors == {}


PRIVACY_ACCESS_DRIVER = r'''
import json, os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import hierarchy_fresh_brief as fresh
import hierarchy_router as router
root, private, alias, target = map(Path, sys.argv[2:6])
action, backend = sys.argv[6:8]
router._owner_home = lambda: root/'owner'
router._home_declarations = lambda: (('ALIAS_TEST_HOME', '.private'),)
os.environ['ALIAS_TEST_HOME'] = str(private)
native = fresh._reference_descriptors()
if backend == 'descriptor' and not native:
    print(json.dumps({'unsupported': True})); sys.exit(0)
fresh._reference_descriptors = lambda: backend == 'descriptor'
identity = private.stat()
original_stat, original_lstat, original_fstat = os.stat, os.lstat, os.fstat
original_open, original_close, original_read, original_write = os.open, os.close, os.read, os.write
descriptors, accesses = {}, []
injected = False
active = action not in {'recheck', 'verify', 'verify-absence', 'read-swap'}
synthetic = action not in {'symlink-parent', 'race-parent', 'read-swap'}
def actual(value, kwargs=None):
    if isinstance(value, int): return descriptors.get(value)
    if not isinstance(value, (str, bytes, os.PathLike)): return None
    value = Path(os.fsdecode(value)); kwargs = kwargs or {}
    if not value.is_absolute() and kwargs.get('dir_fd') is not None:
        value = descriptors[kwargs['dir_fd']]/value
    return value
def observe(kind, value, kwargs=None):
    path = actual(value, kwargs)
    if active and path is not None and (path == alias or alias in path.parents):
        accesses.append({'kind': kind, 'path': str(path)})
    return path
def stated(path, *args, **kwargs):
    value = observe('stat', path, kwargs)
    return identity if active and synthetic and value == alias else original_stat(path, *args, **kwargs)
def lstated(path, *args, **kwargs):
    value = observe('lstat', path, kwargs)
    return identity if active and synthetic and value == alias else original_lstat(path, *args, **kwargs)
def fstated(descriptor):
    global injected
    if action == 'lock-fstat-failure' and not injected and descriptors.get(descriptor) == root/'.write.lock':
        injected = True
        raise OSError('fixture lock metadata failure')
    return identity if active and synthetic and descriptors.get(descriptor) == alias else original_fstat(descriptor)
def opened(path, *args, **kwargs):
    global injected
    value = observe('open', path, kwargs)
    if action == 'lock-open-failure' and not injected and value == root/'.write.lock':
        injected = True
        raise OSError('UNTRUSTED lock open error')
    if action == 'race-parent' and value == alias and not injected:
        injected = True
        alias.rename(alias.with_name('previous-alias'))
        alias.symlink_to(private, target_is_directory=True)
    descriptor = original_open(path, *args, **kwargs)
    if active and not synthetic:
        info = original_fstat(descriptor)
        if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
            answer['opened_private'] = True
    if value is not None: descriptors[descriptor] = value
    return descriptor
def closed(descriptor):
    descriptors.pop(descriptor, None)
    return original_close(descriptor)
def consumed(descriptor, amount):
    global active, injected
    observe('read', descriptor)
    raw = original_read(descriptor, amount)
    if action == 'read-swap' and raw and not injected:
        injected = True
        previous = alias.with_name('previous-alias')
        alias.rename(previous)
        alias.symlink_to(private, target_is_directory=True)
        # Descriptors already opened before the rename retain their PUBLIC identity.
        for opened_descriptor, path in list(descriptors.items()):
            if path == alias or alias in path.parents:
                descriptors[opened_descriptor] = previous/path.relative_to(alias)
        active = True
    return raw
def written(descriptor, raw):
    global injected
    if action in {'lock-write-failure', 'lock-write-exception'} and not injected and descriptors.get(descriptor) == root/'.write.lock':
        injected = True
        if action == 'lock-write-exception': raise OSError('UNTRUSTED lock write error')
        return 0
    return original_write(descriptor, raw)
os.stat, os.lstat, os.fstat, os.open, os.close, os.read = stated, lstated, fstated, opened, closed, consumed
os.write = written
def path_stat(path, *args, **kwargs): return stated(path, *args, **kwargs)
def path_lstat(path, *args, **kwargs): return lstated(path, *args, **kwargs)
# This child owns its pathlib classes; cover Python 3.9's cached accessor functions too.
Path.stat, Path.lstat = path_stat, path_lstat
sys.addaudithook(lambda event, args: observe(event, args[0])
    if active and args and event in {'open', 'os.scandir', 'os.listdir', 'os.mkdir'} else None)
operation = fresh._Operation()
answer = {'refused': False}
try:
    if action == 'read': fresh.file_ref(target)
    elif action in {'symlink-parent', 'race-parent', 'read-swap'}: operation.read(target)
    elif action == 'verify':
        operation.read(target)
        active = True
        operation.verify()
    elif action == 'verify-absence':
        assert not operation.exists(target)
        target.write_bytes(b'fixture private')
        active = True
        operation.verify()
    elif action == 'recheck':
        witness = {}
        fresh._read_reference(target, _witness=witness, _guard=operation.path_guard)
        active = True
        fresh._recheck_reference(witness, _guard=operation.path_guard)
    elif action == 'parent':
        descriptor, _ = fresh._reference_parent(alias, _guard=operation.path_guard)
        os.close(descriptor)
    elif action == 'ancestors': fresh._reference_ancestors(target, _guard=operation.path_guard)
    elif action in {'members', 'identity-only'}: operation.entries(alias, identity_only=action == 'identity-only')
    elif action.startswith('exists'): answer['exists'] = operation.exists(target); operation.verify()
    elif action == 'optional-evidence':
        brief = fresh.Brief(_operation=operation)
        brief.evidence({'path': str(target), 'sha256': sys.argv[8]},
                       {'path': str(root/'origin'), 'sha256': '0'*64})
        answer['unverified'] = any(row['kind'] == 'unverified_evidence'
                                  for row in brief.sections['Evidence references'])
        operation.verify()
    elif action == 'optional-attachment':
        active = False
        mailbox = fresh._CapturedMailbox(root/'mailbox', _operation=operation)
        active = True
        fresh._unread_attachment(mailbox, {'path': str(target), 'sha256': sys.argv[8]})
        operation.verify()
    elif action == 'readiness':
        mailbox = fresh._CapturedMailbox(root/'mailbox', _operation=operation)
        mailbox.readiness({'worktree': str(alias), 'branch': 'fixture', 'base_revision': 'a'*40,
            'lease_ref': 'refs/aegis/lanes/fixture', 'lease_oid': 'b'*40,
            'lease_expires_at': '2099-01-01T00:00:00Z', 'owned_paths': ['tools'],
            'scan_workspace': str(alias), 'scan_evidence': 'fixture', 'hook_evidence': 'fixture',
            'enforcement_tier': 'advisory'}, observe=False)
    elif action == 'router-lock':
        answer['code'] = router.main(['--lifecycle', str(alias), '--store', str(root/'store'), 'status'])
        answer['refused'] = answer['code'] == 2
    elif action == 'preflight-before-invalid':
        router.preflight_paths(alias, 'relative', _guard=operation.path_guard)
    elif action.startswith('lock-'):
        try:
            with router.writer_lock(root): pass
        except (ValueError, OSError) as exc:
            answer['first_failure'] = str(exc)
        answer['lock_left'] = (root/'.write.lock').exists()
        with router.writer_lock(root): answer['retried'] = True
except router.PrivatePathError as exc:
    answer.update(refused=True, error=str(exc), privacy=True)
except (ValueError, OSError) as exc:
    answer.update(refused=True, error=str(exc), privacy=False, exception=type(exc).__name__)
if action == 'read-swap':
    try: operation.read(target)
    except ValueError: answer['retry_refused'] = True
    active = False
    alias.unlink()
    alias.with_name('previous-alias').rename(alias)
    answer['repaired_sha256'] = fresh._Operation().read(target)[0]['sha256']
answer.update(accesses=accesses, live_descriptors=len(descriptors), parent_failed=operation.failed_validation)
print(json.dumps(answer))
'''


def test_privacy_case_alias_preflight_uses_the_mailbox_operation_snapshot(pilot, monkeypatch):  # noqa: F811
    """Argon 5 counts one mailbox operation, including its preflight, not guard instances."""
    if not alias_fresh._reference_descriptors():
        pytest.skip("case-sensitive public-sibling probes require directory descriptors")
    root, _ = pilot
    private, public = root.parent / "PrivateHome", root.parent / "pRIVATEhOME"
    private.mkdir()
    if public.exists(): pytest.skip("distinct case spellings require a case-sensitive fixture volume")
    public.mkdir()
    target = public / "note.md"
    target.write_bytes(b"public note")
    calls = []
    def stated(path, *args, **kwargs):
        if not isinstance(path, int) and Path(path) == private: calls.append(Path(path))
        return os.stat(path, *args, **kwargs)
    monkeypatch.setattr(alias_router, "_owner_home", lambda: root.parent / "owner")
    monkeypatch.setattr(alias_router, "_home_declarations", lambda: (("ALIAS_TEST_HOME", ".private"),))
    monkeypatch.setattr(alias_router, "os", SimpleNamespace(**{**vars(os), "stat": stated,
        "environ": {**os.environ, "ALIAS_TEST_HOME": str(private)}}))
    mailbox = alias_fresh._CapturedMailbox(root)
    reference = {"path": str(target), "sha256": hashlib.sha256(b"public note").hexdigest()}
    for _ in range(2):
        assert mailbox.brief(reference) == b"public note"
        mailbox.operation.verify()
    assert calls == [private]


def test_privacy_windows_anchor_quarantines_only_its_message(pilot, monkeypatch):  # noqa: F811
    root, _ = pilot
    invoke(root, "publish", message(identifier="windows-private", body=r"\\server\share\private"))
    invoke(root, "publish", message(identifier="healthy-note", body="healthy"))
    original = alias_router._lexical_path
    def lexical(value):
        return original(PureWindowsPath(value) if isinstance(value, str) and value.startswith("\\") else value)
    monkeypatch.setattr(alias_router, "_lexical_path", lexical)
    mailbox = alias_fresh._CapturedMailbox(root)
    records = mailbox.messages()
    assert {"windows-private", "healthy-note"} <= records.keys()
    assert set(mailbox.message_refusals) == {"windows-private"}
    assert mailbox.message_refusals["windows-private"][0].endswith("unsupported Windows path anchor")
    mailbox.operation.verify()


@lifecycle_only
def test_privacy_windows_anchor_quarantines_only_its_lifecycle_row(tmp_path, monkeypatch):
    ledger = Ledger(tmp_path)
    bad, healthy = request("windows-private"), request("healthy")
    ledger.publish(bad); ledger.publish(healthy)
    ledger.event("decision", actor=ledger.root_actor, decision="approve", reason=r"\\server\share\private",
                 **ledger.target(bad))
    original = alias_router._lexical_path
    def lexical(value):
        return original(PureWindowsPath(value) if isinstance(value, str) and value.startswith("\\") else value)
    monkeypatch.setattr(alias_router, "_lexical_path", lexical)
    operation = alias_fresh._Operation()
    journal = operation.lifecycle(ledger.path)
    _policy, state = journal.load()
    assert {"windows-private", "healthy"} <= state["requests"].keys()
    assert set(journal.private_refusals) == {"windows-private"}
    assert journal.refusals_for("healthy") == []
    assert journal.private_refusals["windows-private"][0][1] == "unsupported Windows path anchor"
    operation.verify()


@pytest.mark.parametrize("action", ["verify", "retry"])
@pytest.mark.parametrize("replacement", [True, False], ids=["replaced", "missing"])
def test_privacy_exists_retains_its_successful_identity_witness(tmp_path, action, replacement):
    target = tmp_path.resolve() / "present"
    target.write_bytes(b"public")
    operation = alias_fresh._Operation()
    assert operation.exists(target) is True
    target.rename(target.with_name("previous"))
    if replacement: target.write_bytes(b"replacement")
    with pytest.raises(ValueError, match="captured existing input changed"):
        operation.verify() if action == "verify" else operation.exists(target)
    with pytest.raises(ValueError, match="captured existing input changed"):
        operation.verify()


@pytest.mark.parametrize("backend", ["descriptor", "portable"])
@pytest.mark.parametrize("action", ["read", "recheck", "verify", "parent", "ancestors", "members", "identity-only",
                                    "exists-existing", "exists-missing", "exists-notdir", "router-lock",
                                    "optional-evidence", "optional-attachment", "readiness", "preflight-before-invalid"])
def test_privacy_before_every_alias_touch(tmp_path, backend, action):
    """Argon 1-4: even pathlib metadata and directory opens must follow the identity refusal."""
    if action == "parent" and backend == "portable":
        pytest.skip("directory descriptors are explicitly unsupported in this backend")
    root = tmp_path.resolve()
    private, alias = root / "private", root / "alias"
    private.mkdir(); alias.mkdir()
    target = alias / "record.md"
    target.write_bytes(b"fixture evidence")
    (root / "store").mkdir()
    if action == "exists-missing": target = alias / "missing"
    if action == "exists-notdir": target = target / "child"
    if action in {"optional-attachment", "readiness"}:
        invoke(root / "mailbox", "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": {
            "a/front-door": {}, "a/orchestrator": {}, "a/root": {}}, "counterparts": [], "writer_limit": 3})
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", PRIVACY_ACCESS_DRIVER, str(ROOT / "tools"),
        str(root), str(private), str(alias), str(target), action, backend,
        hashlib.sha256(b"fixture evidence").hexdigest()], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0 and not proc.stderr, proc.stdout + proc.stderr
    answer = json.loads(proc.stdout.splitlines()[-1])
    if answer.get("unsupported"): pytest.skip("directory descriptor capability unavailable")
    assert answer["refused"] and answer.get("exception") != "NotADirectoryError", answer
    assert all(row["path"] == str(alias) and row["kind"] in {"stat", "lstat"}
               for row in answer["accesses"]), answer
    assert answer["live_descriptors"] == 0, answer
    if action == "preflight-before-invalid":
        assert answer["error"] == "owner-private host directory is not an input", answer
    if action == "verify": assert answer.get("privacy") and answer["parent_failed"], answer
    if action.startswith("optional"):
        assert answer["parent_failed"] and not answer.get("unverified", False), answer


@pytest.mark.parametrize("backend", ["descriptor", "portable"])
@pytest.mark.parametrize("action", ["read", "verify-absence"])
def test_privacy_refuses_a_leaf_that_aliases_a_private_file(tmp_path, backend, action):
    """Argon 1's regular-file private-root instance must never open the matching leaf."""
    root = tmp_path.resolve()
    private, alias = root / "private-file", root / "alias-file"
    private.write_bytes(b"fixture private")
    if action == "read": alias.write_bytes(b"fixture private")
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", PRIVACY_ACCESS_DRIVER, str(ROOT / "tools"),
        str(root), str(private), str(alias), str(alias), action, backend, "0" * 64],
        capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0 and not proc.stderr, proc.stdout + proc.stderr
    answer = json.loads(proc.stdout.splitlines()[-1])
    if answer.get("unsupported"): pytest.skip("directory descriptor capability unavailable")
    assert answer["refused"] and answer["live_descriptors"] == 0, answer
    assert answer.get("privacy"), answer
    assert all(row["kind"] in {"stat", "lstat"} for row in answer["accesses"]), answer


@pytest.mark.parametrize("fault", ["lock-fstat-failure", "lock-write-failure", "lock-open-failure", "lock-write-exception"])
def test_privacy_anchored_lock_failure_closes_descriptors_and_allows_retry(tmp_path, fault):
    root = tmp_path.resolve()
    private, alias = root / "private", root / "alias"
    private.mkdir(); alias.mkdir()
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", PRIVACY_ACCESS_DRIVER, str(ROOT / "tools"),
        str(root), str(private), str(alias), str(alias / "unused"), fault, "descriptor", "0" * 64],
        capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0 and not proc.stderr, proc.stdout + proc.stderr
    answer = json.loads(proc.stdout.splitlines()[-1])
    if answer.get("unsupported"): pytest.skip("directory descriptor capability unavailable")
    assert answer.get("first_failure") and not answer["lock_left"] and answer.get("retried"), answer
    assert answer["first_failure"] == {"lock-fstat-failure": "cannot inspect journal lock",
        "lock-open-failure": "cannot create journal lock", "lock-write-failure": "cannot write journal lock",
        "lock-write-exception": "cannot write journal lock"}[fault], answer
    assert answer["live_descriptors"] == 0, answer


@pytest.mark.parametrize("action,backend", [("symlink-parent", "descriptor"),
    ("symlink-parent", "portable"), ("race-parent", "descriptor")])
def test_privacy_symlink_parent_and_concurrent_replacement(tmp_path, action, backend):
    root = tmp_path.resolve()
    private, alias = root / "private", root / "alias"
    private.mkdir()
    (private / "record.md").write_bytes(b"private fixture")
    if action == "symlink-parent":
        symlink_or_skip(private, alias, target_is_directory=True)
    else:
        probe = root / "capability-probe"
        symlink_or_skip(private, probe, target_is_directory=True)
        probe.unlink()
        alias.mkdir()
        (alias / "record.md").write_bytes(b"public fixture")
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", PRIVACY_ACCESS_DRIVER, str(ROOT / "tools"),
        str(root), str(private), str(alias), str(alias / "record.md"), action, backend, "0" * 64],
        capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0 and not proc.stderr, proc.stdout + proc.stderr
    answer = json.loads(proc.stdout.splitlines()[-1])
    if answer.get("unsupported"): pytest.skip("directory descriptor capability unavailable")
    assert answer["refused"] and not answer.get("opened_private"), answer
    assert all(row["path"] == str(alias) for row in answer["accesses"]), answer
    assert answer["live_descriptors"] == 0, answer


def test_privacy_unsupported_lock_backend_refuses_without_a_lock(tmp_path):
    root = tmp_path.resolve()
    private, alias = root / "private", root / "alias"
    private.mkdir(); alias.mkdir()
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", PRIVACY_ACCESS_DRIVER, str(ROOT / "tools"),
        str(root), str(private), str(alias), str(alias / "unused"), "lock-unsupported", "portable", "0" * 64],
        capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0 and not proc.stderr, proc.stdout + proc.stderr
    answer = json.loads(proc.stdout.splitlines()[-1])
    assert answer["refused"] and answer["error"] == "secure reference hashing requires directory descriptor support"
    assert not answer["lock_left"] and answer["live_descriptors"] == 0


def _privacy_parent_swap_during_read_checks_ancestors_before_metadata(tmp_path, backend):
    if os.name != "posix":
        pytest.skip("renaming a parent while its file is open requires POSIX sharing semantics")
    root = tmp_path.resolve()
    private, alias = root / "private", root / "alias"
    private.mkdir(); alias.mkdir()
    (alias / "record").write_bytes(b"initially public")
    (private / "record").write_bytes(b"private fixture")
    probe = root / "symlink-probe"
    symlink_or_skip(private, probe, target_is_directory=True)
    probe.unlink()
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", PRIVACY_ACCESS_DRIVER, str(ROOT / "tools"),
        str(root), str(private), str(alias), str(alias / "record"), "read-swap", backend, "0" * 64],
        capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0 and not proc.stderr, proc.stdout + proc.stderr
    answer = json.loads(proc.stdout.splitlines()[-1])
    if answer.get("unsupported"): pytest.skip("directory descriptor capability unavailable")
    assert answer["refused"] and not answer.get("opened_private") and answer["retry_refused"], answer
    assert answer["repaired_sha256"] == hashlib.sha256(b"initially public").hexdigest(), answer
    assert all(row["path"] == str(alias) and row["kind"] in {"stat", "lstat"}
               for row in answer["accesses"]), answer
    assert answer["live_descriptors"] == 0, answer


@pytest.mark.parametrize("value", [
    r"\\?\C:\Users\Alice\.codex\secret", r"\\.\C:\Users\Alice\.codex\secret",
    r"\\server\share\Users\Alice\.codex\secret", r"\\?\UNC\server\share\secret",
    r"\Users\Alice\.codex\secret",
])
def test_private_alias_windows_anchors_refuse_before_metadata(monkeypatch, value):
    def unexpected(*args, **kwargs):
        pytest.fail("non-drive anchor reached owner or filesystem discovery")

    monkeypatch.setattr(alias_router, "_owner_home", unexpected)
    monkeypatch.setattr(alias_router, "os", SimpleNamespace(stat=unexpected, lstat=unexpected, open=unexpected))
    with pytest.raises(ValueError, match="^unsupported Windows path anchor$"):
        alias_router.preflight_paths(PureWindowsPath(value))


def test_private_alias_windows_drive_paths_remain_lexically_private():
    root = PureWindowsPath(r"C:\Users\Alice\.codex")
    for value in (root / "secret", PureWindowsPath(r"c:\users\ALICE\.CODEX\secret")):
        with pytest.raises(alias_router.PrivatePathError, match="^owner-private host directory is not an input$"):
            alias_router._refuse_private_paths([value], {root})
    alias_router._refuse_private_paths([PureWindowsPath(r"C:\Users\Alice\public\record")], {root})


@pytest.mark.parametrize("anchored", [False, True], ids=["portable", "descriptor"])
@pytest.mark.parametrize("action", ["reference", "entries", "identity-only"])
def test_private_alias_reference_refuses_identity_before_content(tmp_path, anchored, action):
    root = tmp_path.resolve()
    private, alias = root / "private", root / "alias"
    private.mkdir(); alias.mkdir()
    target = alias / "record"
    target.write_bytes(b"private fixture bytes")
    selected = {"reference": "read", "entries": "members", "identity-only": "identity-only"}[action]
    for _ in range(2):
        proc = subprocess.run([sys.executable, "-I", "-B", "-c", PRIVACY_ACCESS_DRIVER, str(ROOT / "tools"),
            str(root), str(private), str(alias), str(target), selected,
            "descriptor" if anchored else "portable", "0" * 64], capture_output=True, text=True, timeout=30)
        assert proc.returncode == 0 and not proc.stderr, proc.stdout + proc.stderr
        answer = json.loads(proc.stdout.splitlines()[-1])
        if answer.get("unsupported"): pytest.skip("directory descriptor capability unavailable")
        assert answer["refused"] and answer["privacy"] and answer["live_descriptors"] == 0, answer
        assert all(row["path"] == str(alias) and row["kind"] in {"stat", "lstat"}
                   for row in answer["accesses"]), answer


@pytest.mark.parametrize("anchored", [False, True], ids=["portable", "descriptor"])
def test_private_alias_root_metadata_is_lazy_and_once_per_operation(tmp_path, monkeypatch, anchored):
    if anchored and not alias_fresh._reference_descriptors():
        pytest.skip("secure reference hashing requires directory descriptor support")
    tmp_path = tmp_path.resolve()
    private = tmp_path / "private"
    private.mkdir()
    target = tmp_path / "public"
    target.write_bytes(b"public fixture")
    calls = []

    def inspected(path, *args, **kwargs):
        if Path(path) == private:
            calls.append(Path(path))
        return os.stat(path, *args, **kwargs)

    monkeypatch.setattr(alias_router, "_owner_home", lambda: tmp_path / "owner")
    monkeypatch.setattr(alias_router, "_home_declarations", lambda: (("ALIAS_TEST_HOME", ".private"),))
    monkeypatch.setattr(alias_router, "os", SimpleNamespace(**{**vars(os), "stat": inspected,
        "environ": {**os.environ, "ALIAS_TEST_HOME": str(private)}}))
    monkeypatch.setattr(alias_fresh, "_reference_descriptors", lambda: anchored)
    operation = alias_fresh._Operation()
    operation.path_guard(str(target))
    operation.verify()
    assert calls == []
    for _ in range(2):
        operation.reference(target)
        operation.entries(tmp_path, identity_only=True)
        operation.verify()
    assert calls == [private]
    assert alias_fresh.file_ref(target)["sha256"] == hashlib.sha256(b"public fixture").hexdigest()
    assert calls == [private, private]


@pytest.mark.parametrize("failure", ["denied", "zero-inode"])
def test_private_alias_root_metadata_failure_is_a_fixed_cli_refusal(tmp_path, monkeypatch, capsys, failure):
    tmp_path = tmp_path.resolve()
    private = tmp_path / "private"
    private.mkdir()
    target = tmp_path / "brief.md"
    target.write_bytes(b"not consumed")
    calls = []

    def inspected(path, *args, **kwargs):
        if Path(path) == private:
            calls.append(Path(path))
            if failure == "denied":
                raise PermissionError("SECRET_FROM_UNTRUSTED_OS_ERROR")
            return SimpleNamespace(st_dev=1, st_ino=0)
        return os.stat(path, *args, **kwargs)

    monkeypatch.setattr(alias_router, "_owner_home", lambda: tmp_path / "owner")
    monkeypatch.setattr(alias_router, "_home_declarations", lambda: (("ALIAS_TEST_HOME", ".private"),))
    monkeypatch.setattr(alias_router, "os", SimpleNamespace(**{**vars(os), "stat": inspected,
        "environ": {**os.environ, "ALIAS_TEST_HOME": str(private)}}))
    expected = ("cannot determine private directory identity" if failure == "denied"
                else "private directory identity unavailable")
    operation = alias_fresh._Operation()
    for _ in range(2):
        with pytest.raises(ValueError, match="^" + expected + "$"):
            operation.reference(target)
    assert calls == [private]
    for _ in range(2):
        assert alias_fresh.main(["verify", "--path", str(target), "--sha256", "0" * 64]) == 2
        output = capsys.readouterr()
        assert output.err == ""
        assert json.loads(output.out) == {"error": expected}
    # Failure belongs to its operation; a later operation can capture a repaired trusted root.
    monkeypatch.setattr(alias_router, "os", SimpleNamespace(**{**vars(os),
        "environ": {**os.environ, "ALIAS_TEST_HOME": str(private)}}))
    assert alias_fresh.file_ref(target)["sha256"] == hashlib.sha256(b"not consumed").hexdigest()


@pytest.mark.parametrize("anchored", [False, True], ids=["portable", "descriptor"])
def test_private_alias_change_during_read_refuses_and_does_not_poison_next_operation(tmp_path, anchored):
    _privacy_parent_swap_during_read_checks_ancestors_before_metadata(
        tmp_path, "descriptor" if anchored else "portable")


LATCH_STATES = list(itertools.product((False, True), repeat=3))
LATCH_OUTCOMES = list(itertools.product(('missing', 'failed', 'proved'),
                                       ('enter', 'exit', 'ok'), (True, False)))


LATCH_PROJECT_DRIVER = r'''
import json, sys
from contextlib import contextmanager
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import hierarchy_small_change_dispatch as dispatch
from hierarchy_lifecycle import Lifecycle
from hierarchy_workspace import Store

lifecycle, store, recipes, mailbox, lock, mutate = sys.argv[2:8]
race = sys.argv[8] if len(sys.argv) > 8 else None
mutate = mutate == 'True'
observed = {'proofs': 0, 'finalizers': [], 'custody': [], 'locks': [], 'unknown': None, 'resolved': None, 'routed': None,
            'race': False, 'exit_collections': None, 'collections': None}
proof_tokens = {}

def collections(frame):
    while frame is not None:
        if frame.f_code.co_filename == dispatch.__file__ and frame.f_code.co_name == 'project':
            values = frame.f_locals
            return {'rows': [row['request_id'] for row in values['rows']],
                    'custody': [facts.request_id for facts in values['custody']],
                    'contexts': [holder.key for holder in values['contexts']],
                    'released': [facts.released for facts in values['custody']]}
        frame = frame.f_back
    raise AssertionError('project collection frame is missing')

original_lock = dispatch.writer_lock
@contextmanager
def writer_lock(root):
    assert Path(root) == Path(mailbox)
    observed['locks'].append('enter')
    if lock == 'enter':
        raise OSError('table writer lock enter refusal')
    with original_lock(root):
        yield
    observed['locks'].append('exit')
    observed['exit_collections'] = collections(sys._getframe())
    if lock == 'exit':
        raise OSError('table writer lock exit refusal')
dispatch.writer_lock = writer_lock  # Only this module's OS-lock reference.

if race:
    import subprocess
    original_journal_lock = dispatch.router.writer_lock
    @contextmanager
    def journal_lock(root):
        frame, final_snapshot = sys._getframe(), False
        while frame is not None:
            if frame.f_code.co_filename == dispatch.__file__ and frame.f_code.co_name == 'project':
                final_snapshot = 'final' in frame.f_locals
                break
            frame = frame.f_back
        if final_snapshot and not observed['race']:
            observed['race'] = True
            # The concurrent writer uses the real public lifecycle recorder in
            # another process, before this final snapshot acquires its lock.
            program = ('import json,sys\nfrom pathlib import Path\nsys.path.insert(0,sys.argv[1])\n'
                       'from hierarchy_lifecycle import Lifecycle\nfrom hierarchy_mailbox import digest\n'
                       'ledger=Lifecycle(Path(sys.argv[2]))\n'
                       'for value in json.loads(Path(sys.argv[3]).read_text()):\n'
                       '    event=value["event"]\n'
                       '    if event["type"] == "small_change_admit":\n'
                       '        row=ledger.load()[1]["requests"][event["request_id"]]\n'
                       '        event["decision_sha256"]=digest(row["small_change"]["decisions"][-1])\n'
                       '    ledger.record(value)\n')
            child = subprocess.run([sys.executable, '-I', '-B', '-c', program, sys.argv[1], lifecycle, race],
                                   capture_output=True, text=True, timeout=30)
            assert child.returncode == 0 and not child.stderr, (child.stdout, child.stderr)
        with original_journal_lock(root):
            yield
    dispatch.router.writer_lock = journal_lock  # Only the reader module's OS-lock reference.

def observe(frame, event, value):
    if event != 'return':
        return
    if frame.f_code.co_filename == dispatch.__file__ and frame.f_code.co_name == 'project':
        observed['collections'] = collections(frame)
    if frame.f_code.co_filename == dispatch.fresh.__file__ and frame.f_code.co_name == 'prove':
        if value is not None:
            observed['proofs'] += 1
            proof_tokens[id(frame.f_locals['self'])] = value
    if frame.f_code.co_filename == dispatch.__file__ and frame.f_code.co_name == 'finalize_writer_release':
        holder = frame.f_locals['self']
        token = proof_tokens.get(id(holder.operation))
        observed['finalizers'].append({'proof': token is not None and token is holder._verification_proof,
            'clear': frame.f_locals['clear_only'], 'released': bool(value and value.released)})
    if frame.f_code.co_filename == dispatch.__file__ and frame.f_code.co_name == 'run':
        row = frame.f_locals['self'].row
        observed.update(unknown=bool(row.get('lifecycle_unknown')), resolved=row['resolution'] is not None,
                        routed=row['routed'] is not None)
    if frame.f_code.co_filename == dispatch.__file__ and frame.f_code.co_name in {'run', 'clear_writer_release'}:
        holder = frame.f_locals['self']
        token = proof_tokens.get(id(holder.operation))
        facts = holder._custody
        if facts is not None:
            observed['custody'].append({'released': facts.released,
                'proof': token is not None and token is holder._verification_proof})

previous = sys.getprofile()
try:
    sys.setprofile(observe)
    result = dispatch.project(Lifecycle(Path(lifecycle)), Store(Path(store)), recipes=Path(recipes),
                              wait=0.1, mutate=mutate)
finally:
    sys.setprofile(previous)
print(json.dumps({'result': result, 'observed': observed}))
'''


def latch_unknown_event(world):
    """A correlated, hash-valid historical refusal, matching the replay fixtures."""
    paths = sorted((world.ledger.path / 'events').glob('*.json'))
    previous = json.loads(paths[-1].read_text())
    value = {'request_sha256': raw_request(world.change.value)['sha256'], 'intent_id': 'table-unknown',
             'outcome': 'passed', 'exit_code': 'invalid', 'source': SOURCE, 'evidence': world.ledger.evidence}
    envelope = {'id': 'table-unknown', 'actor': world.ledger.operator, 'generation': 1,
                'custody': {'cid': world.ledger.root_actor, 'generation': 1},
                'event': {'type': 'terminal', **world.ledger.target(world.change.value), 'result': raw_request(value)}}

    def sha(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                         ensure_ascii=True).encode()).hexdigest()

    record = {**previous, 'sequence': previous['sequence'] + 1, 'previous': sha(previous),
              'envelope': envelope, 'event_sha256': sha(envelope)}
    (paths[-1].parent / ('%06d.json' % record['sequence'])).write_text(json.dumps(record))


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='real dispatcher fixtures require Linux process evidence')
@pytest.mark.parametrize('routed,resolved,unknown', LATCH_STATES,
                         ids=['routed-%s-resolved-%s-unknown-%s' % state for state in LATCH_STATES])
def test_latch_release_invariant_table(tmp_path, routed, resolved, unknown):
    from tests.integration.test_hierarchy_small_change_dispatch import DispatchWorld

    folder = tmp_path / 'world'
    folder.mkdir()
    world = DispatchWorld(folder)
    initial = world.dispatch()
    assert initial['small_changes'][0]['writer_publication_verified'] is True, initial
    writer_packet = Path(world.messages('dispatch')[0]['message']['brief']['path'])
    if not routed:
        last = sorted((world.ledger.path / 'events').glob('*.json'))[-1]
        assert json.loads(last.read_text())['envelope']['event']['type'] == 'route'
        last.unlink()  # Model retained delivery without the final journal receipt.
    if resolved:
        world.ledger.event('disposition', status='FINAL', resolution={'kind': 'next',
            'request': raw_request(request('table-next')), 'evidence': world.ledger.evidence},
            **world.ledger.target(world.change.value))
    if unknown:
        latch_unknown_event(world)
    snapshot = tmp_path / 'snapshot'
    shutil.copytree(folder, snapshot, symlinks=True)
    for verification, lock, mutate in LATCH_OUTCOMES:
        # Restore at the SAME path: durable references remain genuine absolute
        # paths. Only owned fixture directories are replaced between scenarios.
        shutil.rmtree(folder)
        shutil.copytree(snapshot, folder, symlinks=True)
        if verification == 'failed':
            writer_packet.write_bytes(b'table changed writer attachment\n')
        elif verification == 'missing':
            writer_packet.unlink()
        process = subprocess.run([sys.executable, '-I', '-B', '-c', LATCH_PROJECT_DRIVER, str(ROOT / 'tools'),
            str(world.ledger.path), str(world.workspace.store), str(world.recipes_path), str(world.root),
            lock, str(mutate)], capture_output=True, text=True, timeout=30)
        scenario = (routed, resolved, unknown, verification, lock, mutate)
        assert process.returncode == 0 and not process.stderr, (scenario, process.stdout, process.stderr)
        answer = json.loads(process.stdout)
        result, observed = answer['result'], answer['observed']
        expected = (verification == 'proved' and not resolved and not unknown and (routed or mutate)
                    and (not mutate or lock == 'ok'))
        rows = [row for row in result['small_changes'] if row['request_id'] == world.change.value['id']]
        assert len(rows) == 1, (scenario, answer)
        row = rows[0]
        finalizers = observed['finalizers']
        assert all(not facts['released'] or facts['proof'] for facts in finalizers + observed['custody']), (scenario, answer)
        assert bool(row.get('route_receipt') and row.get('writer_publication_verified')) == expected, (scenario, answer)
        assert result['planning_exclusions'].count('engine/lane/fix') == (0 if expected else 1), (scenario, answer)
        collected = observed['collections']
        identifiers = [world.change.value['id']]
        assert collected['rows'] == collected['custody'] == collected['contexts'] == identifiers, (scenario, answer)
        assert collected['released'] == [expected], (scenario, answer)
        if mutate and lock != 'enter':
            before_exit = observed['exit_collections']
            assert before_exit['rows'] == before_exit['custody'] == before_exit['contexts'] == identifiers, (scenario, answer)
            if lock == 'exit' and verification == 'proved' and routed and not resolved and not unknown:
                assert before_exit['released'] == [True], (scenario, answer)
        if expected:
            assert observed['proofs'] == 1, (scenario, answer)
            assert sum(facts['released'] for facts in finalizers) == 1, (scenario, answer)
            assert row['state'] != 'held', (scenario, answer)
        else:
            assert row['state'] == 'held', (scenario, answer)
            assert not finalizers[-1]['released'], (scenario, answer)
            if verification != 'proved' and not resolved and not unknown and (not mutate or lock == 'ok'):
                assert any(facts['clear'] for facts in finalizers), (scenario, answer)
                assert any(not facts['clear'] for facts in finalizers), (scenario, answer)
        if not mutate:
            assert observed['locks'] == [], (scenario, answer)
        if observed['unknown'] is not None:
            assert observed['unknown'] == unknown and observed['resolved'] == resolved, (scenario, answer)


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='real dispatcher fixtures require Linux process evidence')
@pytest.mark.parametrize('mutate', [False, True], ids=['read', 'mutate'])
@pytest.mark.parametrize('race', ['new-request', 'new-decision'])
@pytest.mark.parametrize('verification', ['proved', 'failed'])
def test_latch_snapshot_race_table(tmp_path, race, mutate, verification):
    from tests.integration.test_hierarchy_small_change_dispatch import DispatchWorld

    world = DispatchWorld(tmp_path)
    world.dispatch()
    directory = world.ledger.path / 'events'
    before = set(directory.glob('*.json'))
    if race == 'new-request':
        change = SmallChange(world.ledger, request('table-raced-request'))
        change.plan['plan']['writing_lanes'][0]['lane'] = 'other'
        change.register()
        change.decide()
        change.admit()
        world.ledger.event('route', actor='router-1', to='engine/lane/other',
                           **world.ledger.target(change.value))
    else:
        world.ledger.event('decision', actor=world.ledger.root_actor, decision='deny',
                           reason='table decision changed after verification',
                           **world.ledger.target(world.change.value))
    appended = sorted(set(directory.glob('*.json')) - before)
    events = [json.loads(path.read_text())['envelope'] for path in appended]
    for path in appended:
        path.unlink()
    packet = tmp_path / 'race-events.json'
    packet.write_text(json.dumps(events))
    if verification == 'failed':
        writer_packet = Path(world.messages('dispatch')[0]['message']['brief']['path'])
        writer_packet.write_bytes(b'table failed writer before snapshot race\n')
    before_race = world.dispatch(command='status')['small_changes'][0]
    process = subprocess.run([sys.executable, '-I', '-B', '-c', LATCH_PROJECT_DRIVER, str(ROOT / 'tools'),
        str(world.ledger.path), str(world.workspace.store), str(world.recipes_path), str(world.root),
        'ok', str(mutate), str(packet)], capture_output=True, text=True, timeout=45)
    assert process.returncode == 0 and not process.stderr, (process.stdout, process.stderr)
    answer = json.loads(process.stdout)
    result, observed = answer['result'], answer['observed']
    assert observed['race'] and observed['proofs'] == (1 if verification == 'proved' else 0), answer
    canonical = world.ledger.status()
    if race == 'new-request':
        assert canonical['requests'][change.value['id']]['routed'] is not None, canonical
    else:
        decisions = [value for value in canonical['decisions'] if value['request_id'] == world.change.value['id']]
        assert decisions[-1]['decision'] == 'deny', canonical
    assert result['planning_exclusions'].count('engine/lane/fix') == 1, answer
    row = result['small_changes'][0]
    assert row['state'] == 'held' and not row.get('route_receipt') and not row.get('writer_publication_verified'), answer
    if verification == 'failed':
        assert row['reason'] == before_race['reason'] and row['detail'] == before_race['detail'], answer
    if race == 'new-request':
        assert result['planning_exclusions'].count('engine/lane/other') == 1, answer
        assert not any(row.get('writer_publication_verified') for row in result['small_changes']
                       if row['request_id'] == change.value['id']), answer


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='real dispatcher fixtures require Linux process evidence')
@pytest.mark.parametrize('failure', ['review', 'check'])
def test_latch_head_advance_preserves_owner_hold_drafts_and_evidence(tmp_path, failure):
    from tests.integration.test_hierarchy_mailbox import mailbox_snapshot
    from tests.integration.test_hierarchy_small_change_dispatch import (
        DispatchWorld, r13_second_team, ready_reviewer, record_drafts, review_result,
    )

    world = DispatchWorld(tmp_path)
    if failure == 'review':
        review_result(world, ready_reviewer(world), 'reject')
        reason = 'small_change_review_rejected'
    else:
        world.dispatch()
        world.finish_writer()
        world.dispatch()
        job = world.messages('job_request')[0]['message']
        invoke(world.root, 'publish', {'message_id': 'owner-check-refused', 'from': 'engine/root',
            'to': 'engine/orchestrator', 'host': 'host-one', 'session': 'engine/root', 'binding_generation': 1,
            'type': 'job_receipt', 'in_reply_to': job['message_id'], 'body': 'owner retains refused check',
            'receipt': {'state': 'refused', 'reason': 'owner refused original check'}})
        reason = 'small_change_check_failed'
    _other_root, other = r13_second_team(world, 'zz-next-route')
    assert world.change.value['id'] < other.value['id']
    before = world.dispatch(command='status')['small_changes'][0]
    assert before['state'] == 'held' and before['reason'] == reason, before
    assert before['drafts'], before
    assert all(draft['event']['status'] == 'HOLD' and draft['event']['resolution']['kind'] == 'blocked'
               and draft['event']['resolution']['evidence'] for draft in before['drafts']), before
    evidence = {ref['path']: Path(ref['path']).read_bytes() for draft in before['drafts']
                for ref in draft['event']['resolution']['evidence']}
    retained = mailbox_snapshot(world.root)
    original = world.ledger.status()
    answer = world.dispatch()
    canonical = world.ledger.status()
    assert canonical['head'] != original['head'], answer
    assert canonical['requests'][other.value['id']]['routed'] is not None, answer
    assert canonical['requests'][world.change.value['id']] == original['requests'][world.change.value['id']]
    row = answer['small_changes'][0]
    assert row['drafts'] == before['drafts'], (before, answer)
    assert row == before, (before, answer)
    assert mailbox_snapshot(world.root) == retained
    assert {path: Path(path).read_bytes() for path in evidence} == evidence
    assert not row.get('route_receipt') and not row.get('writer_publication_verified'), row
    assert answer['planning_exclusions'].count('engine/lane/fix') == 1, answer
    # Exact envelopes remain consumable through the owner's public recorder.
    record_drafts(world, row)
    resolution = world.change.row()['resolution']
    assert resolution == row['drafts'][-1]['event']['resolution']


LATCH_DRAFT_DRIVER = r'''
import json, sys, subprocess
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, sys.argv[1])
import hierarchy_small_change_dispatch as dispatch
from hierarchy_lifecycle import Lifecycle
from hierarchy_workspace import Store
lifecycle, store, recipes, packet, cause = sys.argv[2:7]
observed = {'injected': False, 'before': None, 'frames': [], 'capture_changed': False}

def boundary():
    frame, holder, names, final = sys._getframe(1), None, [], False
    while frame is not None:
        if frame.f_code.co_filename == dispatch.__file__:
            names.append(frame.f_code.co_name)
            if frame.f_code.co_name == 'run':
                holder = frame.f_locals['self']
            if frame.f_code.co_name == 'project':
                final = 'final' in frame.f_locals
                if final:
                    holder = frame.f_locals['contexts'][0]
        frame = frame.f_back
    return holder, names, final

def inject(holder, names):
    assert holder is not None and holder.view['drafts']
    observed.update(injected=True, before=json.loads(json.dumps(holder.view['drafts'])), frames=names)
    if cause == 'capture':
        # Every pass captures policy, including a check refused before recipes
        # are read. Whitespace changes its witness without changing its policy.
        with (Path(lifecycle) / 'policy.json').open('ab') as stream:
            stream.write(b'\n')
    else:
        program = ('import json,sys\nfrom pathlib import Path\nsys.path.insert(0,sys.argv[1])\n'
                   'from hierarchy_lifecycle import Lifecycle\n'
                   'Lifecycle(Path(sys.argv[2])).record(json.loads(Path(sys.argv[3]).read_text()))\n')
        child = subprocess.run([sys.executable, '-I', '-B', '-c', program, sys.argv[1], lifecycle, packet],
                               capture_output=True, text=True, timeout=30)
        assert child.returncode == 0 and not child.stderr, (child.stdout, child.stderr)

original_os = dispatch.fresh.os
def stat(path, *args, **kwargs):
    holder, names, final = boundary()
    if (not observed['injected'] and holder is not None and holder.view['drafts']
            and ((cause == 'capture' and not final)
                 or (cause == 'release-journal' and 'finalize_writer_release' in names))):
        inject(holder, names)
    return original_os.stat(path, *args, **kwargs)
# Patch only the captured-reader module's OS reference, never the shared os module.
dispatch.fresh.os = SimpleNamespace(**dict(vars(original_os), stat=stat))

original_journal_lock = dispatch.router.writer_lock
@contextmanager
def journal_lock(root):
    holder, names, final = boundary()
    if cause in {'head', 'denial'} and final and not observed['injected']:
        inject(holder, names)
    with original_journal_lock(root):
        yield
dispatch.router.writer_lock = journal_lock

original_lock = dispatch.writer_lock
@contextmanager
def writer_lock(root):
    with original_lock(root):
        yield
    if cause == 'lock-exit':
        # The Row.run frame has returned, but collection is complete before exit.
        frame = sys._getframe(1)
        while frame is not None and frame.f_code.co_name != 'project':
            frame = frame.f_back
        holder = frame.f_locals['current']
        observed.update(injected=True, before=json.loads(json.dumps(holder.view['drafts'])), frames=['lock-exit'])
        raise OSError('draft table lock exit refusal')
dispatch.writer_lock = writer_lock
def observe(frame, event, value):
    if (event == 'return' and frame.f_code.co_filename == dispatch.fresh.__file__
            and frame.f_code.co_name == 'verify'):
        operation = frame.f_locals.get('self')
        if isinstance(getattr(operation, 'validation_failure', None), dispatch.fresh.CaptureChanged):
            observed['capture_changed'] = True
previous = sys.getprofile()
try:
    sys.setprofile(observe)
    result = dispatch.project(Lifecycle(Path(lifecycle)), Store(Path(store)), recipes=Path(recipes), wait=0.1, mutate=True)
finally:
    sys.setprofile(previous)
print(json.dumps({'result': result, 'observed': observed}))
'''


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='real dispatcher fixtures require Linux process evidence')
@pytest.mark.parametrize('case', ['final', 'resolve', 'review-hold', 'check-hold'])
@pytest.mark.parametrize('cause', ['head', 'denial', 'capture', 'release-journal', 'lock-exit'])
def test_latch_draft_invalidation_table(tmp_path, case, cause):
    from tests.integration.test_hierarchy_mailbox import mailbox_snapshot
    from tests.integration.test_hierarchy_small_change_dispatch import DispatchWorld, ready_reviewer, review_result

    world = DispatchWorld(tmp_path)
    if case == 'check-hold':
        world.dispatch()
        world.finish_writer()
        world.dispatch()
        job = world.messages('job_request')[0]['message']
        invoke(world.root, 'publish', {'message_id': 'draft-check-refused', 'from': 'engine/root',
            'to': 'engine/orchestrator', 'host': 'host-one', 'session': 'engine/root', 'binding_generation': 1,
            'type': 'job_receipt', 'in_reply_to': job['message_id'], 'body': 'owner retains refused check',
            'receipt': {'state': 'refused', 'reason': 'owner refused original check'}})
    else:
        reviewer = ready_reviewer(world)
        if case == 'resolve':
            world.ledger.event('disposition', status='HOLD', resolution={'kind': 'blocked', 'owner': 'owner',
                'next_decision': 'review', 'condition': 'owner waiting for review', 'evidence': world.ledger.evidence},
                **world.ledger.target(world.change.value))
        review_result(world, reviewer, 'reject' if case == 'review-hold' else 'accept')
    other = request('draft-other-team', team='docs')
    world.ledger.publish(other)
    before = world.dispatch(command='status')['small_changes'][0]
    assert before['drafts'], before
    terminal = before['drafts'][-1]['event']
    if case in {'final', 'resolve'}:
        assert terminal['type'] == ('disposition' if case == 'final' else 'resolve'), before
        assert terminal['resolution']['kind'] == 'complete', before
    else:
        assert terminal['status'] == 'HOLD' and terminal['resolution']['kind'] == 'blocked', before
    evidence = {ref['path']: Path(ref['path']).read_bytes() for draft in before['drafts']
                for ref in draft['event'].get('evidence', draft['event'].get('resolution', {}).get('evidence', []))}
    retained = mailbox_snapshot(world.root)
    # Prepare a real public journal envelope, then retain it for the concurrent
    # recorder to append at the chosen OS boundary rather than before the pass.
    events = world.ledger.path / 'events'
    previous = set(events.glob('*.json'))
    target = world.change.value if cause == 'denial' else other
    world.ledger.event('decision', actor=world.ledger.root_actor,
        decision='deny' if cause == 'denial' else 'approve', reason='draft table concurrent decision',
        **world.ledger.target(target))
    added = set(events.glob('*.json')) - previous
    assert len(added) == 1
    path = added.pop()
    packet = tmp_path / 'draft-race.json'
    packet.write_text(json.dumps(json.loads(path.read_text())['envelope']))
    path.unlink()
    process = subprocess.run([sys.executable, '-I', '-B', '-c', LATCH_DRAFT_DRIVER, str(ROOT / 'tools'),
        str(world.ledger.path), str(world.workspace.store), str(world.recipes_path), str(packet), cause],
        capture_output=True, text=True, timeout=60)
    assert process.returncode == 0 and not process.stderr, (process.stdout, process.stderr)
    answer = json.loads(process.stdout)
    row, observed = answer['result']['small_changes'][0], answer['observed']
    assert observed['injected'] and observed['before'] == before['drafts'], answer
    if cause in {'capture', 'release-journal'}:
        assert observed['capture_changed'], answer
    if cause == 'capture':
        assert 'release_validation_error' in row, answer
    if cause == 'release-journal':
        assert 'finalize_writer_release' in observed['frames'] and 'run' in observed['frames'], answer
        if case.endswith('hold'):
            assert 'release_validation_error' in row, answer
    assert row['state'] in {'held', 'owned_hold'}, answer
    if case.endswith('hold'):
        assert row['drafts'] == before['drafts'], answer
    else:
        assert row['drafts'] == [], answer
        expected_reason = {'head': 'small_change_snapshot_changed', 'denial': 'small_change_revoked',
            'capture': 'small_change_configuration', 'release-journal': 'small_change_configuration',
            'lock-exit': 'small_change_configuration'}[cause]
        assert row['reason'] == expected_reason, answer
    assert not row.get('route_receipt') and not row.get('writer_publication_verified'), answer
    assert mailbox_snapshot(world.root) == retained
    assert {path: Path(path).read_bytes() for path in evidence} == evidence


def assert_draft_invalidation_structure(source):
    """Draft creation is explicit; only invalidate may replace existing drafts."""
    tree = ast.parse(source)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    creation = {'Row.__init__', 'Row.progress', 'Row.run'}

    def scope(node):
        names = []
        while node in parents:
            node = parents[node]
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                names.append(node.name)
        return '.'.join(reversed(names))

    def view(node):
        return (isinstance(node, ast.Attribute) and node.attr == 'view' and isinstance(node.value, ast.Name)
                and node.value.id == 'self')

    invalidators = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == 'invalidate' and scope(node) == 'Row']
    assert len(invalidators) == 1 and isinstance(invalidators[0], ast.FunctionDef), (
        'draft invalidation must have one synchronous policy function')
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == 'drafts':
            raise AssertionError(('draft keyword write is not creation', node.lineno))
        if not isinstance(node, ast.Constant) or node.value != 'drafts':
            continue
        parent, owner = parents[node], scope(node)
        if isinstance(parent, ast.Dict) and node in parent.keys:
            assignment = parents[parent]
            assert (owner == 'Row.__init__' and isinstance(assignment, ast.Assign)
                    and len(assignment.targets) == 1 and view(assignment.targets[0])
                    and isinstance(parent.values[parent.keys.index(node)], ast.List)
                    and not parent.values[parent.keys.index(node)].elts), ('draft initialization', node.lineno)
            continue
        assert isinstance(parent, ast.Subscript) and parent.slice is node and view(parent.value), (
            'draft access is not admitted', node.lineno)
        statement = parents[parent]
        if isinstance(parent.ctx, ast.Store):
            assert isinstance(statement, ast.Assign) and statement.targets == [parent], ('draft assignment', node.lineno)
            assert owner in creation | {'Row.invalidate'}, ('draft write outside creation/invalidation', node.lineno)
            if owner != 'Row.invalidate':
                value = statement.value
                assert (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
                        and isinstance(value.func.value, ast.Name) and value.func.value.id == 'self'
                        and value.func.attr == 'drafts' and not value.keywords
                        and len(value.args) == 1 and not isinstance(value.args[0], ast.Starred)), (
                            'draft creation must use the draft builder', node.lineno)
        else:
            assert isinstance(parent.ctx, ast.Load) and (owner == 'Row.invalidate' or (
                owner == 'Row.run' and isinstance(statement, ast.UnaryOp) and isinstance(statement.op, ast.Not))), (
                    'draft alias or mutation outside invalidation', node.lineno)


def test_latch_draft_writes_are_creation_or_central_invalidation():
    assert_draft_invalidation_structure((ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8'))


def test_latch_draft_structure_rejects_async_policy_shadow():
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    source = latch_insert(source, 'Row', 'async def invalidate(self, reason, detail):\n    pass')
    with pytest.raises(AssertionError, match='draft invalidation'):
        assert_draft_invalidation_structure(source)


@pytest.mark.parametrize('snippet', [
    'self.view["drafts"] = []', 'self.view.update(drafts=[])',
    'self.view.update({"drafts": []})', 'self.view["drafts"].clear()',
    'alias = self.view["drafts"]; alias.clear()', 'del self.view["drafts"]',
    'self.view["drafts"] += []', 'self.view["drafts"][:] = []',
])
def test_latch_draft_structure_rejects_scattered_invalidation(snippet):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    with pytest.raises(AssertionError, match='draft'):
        assert_draft_invalidation_structure(latch_insert(source, 'Row.run', snippet))


def assert_latch_release_structure(source):
    """Allow only explicit view producers, consumers and mutations.

    This is a secondary syntax barrier. The real project() table determines
    release outcomes, including side effects and skipped collection.
    """
    tree = ast.parse(source)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    keys = {'route_receipt', 'writer_publication_verified'}
    scopes = (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    writes, writers, initializers, collections = [], set(), [], []

    def ancestors(node):
        chain = []
        while node in parents:
            node = parents[node]
            chain.append(node)
        return chain

    def qualified(node):
        return '.'.join(item.name for item in reversed(ancestors(node)) if isinstance(item, scopes))

    def name(node, value):
        return isinstance(node, ast.Name) and node.id == value

    def string(node):
        return isinstance(node, ast.Constant) and isinstance(node.value, str)

    def view(node):
        return isinstance(node, ast.Attribute) and node.attr == 'view' and name(node.value, 'self')

    def literal_keys(node):
        return isinstance(node, ast.Dict) and all(string(key) for key in node.keys)

    def rows_append(call):
        return (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and name(call.func.value, 'rows') and call.func.attr == 'append'
                and len(call.args) == 1 and not call.keywords and qualified(call) == 'project')

    def run_call(call):
        return (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == 'run'
                and (name(call.func.value, 'current') or (isinstance(call.func.value, ast.Call)
                     and name(call.func.value.func, 'context') and not call.func.value.args
                     and not call.func.value.keywords))
                and len(call.args) == 1 and isinstance(call.args[0], ast.Constant)
                and type(call.args[0].value) is bool and not call.keywords)

    # There is no admitted reflective spelling of the protected view. Reject
    # opaque reflection primitives too, including aliases to those primitives.
    reflection = {'getattr', 'setattr', 'vars', 'eval', 'exec', 'globals', 'locals'}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr.startswith('__'):
            parent = parents[node]
            # All special attribute access requires an admitted shape. This
            # includes protocols reached indirectly through a bound method.
            assert (qualified(node) == 'Hold.__init__' and node.attr == '__init__'
                    and isinstance(node.value, ast.Call) and name(node.value.func, 'super')
                    and not node.value.args and not node.value.keywords
                    and isinstance(parent, ast.Call) and parent.func is node
                    and len(parent.args) == 1 and name(parent.args[0], 'detail') and not parent.keywords), (
                        'release reflection: unadmitted special attribute', node.lineno)
        if isinstance(node, ast.Attribute) and node.attr == 'project':
            raise AssertionError(('release producer result escape', node.lineno))
        if ((isinstance(node, ast.Name) and node.id in reflection)
                or (isinstance(node, ast.Attribute) and node.attr in reflection | {
                    '__dict__', '__getattribute__', '__setattr__'})
                or (string(node) and node.value == 'view')
                or (isinstance(node, ast.keyword) and node.arg == 'view')):
            raise AssertionError(('release reflection is not admitted', node.lineno))

    producers = {key: [] for key in ('Row', 'Row.run', 'Row.finalize_writer_release', 'project', 'exclusions')}
    returns = []
    for node in ast.walk(tree):
        scope = qualified(node)
        if isinstance(node, scopes):
            identity = '.'.join(part for part in (scope, node.name) if part)
            if identity in producers:
                producers[identity].append(node)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and node.id in {'Row', 'project', 'exclusions'}:
            raise AssertionError(('release producer rebinding', node.lineno))
        if scope == 'Row.run' and isinstance(node, ast.Return):
            assert view(node.value), ('release producer must return its protected view', node.lineno)
            returns.append(node)
        if scope == 'Row.run' and isinstance(node, (ast.Yield, ast.YieldFrom)):
            raise AssertionError(('release producer cannot yield a view', node.lineno))
    assert all(len(definitions) == 1 for definitions in producers.values()), ('release producer definitions', producers)
    run = producers['Row.run'][0]
    assert (isinstance(run, ast.FunctionDef) and len(returns) == 1 and run.body[-1] is returns[0]), (
        'release producer must have one final return')

    row_class = producers['Row'][0]
    methods = {node.name for node in row_class.body if isinstance(node, ast.FunctionDef)}
    assert all(node.args.args and node.args.args[0].arg == 'self'
               for node in row_class.body if isinstance(node, ast.FunctionDef)), 'release holder parameter'
    assert not row_class.bases and not row_class.decorator_list, 'release holder definition'
    assert all(not method.startswith('__') or method == '__init__' for method in methods), (
        'release holder protocols are not admitted')
    # A positive list of ordinary fields and methods, rather than a list of
    # known state-exposing protocols. New holder attributes require review.
    holder_fields = {
        '_completed_checks', '_custody', '_retained_jobs', '_verification_proof',
        '_writer_receipt', '_writer_target_current', '_writer_verified', 'accepted',
        'change', 'initiative', 'key', 'ledger', 'lifecycle', 'mailbox', 'operation',
        'plan', 'policy', 'proofs', 'recipes', 'records', 'result_record',
        'review_not_before', 'reviewer', 'row', 'running_checks', 'setup', 'state',
        'store', 'team', 'view', 'wait', 'writer',
    }

    # Views leave Row only through run() and the project rows collection.
    # The custody consumer has no presentation alias.
    for node in ast.walk(tree):
        parent = parents.get(node)
        scope = qualified(node)
        if isinstance(node, ast.Name) and node.id == 'project' and isinstance(node.ctx, ast.Load):
            raise AssertionError(('release producer result escape', node.lineno))
        if isinstance(node, ast.Name) and node.id == 'context' and isinstance(node.ctx, ast.Load) and scope == 'project':
            statement = parents.get(parent)
            assert (isinstance(parent, ast.Call) and parent.func is node
                    and isinstance(statement, ast.Assign) and len(statement.targets) == 1
                    and name(statement.targets[0], 'current')), ('release view escape through context', node.lineno)
        if isinstance(node, ast.Name) and node.id == 'self' and scope.startswith('Row.'):
            allowed = (isinstance(parent, ast.Attribute) and parent.value is node
                       and parent.attr in holder_fields | methods)
            allowed = allowed or (isinstance(parent, ast.Call) and name(parent.func, 'hasattr')
                and len(parent.args) == 2 and parent.args[0] is node and string(parent.args[1])
                and parent.args[1].value == 'result_record' and not parent.keywords
                and scope == 'Row.foreign_publications')
            assert allowed, ('release view escape through holder', node.lineno)
            if isinstance(parent, ast.Attribute) and parent.attr in methods:
                use = parents[parent]
                direct = isinstance(use, ast.Call) and use.func is parent
                callback = (isinstance(use, ast.Call) and isinstance(use.func, ast.Attribute)
                    and ((parent.attr in {'recheck_jobs', 'recheck_dependencies'} and use.func.attr == 'append')
                         or (parent.attr == 'verification_pass' and use.func.attr == 'prove')))
                callback = callback or (parent.attr == 'publication_authority' and isinstance(use, ast.Assign)
                                        and scope == 'Row.verification_pass')
                assert direct or callback, ('release view escape through bound method', node.lineno)
        if isinstance(node, ast.Name) and node.id == 'current' and scope == 'project' and isinstance(node.ctx, ast.Load):
            allowed = (isinstance(parent, ast.Attribute) and parent.value is node
                       and parent.attr in holder_fields | methods)
            allowed = allowed or (isinstance(parent, ast.Compare) and parent.left is node
                and len(parent.ops) == 1 and isinstance(parent.ops[0], ast.Is)
                and len(parent.comparators) == 1 and isinstance(parent.comparators[0], ast.Constant)
                and parent.comparators[0].value is None)
            allowed = allowed or (isinstance(parent, ast.Call) and name(parent.func, 'exclusions')
                and len(parent.args) == 2 and parent.args[0] is node and name(parent.args[1], 'custody')
                and not parent.keywords)
            allowed = allowed or (isinstance(parent, ast.Call) and isinstance(parent.func, ast.Attribute)
                and name(parent.func.value, 'contexts') and parent.func.attr == 'append'
                and parent.args == [node] and not parent.keywords)
            allowed = allowed or (isinstance(parent, ast.Assign)
                and ast.dump(parent, include_attributes=False) == ast.dump(
                    ast.parse('contexts[-1] = current').body[0], include_attributes=False))
            assert allowed, ('release view escape through current', node.lineno)
        if isinstance(node, ast.Name) and node.id == 'view':
            raise AssertionError(('release view escape or mutation of alias', node.lineno))
        if isinstance(node, ast.Name) and node.id == 'rows':
            allowed = False
            if isinstance(node.ctx, ast.Store):
                allowed = (scope == 'project' and isinstance(parent, ast.Assign) and parent.targets == [node]
                           and isinstance(parent.value, ast.List) and not parent.value.elts)
                if allowed:
                    collections.append(parent)
            elif isinstance(node.ctx, ast.Load):
                if scope == 'project':
                    if isinstance(parent, ast.Attribute):
                        call = parents[parent]
                        if rows_append(call):
                            value = call.args[0]
                            allowed = run_call(value) or (isinstance(value, ast.Attribute)
                                      and name(value.value, 'current') and value.attr == 'view')
                    elif isinstance(parent, ast.Dict) and isinstance(parents[parent], ast.Return):
                        allowed = any(value is node and string(key) and key.value == 'small_changes'
                                      for key, value in zip(parent.keys, parent.values))
            assert allowed, ('release view escape through rows', node.lineno)
        if isinstance(node, ast.Attribute) and node.attr == 'run':
            call = parent
            assert (scope == 'project' and run_call(call) and call.func is node
                    and ((rows_append(parents[call]) and parents[call].args == [call])
                         or isinstance(parents[call], ast.Expr))), (
                        'release view escape through run result', node.lineno)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute) or node.attr != 'view':
            continue
        parent, scope = parents[node], qualified(node)
        assert ((name(node.value, 'self') and scope.startswith('Row.'))
                or (name(node.value, 'current') and scope == 'project')), (
                    'release view receiver is not admitted', node.lineno)
        if isinstance(node.ctx, ast.Store):
            assert (scope == 'Row.__init__' and isinstance(parent, ast.Assign) and parent.targets == [node]
                    and literal_keys(parent.value)), ('unrecognized release view replacement', node.lineno)
            initializers.append(parent)
        elif isinstance(parent, ast.Subscript) and parent.value is node:
            assert string(parent.slice), ('unrecognized release view key', node.lineno)
            if not isinstance(parent.ctx, ast.Load):
                statement = parents[parent]
                assert (isinstance(parent.ctx, ast.Store) and isinstance(statement, ast.Assign)
                        and statement.targets == [parent]), ('unrecognized release subscript mutation', node.lineno)
        elif isinstance(parent, ast.Attribute):
            call = parents[parent]
            assert isinstance(call, ast.Call) and call.func is parent, ('unrecognized release view method', node.lineno)
            if parent.attr == 'update':
                assert (len(call.args) <= 1 and all(literal_keys(arg) for arg in call.args)
                        and all(keyword.arg is not None for keyword in call.keywords)), (
                            'unrecognized release view update', node.lineno)
            elif parent.attr == 'get':
                assert (1 <= len(call.args) <= 2 and string(call.args[0]) and not call.keywords), (
                    'unrecognized release view read', node.lineno)
            else:
                assert (parent.attr == 'pop' and scope == 'Row.finalize_writer_release'
                        and len(call.args) == 2 and string(call.args[0])
                        and isinstance(call.args[1], ast.Constant) and call.args[1].value is None
                        and not call.keywords and isinstance(parents[call], ast.Expr)), (
                            'unrecognized release view call', node.lineno)
        elif isinstance(parent, ast.Return) and view(node) and scope == 'Row.run':
            continue
        else:
            assert (scope == 'project' and name(node.value, 'current') and rows_append(parent)
                    and parent.args == [node]), ('release view escape', node.lineno)

    def proof_read(node):
        return (isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load)
                and name(node.value, 'self') and node.attr == '_verification_proof')

    def positive(test):
        candidates = test.values if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And) else [test]
        return any(isinstance(item, ast.Compare) and proof_read(item.left) and len(item.ops) == 1
                   and isinstance(item.ops[0], ast.IsNot) and len(item.comparators) == 1
                   and isinstance(item.comparators[0], ast.Constant) and item.comparators[0].value is None
                   for item in candidates)

    for token in ast.walk(tree):
        parent = parents.get(token)
        if isinstance(token, ast.keyword) and token.arg in keys:
            raise AssertionError(('unrecognized release keyword', token.arg, token.lineno))
        if isinstance(token, ast.Attribute) and token.attr in keys and isinstance(token.ctx, (ast.Store, ast.Del)):
            raise AssertionError(('unrecognized release attribute write', token.attr, token.lineno))
        if not string(token) or token.value not in keys:
            continue
        removal = False
        if isinstance(parent, ast.Subscript) and parent.slice is token:
            statement = parents[parent]
            assert (view(parent.value) and isinstance(parent.ctx, ast.Store)
                    and isinstance(statement, ast.Assign) and statement.targets == [parent]), (
                        'unrecognized release subscript write', token.lineno)
        elif (isinstance(parent, ast.Call) and parent.args and parent.args[0] is token
              and isinstance(parent.func, ast.Attribute)):
            statement = parents[parent]
            assert (view(parent.func.value) and parent.func.attr == 'pop' and len(parent.args) == 2
                    and isinstance(parent.args[1], ast.Constant) and parent.args[1].value is None
                    and not parent.keywords and isinstance(statement, ast.Expr)), (
                        'unrecognized release mutation call', token.lineno)
            removal = True
        else:
            raise AssertionError(('unrecognized release key use', token.value, token.lineno))
        chain, owner = ancestors(statement), qualified(statement)
        assert owner == 'Row.finalize_writer_release', ('release writer', owner, token.lineno)
        writes.append((owner, token.lineno))
        writers.add(next(node for node in chain if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))))
        if removal:
            continue
        guarded, child = False, statement
        for ancestor in chain:
            if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)):
                break
            if isinstance(ancestor, ast.If):
                assert not (child in ancestor.orelse and any(proof_read(read) for read in ast.walk(ancestor.test))), (
                    'release proof polarity: orelse of proof-reading If', token.lineno)
                guarded = guarded or (child in ancestor.body and positive(ancestor.test))
            child = ancestor
        assert guarded, ('release proof polarity: positive body gate required', token.lineno)

    assert len(initializers) == 1 and len(collections) == 1, ('release view initialization', len(initializers), len(collections))
    assert writes and len(writers) == 1, ('release function definitions', len(writers))
    assert_custody_channel(tree, parents, qualified)
    return writes


def assert_custody_channel(tree, parents, qualified):
    """Secondary syntax checks only; the runtime table owns control-flow safety."""
    def shape(node):
        return ast.dump(node, include_attributes=False)

    def expression(source):
        return shape(ast.parse(source, mode='eval').body)

    last_replacement = shape(ast.parse('custody[-1] = current._custody').body[0])

    def replaces_custody(statement):
        return isinstance(statement, ast.Assign) and shape(statement) == last_replacement

    definitions = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == '_WriterCustody']
    assert len(definitions) == 1, 'release custody record definition'
    record = definitions[0]
    assert (not record.decorator_list and len(record.bases) == 1
            and isinstance(record.bases[0], ast.Name) and record.bases[0].id == 'NamedTuple'), (
                'release custody record must be immutable')
    fields = [node.target.id for node in record.body if isinstance(node, ast.AnnAssign)
              and isinstance(node.target, ast.Name)]
    assert fields == ['request_id', 'writer', 'message_present', 'state_head', 'history_verified', 'released'], (
        'release custody record fields')
    assert all(isinstance(node, ast.AnnAssign) or (
        isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str))
        for node in record.body), 'release custody record body'

    # This small authority consumer admits only this complete parsed shape,
    # including its bindings and calls. Checking selected keyword spellings
    # cannot classify unpacking, aliases or an injected replacement statement.
    consumer = ast.parse('''
def exclusions(state, custody):
    result = {team + "/" + role for team in active_teams(state) for role in ("orchestrator", "decider")}
    captured = set()
    for facts in custody:
        require(type(facts) is _WriterCustody, "unverified writer custody input")
        if facts.state_head != state["head"]:
            continue
        captured.add(facts.request_id)
        row = state["requests"][facts.request_id]
        released = not row.get("lifecycle_unknown") and row["resolution"] is not None and row["resolution"]["kind"] in {"complete", "blocked"}
        if not released and (facts.message_present or row["routed"] is not None) and not facts.released:
            result.add(facts.writer)
    absent = {facts.request_id for facts in custody if facts.state_head == state["head"]
              and facts.history_verified and not facts.message_present}
    for key, row in state["requests"].items():
        if key in absent and not row.get("lifecycle_unknown") and row["intent"] is None and row["start"] is None:
            continue
        canonical_release = closed(row) and row["resolution"]["kind"] in {"complete", "blocked"}
        if "small_change" in row and not canonical_release and (
                key not in captured or row.get("lifecycle_unknown") or row["routed"] is None):
            plan = life.raw_value(row["small_change"]["registration"]["proposal"])["plan"]
            result.add(row["request"]["team"] + "/lane/" + plan["writing_lanes"][0]["lane"])
    return sorted(result)
''').body[0]
    definitions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'exclusions']
    assert len(definitions) == 1 and shape(definitions[0]) == shape(consumer), (
        'release custody consumer has an unadmitted shape')
    constructor = expression('_WriterCustody(self.key, self.writer, identifier("scw", self.row) in self.records, '
                             'self.state["head"], history_verified, released)')
    collection_initializers = []
    for node in ast.walk(tree):
        parent = parents.get(node)
        scope = qualified(node)
        if ((isinstance(node, ast.Attribute) and node.attr == 'finalize_writer_release')
                or (isinstance(node, ast.Name) and node.id == 'finalize_writer_release')):
            assert not isinstance(node.ctx, (ast.Store, ast.Del)), ('release finalizer rebinding', node.lineno)
        if ((isinstance(node, ast.Attribute) and node.attr == '_replace')
                or (isinstance(node, ast.Name) and node.id == '_replace')):
            raise AssertionError(('release custody replacement is not admitted', node.lineno))
        if isinstance(node, ast.Name) and node.id == '_WriterCustody':
            assert isinstance(node.ctx, ast.Load) and (
                (scope == 'Row.finalize_writer_release' and isinstance(parent, ast.Call) and parent.func is node
                 and shape(parent) == constructor and isinstance(parents.get(parent), ast.Return))
                or (scope == 'exclusions' and isinstance(parent, ast.Compare))), 'release custody constructor escape'
        if isinstance(node, ast.alias):
            assert (node.asname or node.name) not in {'_WriterCustody', 'exclusions', 'project', 'Row'}, (
                'release custody import rebinding')
        if isinstance(node, ast.Attribute) and node.attr in {'_custody', '_WriterCustody'}:
            if isinstance(node.ctx, ast.Store):
                admitted = {
                    'Row.__init__': {'None'},
                    'Row.run': {'self.finalize_writer_release()'},
                    'Row.clear_writer_release': {'self.finalize_writer_release(clear_only=True)'},
                }
                assert (isinstance(node.value, ast.Name) and node.value.id == 'self'
                        and isinstance(parent, ast.Assign) and parent.targets == [node]
                        and shape(parent.value) in {expression(value) for value in admitted.get(scope, set())}), (
                            'release custody write', node.lineno)
            else:
                collected = (scope == 'project' and shape(node) == expression('current._custody')
                        and isinstance(parent, ast.Call) and shape(parent) == expression('custody.append(current._custody)')
                        and isinstance(parents[parent], ast.Expr))
                head = (scope == 'project' and isinstance(parent, ast.Attribute)
                        and shape(parent) == expression('current._custody.state_head'))
                replaced = scope == 'project' and replaces_custody(parent)
                assert collected or head or replaced, ('release custody escape', node.lineno)
        if isinstance(node, ast.Name) and node.id == 'custody':
            if scope == 'exclusions':
                continue
            admitted = (scope == 'project' and isinstance(node.ctx, ast.Store)
                        and isinstance(parent, ast.Assign) and parent.targets == [node]
                        and shape(parent.value) == expression('[]'))
            if admitted:
                collection_initializers.append(node)
            if scope == 'project' and isinstance(node.ctx, ast.Load):
                admitted = (isinstance(parent, ast.Attribute) and isinstance(parents[parent], ast.Call)
                            and shape(parents[parent]) == expression('custody.append(current._custody)')
                            and isinstance(parents[parents[parent]], ast.Expr))
                admitted = admitted or (isinstance(parent, ast.Call)
                                        and shape(parent) == expression('exclusions(planning, custody)'))
                statement = parents.get(parent)
                admitted = admitted or (isinstance(parent, ast.Subscript) and replaces_custody(statement))
            assert admitted, ('release custody collection escape', node.lineno)
        if isinstance(node, ast.Name) and node.id == 'exclusions' and isinstance(node.ctx, ast.Load):
            assert (scope == 'project' and isinstance(parent, ast.Call)
                    and shape(parent) == expression('exclusions(planning, custody)')), 'release custody consumer escape'
    assert len(collection_initializers) == 1, 'release custody collection must have one initialization'


def test_latch_release_assignments_require_one_proof_reading_function():
    # Tracked source is ordinary, cross-platform test input.
    assert_latch_release_structure((ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8'))


@pytest.mark.parametrize("damage", ["index-overwrite", "wrong-iterable", "stale-context"])
def test_round10_custody_collection_rejects_misaligned_producers(damage):
    source = (ROOT / "tools/hierarchy_small_change_dispatch.py").read_text(encoding="utf-8")
    assert_latch_release_structure(source)
    if damage == "index-overwrite":
        before = "custody[-1] = current._custody"
        after = "custody[0] = current._custody"
    elif damage == "wrong-iterable":
        before = "exclusions(planning, custody)"
        after = "exclusions(planning, custody[::-1])"
    else:
        before = "custody[-1] = current._custody"
        after = "custody[-1] = contexts[0]._custody"
    assert before in source
    with pytest.raises(AssertionError, match="custody"):
        assert_latch_release_structure(source.replace(before, after, 1))


@pytest.mark.parametrize('line', [
    'self.view.update(route_receipt=self._writer_receipt, writer_publication_verified=True)',
    'self.view.update({"route_receipt": self._writer_receipt})',
    'self.view.setdefault("route_receipt", self._writer_receipt)',
    'self.view.__setitem__("route_receipt", self._writer_receipt)',
    'self.view["route_receipt"] = self.view.pop("route_receipt", None)',
    'self.view["writer_publication_verified"] = self._writer_verified',
    'self.view["writer_publication_verified"] = False',
    'self.view["route_receipt"]: object = self._writer_receipt',
    'self.view["route_receipt"] += self._writer_receipt',
    'del self.view["route_receipt"]',
    'self.view = {"route_receipt": self._writer_receipt}',
    'self.view = dict(writer_publication_verified=self._writer_verified)',
    'setattr(self, "route_receipt", self._writer_receipt)',
    'self.view.route_receipt = self._writer_receipt',
    'key = "route_receipt"; self.view[key] = self._writer_receipt',
    'publish_release(self.view, "route_receipt", self._writer_receipt)',
    'self.view["route_" + "receipt"] = self._writer_receipt',
    'self.view.update(self._writer_fields)',
    'self.view = self._writer_fields',
    'alias = self.view; alias.update(self._writer_fields)',
    'self.view.clear()',
    'self.view |= self._writer_fields',
], ids=['update-keywords', 'update-dict', 'setdefault', 'setitem', 'pop-reassign', 'nonliteral',
        'false-value', 'annotated', 'augmented', 'delete', 'dict-display', 'dict-call', 'setattr',
        'attribute-store', 'key-alias', 'unknown-call', 'computed-key', 'opaque-update',
        'opaque-replacement', 'view-alias', 'clear', 'inplace-update'])
def test_latch_structure_rejects_release_mutations(line):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    source += '\nclass Bypass:\n    def recover(self):\n        ' + line + '\n'
    with pytest.raises(AssertionError, match='release'):
        assert_latch_release_structure(source)


@pytest.mark.parametrize('class_name', ['Bypass', 'Row'])
def test_latch_structure_rejects_same_bare_function_name_in_another_class(class_name):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    source += '''
class CLASS_NAME:
    def finalize_writer_release(self):
        if self._verification_proof is not None:
            self.view["writer_publication_verified"] = True
'''.replace('CLASS_NAME', class_name)
    with pytest.raises(AssertionError, match='release'):
        assert_latch_release_structure(source)


def test_latch_structure_rejects_release_outside_the_proof_if():
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    row = next(node for node in ast.parse(source).body if isinstance(node, ast.ClassDef) and node.name == 'Row')
    release = next(node for node in row.body if isinstance(node, ast.FunctionDef)
                   and node.name == 'finalize_writer_release')
    lines = source.splitlines(keepends=True)
    lines.insert(release.lineno, '        self.view["writer_publication_verified"] = True\n')
    with pytest.raises(AssertionError, match='release'):
        assert_latch_release_structure(''.join(lines))


def latch_insert(source, qualified, snippet):
    """Insert static text before a function's final return, or at a class/body end."""
    tree = ast.parse(source)
    parts = qualified.split('.')
    nodes = tree.body
    for part in parts:
        node = next(item for item in nodes if isinstance(item, (ast.ClassDef, ast.FunctionDef))
                    and item.name == part)
        nodes = node.body
    lines = source.splitlines(keepends=True)
    indent = ' ' * (node.col_offset + 4)
    position = (node.body[-1].lineno - 1 if isinstance(node, ast.FunctionDef)
                and isinstance(node.body[-1], ast.Return) else node.end_lineno)
    lines.insert(position, ''.join(indent + line + '\n' for line in snippet.splitlines()))
    return ''.join(lines)


LATCH_REVIEW_MUTATIONS = (
    'collection-reset', 'skipped-appends', 'self-finalizer-rebind', 'current-finalizer-rebind',
    'class-finalizer-rebind', 'class-field-finalizer-rebind', 'replace-released',
    'walrus-released-assign', 'walrus-released-update', 'walrus-released-condition',
    'walrus-history-assign', 'walrus-history-update', 'walrus-history-condition',
    'argon-forged-proof', 'argon-clear-flags',
)


def latch_review_mutation(source, variant):
    """Trusted reviewer mutation recipes for temporary RED runs, never product configuration."""
    assert variant in LATCH_REVIEW_MUTATIONS

    def once(old, new):
        assert source.count(old) == 1, (variant, old)
        return source.replace(old, new)

    if variant == 'collection-reset':
        line = '    final = fresh._Operation(reference_cache=reference_cache)\n'
        return once(line, '    custody = []\n' + line)
    if variant == 'skipped-appends':
        lines, changed = [], 0
        for line in source.splitlines(keepends=True):
            if line.lstrip().startswith('custody.append('):
                indent = line[:len(line) - len(line.lstrip())]
                lines.extend([indent + 'if False:\n', '    ' + line])
                changed += 1
            else:
                lines.append(line)
        assert changed == 3
        return ''.join(lines)
    if variant == 'self-finalizer-rebind':
        header = '    def run(self, mutate):\n'
        return once(header, header + '        original = self.finalize_writer_release\n'
                    '        self.finalize_writer_release = lambda **kw: original(**kw)._replace(released=True)\n')
    if variant == 'current-finalizer-rebind':
        line = '                        rows.append(current.run(True))\n'
        return once(line, '                        original = current.finalize_writer_release\n'
                    '                        current.finalize_writer_release = lambda **kw: original(**kw)._replace(released=True)\n'
                    + line)
    if variant == 'class-finalizer-rebind':
        header = '    def run(self, mutate):\n'
        return once(header, header + '        original = Row.finalize_writer_release\n'
                    '        Row.finalize_writer_release = lambda holder, **kw: original(holder, **kw)._replace(released=True)\n')
    if variant == 'class-field-finalizer-rebind':
        return latch_insert(source, 'Row', '_original_finalizer = finalize_writer_release\n'
            'def replacement_finalizer(self, **kw):\n'
            '    return self._original_finalizer(**kw)._replace(released=True)\n'
            'finalize_writer_release = replacement_finalizer')
    if variant == 'replace-released':
        return once('history_verified, released)', 'history_verified, released)._replace(released=True)')
    if variant == 'argon-forged-proof':
        line = '        self._verification_proof = None\n        self.clear_writer_release()\n'
        return once(line, line + '        self._verification_proof = True\n'
                    '        self._writer_verified = True\n'
                    '        self._writer_target_current = True\n'
                    '        self._writer_receipt = True\n')
    if variant == 'argon-clear-flags':
        return latch_insert(source, 'Row.finalize_writer_release',
            'if self._verification_proof is not None:\n'
            '    self.view["writer_publication_verified"] = True\n'
            '    self.view["route_receipt"] = self._writer_receipt')
    _, field, form = variant.split('-')
    field = 'history_verified' if field == 'history' else 'released'
    expression = '(' + field + ' := True)'
    snippet = {'assign': 'self.view["state"] = ' + expression,
               'update': 'self.view.update(state=' + expression + ')',
               'condition': 'if ' + expression + ':\n    self.view["state"] = "held"'}[form]
    return latch_insert(source, 'Row.finalize_writer_release', snippet)


@pytest.mark.parametrize('qualified, snippet', [
    ('project', 'custody = []'),
    ('Row.run', 'self.finalize_writer_release = lambda **kw: forged'),
    ('project', 'current.finalize_writer_release = lambda **kw: forged'),
    ('project', 'Row.finalize_writer_release = lambda **kw: forged'),
    ('Row', 'finalize_writer_release = lambda **kw: forged'),
    ('Row.run', 'self.view["state"] = saved._replace(released=True)'),
    ('Row.run', 'self.view["state"] = saved._replace(custody=True)'),
])
def test_latch_secondary_syntax_bans(qualified, snippet):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    with pytest.raises(AssertionError, match='release'):
        assert_latch_release_structure(latch_insert(source, qualified, snippet))


@pytest.mark.parametrize('snippet', [
    'facts = facts._replace(**{"released": True})',
    'changes = {"released": True}; facts = facts._replace(**changes)',
    'facts = facts._replace(**dict([(key, True)]))',
    'facts = facts._replace(*(), **{"released": True})',
    'facts = facts._replace(*arguments)',
    'replace = facts._replace; facts = replace(released=True)',
    'replace = facts._replace; facts = replace(**changes)',
    'replace = facts._replace; facts = replace(*arguments, **changes)',
    'facts = getattr(facts, "_replace")(**changes)',
    'setattr(facts, "released", True)',
    'object.__setattr__(facts, "released", True)',
    'alias = facts; facts = alias._replace(**changes)',
    'alias = facts; alias.released = True',
    'facts.released = True',
    'facts = forged',
    'custody = forged',
    'custody[0] = forged',
    'for alias in custody:\n    alias = alias._replace(**changes)',
], ids=['unpacked-literal', 'unpacked-variable', 'dynamic-keywords', 'star-and-unpack', 'starred',
        'bound-alias', 'unpacked-alias', 'starred-alias', 'getattr', 'setattr', 'object-setattr',
        'record-alias', 'alias-write', 'attribute-write', 'record-rebinding', 'collection-rebinding',
        'collection-write', 'iteration-alias'])
def test_latch_custody_consumer_rejects_unadmitted_shapes(snippet):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    anchor = '    for facts in custody:\n'
    assert source.count(anchor) == 1
    source = source.replace(anchor, anchor + ''.join('        ' + line + '\n' for line in snippet.splitlines()))
    with pytest.raises(AssertionError, match='release'):
        assert_latch_release_structure(source)


@pytest.mark.parametrize('qualified, snippet', [
    ('Row', 'def recover(holder):\n    publish(holder)'),
    ('project', 'holder = context(); publish(holder)'),
    ('Row.run', 'publish(self.clear_writer_release)'),
])
def test_latch_argon_holder_syntax_bans(qualified, snippet):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    with pytest.raises(AssertionError, match='release'):
        assert_latch_release_structure(latch_insert(source, qualified, snippet))


@pytest.mark.parametrize('gate', [
    'if self._verification_proof is None or clear_only:\n    WRITE',
    'if self._verification_proof is None:\n    WRITE',
    'if self._verification_proof is not None:\n    pass\nelse:\n    WRITE',
    'if self._verification_proof is not None:\n    if self._verification_proof is not None:\n        pass\n    else:\n        WRITE',
    'if self._verification_proof is not None or clear_only:\n    WRITE',
    'if not (self._verification_proof is None):\n    WRITE',
], ids=['clear-only-arm', 'none-body', 'positive-else', 'nested-proof-else', 'positive-or', 'unadmitted-negation'])
def test_latch_r3_rejects_wrong_proof_polarity(gate):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    writes = 'self.view["writer_publication_verified"] = True; self.view["route_receipt"] = self._writer_receipt'
    snippet = gate.replace('WRITE', writes)
    if gate.startswith('if self._verification_proof is None or clear_only:'):
        # Place it after removals and before the non-clearing verification arm,
        # so the inserted grant survives recovery rather than being dead code.
        row = next(node for node in ast.parse(source).body if isinstance(node, ast.ClassDef) and node.name == 'Row')
        release = next(node for node in row.body if isinstance(node, ast.FunctionDef)
                       and node.name == 'finalize_writer_release')
        clear = next(node for node in ast.walk(release) if isinstance(node, ast.If)
                     and isinstance(node.test, ast.UnaryOp) and isinstance(node.test.op, ast.Not)
                     and isinstance(node.test.operand, ast.Name) and node.test.operand.id == 'clear_only')
        lines = source.splitlines(keepends=True)
        lines.insert(clear.lineno - 1, ''.join(' ' * clear.col_offset + line + '\n'
                                             for line in snippet.splitlines()))
        source = ''.join(lines)
    else:
        source = latch_insert(source, 'Row.finalize_writer_release', snippet)
    with pytest.raises(AssertionError, match='release proof polarity'):
        assert_latch_release_structure(source)


@pytest.mark.parametrize('line', [
    'setattr(self, "view", saved)',
    'getattr(self, "view").update(saved)',
    'self.__dict__["view"] = saved',
    'getattr(self, "vi" + "ew").update(saved)',
    'vars(self)["view"] = saved',
], ids=['setattr-view', 'getattr-view', 'dunder-dict-view', 'computed-getattr', 'vars-view'])
def test_latch_r3_rejects_reflective_view_access(line):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    source = latch_insert(source, 'Row', 'def recover(self, saved):\n    ' + line)
    with pytest.raises(AssertionError, match='release reflection'):
        assert_latch_release_structure(source)


@pytest.mark.parametrize('protocol', ['__reduce__()', '__reduce_ex__(4)', '__getstate__()',
                                     'verification_pass.__self__.__reduce_ex__(4)',
                                     'verification_pass.__self__.__reduce__()'])
def test_latch_rejects_unadmitted_state_protocols(protocol):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    state = '' if protocol == '__getstate__()' else '[2]'
    source = latch_insert(source, 'Row', 'def recover(self, saved):\n'
                          '    self.' + protocol + state + '["vi" + "ew"].update(saved)')
    with pytest.raises(AssertionError, match='release'):
        assert_latch_release_structure(source)


@pytest.mark.parametrize('snippet', [
    'answer = project(lifecycle, store)\nfor item in answer["small_changes"]:\n'
    '    item.update(saved)\nanswer["planning_exclusions"] = exclusions(state, answer["small_changes"])',
    'callback = project\nanswer = callback(lifecycle, store)',
    'answer = dispatcher.project(lifecycle, store)\nfor item in answer["small_changes"]:\n'
    '    item.update(saved)',
])
def test_latch_rejects_unadmitted_projection_aliases(snippet):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    source += '\ndef bypass(lifecycle, store, state, saved):\n' + ''.join(
        '    ' + line + '\n' for line in snippet.splitlines())
    with pytest.raises(AssertionError, match='release'):
        assert_latch_release_structure(source)


@pytest.mark.parametrize('qualified, snippet', [
    ('Row.run', 'self._custody = forged'),
    ('Row.run', 'alias = self._custody'),
    ('project', 'alias = custody; alias.clear()'),
    ('project', 'current._custody = forged'),
    ('project', 'custody.append(_WriterCustody(key, writer, True, state_head, True, True))'),
    ('project', 'publish(custody)'),
    ('project', 'callback = exclusions'),
])
def test_latch_rejects_unadmitted_custody_transfers(qualified, snippet):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    source = latch_insert(source, qualified, snippet)
    with pytest.raises(AssertionError, match='release'):
        assert_latch_release_structure(source)


def test_latch_exclusions_refuses_presentation_dicts():
    # Run the public consumer in an isolated interpreter, without platform I/O.
    driver = '''
import sys
sys.path.insert(0, sys.argv[1])
from hierarchy_small_change_dispatch import exclusions
state = {"requests": {"request": {"request": {"team": "a"}, "resolution": None,
    "routed": {}, "intent": None, "start": None, "small_change": {}}}}
view = {"request_id": "request", "writer": "a/lane/fix", "writer_message_present": True,
    "route_receipt": "forged", "writer_publication_verified": True}
try:
    exclusions(state, [view])
except ValueError as exc:
    assert str(exc) == "unverified writer custody input", str(exc)
else:
    raise AssertionError("presentation dictionaries granted writer release")
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', driver, str(ROOT / 'tools')],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('qualified, snippet', [
    ('project', 'for view in rows:\n    view.update(fields)'),
    ('project', 'for view in rows:\n    view["route_" + "receipt"] = True'),
    ('project', 'for alias in rows:\n    alias.update(fields)'),
    ('project', 'alias = rows[0]; alias.update(fields)'),
    ('project', 'alias = current.run(True); alias.update(fields)'),
    ('exclusions', 'view.update(fields)'),
    ('exclusions', 'view["route_" + "receipt"] = True'),
    ('exclusions', 'for alias in rows:\n    alias.update(fields)'),
    ('project', 'alias = rows; alias.append(fields)'),
    ('project', 'callback = current.run; callback(True)'),
    ('project', 'publish(current)'),
    ('Row.run', 'alias = self.view; alias.update(fields)'),
    ('Row.run', 'publish(self)'),
], ids=['rows-update', 'rows-computed-store', 'rows-renamed-alias', 'rows-index-alias',
        'run-alias', 'existing-alias-update', 'existing-alias-computed-store', 'consumer-renamed-alias',
        'collection-alias', 'run-method-alias', 'current-holder-escape', 'view-local-alias', 'self-holder-escape'])
def test_latch_r3_rejects_escaped_view_mutation(qualified, snippet):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    source = latch_insert(source, qualified, snippet)
    with pytest.raises(AssertionError, match='release view escape'):
        assert_latch_release_structure(source)


@pytest.mark.parametrize('gate', ['self._verification_proof is not None',
                                'self._verification_proof is not None and self._writer_verified'])
def test_latch_r3_admits_exact_positive_proof_body(gate):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    source = latch_insert(source, 'Row.finalize_writer_release', 'if ' + gate + ':\n'
                          '    self.view["writer_publication_verified"] = self._writer_verified\n'
                          '    self.view["route_receipt"] = self._writer_receipt')
    assert_latch_release_structure(source)


@pytest.mark.parametrize('variant', ['opaque-return', 'early-view-return', 'run-redefinition',
                                     'row-redefinition', 'project-redefinition', 'consumer-redefinition'])
def test_latch_r3_rejects_unadmitted_producers(variant):
    source = (ROOT / 'tools/hierarchy_small_change_dispatch.py').read_text(encoding='utf-8')
    if variant == 'opaque-return':
        source = latch_insert(source, 'Row.run', 'return fields')
    elif variant == 'early-view-return':
        source = latch_insert(source, 'Row.run', 'if mutate:\n    return self.view')
    elif variant == 'run-redefinition':
        source = latch_insert(source, 'Row', 'def run(self, mutate):\n    return fields')
    elif variant == 'row-redefinition':
        source += '\nclass Row:\n    pass\n'
    else:
        function = 'project' if variant == 'project-redefinition' else 'exclusions'
        source += '\ndef ' + function + '(*args, **kwargs):\n    return fields\n'
    with pytest.raises(AssertionError, match='release producer'):
        assert_latch_release_structure(source)


SECTIONS = ("Role contract", "Approved scope", "Source identity", "Open obligations",
            "Dependencies", "Unread work", "Evidence references")
ENDPOINT = "a/lane/f2"
AS_OF = "2026-11-07T12:00:00Z"
secure_publication = pytest.mark.skipif(os.name != "posix", reason="secure brief publication requires POSIX dir_fd support")


def cli(*args, expect=0):
    proc = subprocess.run([sys.executable, "-I", "-B", str(TOOL), *map(str, args)],
                          capture_output=True, text=True, timeout=30,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert proc.returncode == expect, proc.stdout + proc.stderr
    assert not proc.stderr, proc.stderr
    return json.loads(proc.stdout)


def compose(root, endpoint=ENDPOINT, expect=0, **flags):
    argv = ["compose", "--root", root, "--initiative", "a", "--endpoint", endpoint]
    for key, value in flags.items():
        argv += ["--" + key.replace("_", "-"), value]
    return cli(*argv, expect=expect)


def sections(brief):
    result, current = {}, None
    for line in Path(brief["path"]).read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            current = line[3:]
            result[current] = []
        elif line.startswith("- {"):
            result[current].append(json.loads(line[2:]))
    assert tuple(result) == SECTIONS
    return result


@secure_publication
@pytest.mark.parametrize('damage', ['changed', 'missing'])
def test_latch_r3_authoritative_prepare_names_open_dispatch(pilot, damage):
    from tools import hierarchy_fresh_brief as fresh

    root, reference = pilot
    identifier = 'latch-r3-open-dispatch'
    invoke(root, 'publish', message(identifier=identifier, kind='dispatch', brief=reference))
    packet = Path(reference['path'])
    if damage == 'changed':
        packet.write_bytes(b'changed open dispatch\n')
    else:
        packet.unlink()
    args = SimpleNamespace(root=str(root), initiative='a', endpoint=ENDPOINT, lifecycle=None,
                           delivery_dir=None, as_of=None, target_generation=None)
    before = files(root.parent)
    with pytest.raises(fresh.UnverifiedAttachment) as caught:
        fresh.prepare(args, _request_id='latch-r3-fixture')
    assert caught.value.message_id == identifier
    assert str(caught.value) == 'authoritative brief attachment is unverified'
    assert files(root.parent) == before


@secure_publication
@pytest.mark.parametrize('damage', ['missing', 'oversized'])
def test_latch_standalone_unavailable_receipt_evidence_is_unverified(tmp_path, damage):
    root, _, _ = receipt_fixture(tmp_path)
    packet = tmp_path / 'packet.md'
    packet.write_text(json.dumps({'schema': 'aegis.hierarchy-job-packet/v1', 'recipe': 'tests',
                                 'checkout': str(tmp_path), 'commit': 'a' * 40, 'tree': 'b' * 40}))
    evidence = tmp_path / 'log'
    evidence.write_bytes(b'original receipt evidence')
    reference = ref(evidence)
    invoke(root, 'publish', message(recipient='a/root', identifier='latch-job',
                                    kind='job_request', brief=ref(packet)))
    invoke(root, 'publish', message('a/root', 'a/orchestrator', identifier='latch-receipt',
        kind='job_receipt', in_reply_to='latch-job', receipt={'state': 'started', 'evidence': [reference]}))
    if damage == 'missing':
        evidence.unlink()
    else:
        with evidence.open('wb') as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
    rows = sections(compose(root, 'a/orchestrator')['brief'])
    assert any(row['kind'] == 'unverified_evidence' and row.get('declared') == reference
               for row in rows['Evidence references'])


@secure_publication
@lifecycle_only
def test_latch_standalone_missing_policy_authority_is_unverified(tmp_path):
    root, _, _ = receipt_fixture(tmp_path)
    fixture = tmp_path / 'lifecycle-fixture'
    fixture.mkdir()
    ledger = Ledger(fixture)
    policy = json.loads((ledger.path / 'policy.json').read_text())
    missing = Path(policy['authority'][0]['path'])
    missing.unlink()
    rows = sections(compose(root, 'a/orchestrator', lifecycle=ledger.path)['brief'])
    assert any(row['kind'] == 'unverified_evidence' and row.get('declared', {}).get('path') == str(missing)
               for row in rows['Evidence references'])


@secure_publication
@lifecycle_only
def test_latch_standalone_unsettled_terminal_deleted_evidence_is_unverified(tmp_path):
    root, _, _ = receipt_fixture(tmp_path)
    fixture = tmp_path / 'terminal-fixture'
    fixture.mkdir()
    ledger = Ledger(fixture)
    value = request('unsettled-terminal')
    ledger.ready(value)
    ledger.intent(value, intent_id='terminal-effect')
    proof = fixture / 'terminal-proof'
    proof.write_bytes(b'original terminal evidence\n')
    reference = ref(proof)
    ledger.event('terminal', actor=ledger.operator, result=raw_request({
        'request_sha256': raw_request(value)['sha256'], 'intent_id': 'terminal-effect',
        'outcome': 'passed', 'exit_code': 0, 'source': value['source'], 'evidence': [reference]}),
        **ledger.target(value))
    terminal = sorted((ledger.path / 'events').glob('*.json'))[-1]
    proof.unlink()
    rows = sections(compose(root, 'a/orchestrator', lifecycle=ledger.path)['brief'])
    assert any(row['kind'] == 'unverified_evidence' and row.get('declared') == reference
               and row['ref'] == ref(terminal) for row in rows['Evidence references'])
    assert any(row.get('request_id') == value['id'] for row in rows['Open obligations'])


@secure_publication
@pytest.mark.parametrize('stale_first', [False, True])
def test_latch_standalone_stale_note_is_unverified_independent_of_order(pilot, stale_first):
    root, reference = pilot
    current = Path(reference['path'])
    stale = dict(reference)
    invoke(root, 'publish', message(identifier='a-note' if stale_first else 'z-note',
                                  kind='brief', brief=stale))
    current.write_text('current note bytes')
    invoke(root, 'publish', message(identifier='z-note' if stale_first else 'a-note',
                                  kind='brief', brief=ref(current)))
    rows = sections(compose(root)['brief'])
    assert any(row['kind'] == 'unverified_evidence' and row.get('declared') == stale
               for row in rows['Evidence references'])
    assert any(row['kind'] == 'evidence' and row['ref'] == ref(current)
               for row in rows['Evidence references'])


def files(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def ref(path):
    return {"path": str(path), "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest()}


def seed_messages(root, requests):
    """One isolated interpreter per batch; public API validation stays in-process."""
    driver = r'''
import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from hierarchy_mailbox import Mailbox,writer_lock
root=Path(sys.argv[2])
with writer_lock(root):
    mailbox=Mailbox(root)
    for value in json.load(sys.stdin):
        mailbox.publish(value)
'''
    subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(ROOT / "tools"), str(root)],
                   input=json.dumps(list(requests)), text=True, check=True, timeout=180,
                   env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})


def seed_completed_requests(ledger, count):
    """Build fixture envelopes here; the isolated recorder needs only tools/."""
    events = []

    class SetupLedger(Ledger):
        def cli(self, *args, expect=0):
            if args[0] != "record" or expect != 0:
                raise ValueError("bulk lifecycle setup only collects successful record requests")
            events.append(json.loads(Path(args[2]).read_text()))

    setup = SetupLedger(ledger.tmp, initialize=False)
    for index in range(count):
        completed_request(setup, "done-%02d" % index)
    driver = r'''
import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from hierarchy_lifecycle import Lifecycle
lifecycle=Lifecycle(Path(sys.argv[2]))
for event in json.load(sys.stdin):
    lifecycle.record(event)
'''
    subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(ROOT / "tools"), str(ledger.path)],
                   input=json.dumps(events), text=True, check=True, timeout=180,
                   env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})


@pytest.fixture
def records(pilot, tmp_path):  # noqa: F811
    root, old_brief = pilot
    ledger = Ledger(tmp_path)
    change = SmallChange(ledger)
    change.register()
    change.decide()
    change.admit()
    uncertain = ledger.ready(request("uncertain"))
    ledger.intent(uncertain)
    ledger.terminal(uncertain, outcome="unknown")
    ledger.publish(request("dependent", prerequisites=[change.value["id"]]))
    finished = ledger.ready(request("finished"))
    ledger.intent(finished, intent_id="finished-attempt")
    # The fixture's terminal helper deliberately uses attempt-1; use its public event method here.
    result = {"request_sha256": ledger.target(finished)["request_sha256"], "intent_id": "finished-attempt",
              "outcome": "passed", "exit_code": 0, "source": SOURCE, "evidence": ledger.evidence}
    ledger.event("terminal", actor=ledger.operator, result=raw_request(result), **ledger.target(finished))
    ledger.accepted_delivery(finished)
    invoke(root, "publish", message(kind="dispatch", brief=old_brief))
    invoke(root, "publish", message(identifier="woken-note", body="SECRET_TRANSCRIPT_DO_NOT_INLINE"))
    delivery = tmp_path / "delivery"
    wake = delivery / "wakes" / ENDPOINT / "wake.json"
    wake.parent.mkdir(parents=True)
    wake.write_text(json.dumps({"schema": "aegis.hierarchy-delivery-receipt/v1", "endpoint": ENDPOINT,
                               "host": "host-one", "session": ENDPOINT, "generation": 1,
                               "at": "2026-11-07T00:00:00Z", "message_ids": ["woken-note"],
                               "wake_id": "wake-1", "state": "started"}))
    return root, ledger, change, wake


@lifecycle_only
def test_all_seven_items_reference_reverifiable_durable_records(records):
    root, ledger, change, wake = records
    answer = compose(root)
    brief = answer["brief"]
    rows = sections(brief)
    assert all(rows.values())
    assert answer["entries"] == sum(map(len, rows.values())) <= 256
    for group in rows.values():
        for item in group:
            assert item["ref"] == ref(item["ref"]["path"])
    assert rows["Role contract"][0]["ref"] == ref(ROOT / "tools/hierarchy_templates/roles/lane.md")
    scope = json.dumps(rows["Approved scope"])
    assert change.value["paths"][0] in scope
    assert change.value["continuation"]["expires_at"] in scope
    assert change.plan["request"]["sha256"] in scope
    assert change.row()["small_change"]["registration"]["proposal"]["sha256"] in scope
    assert '"small_change_admit"' in scope and '"small_change_decision"' in scope
    assert json.dumps(change.value["source"], sort_keys=True) in json.dumps(rows["Source identity"], sort_keys=True)
    assert any(row.get("request_id") == "dependent" and row.get("prerequisite") == change.value["id"]
               for row in rows["Dependencies"])
    evidence = json.dumps(rows["Evidence references"])
    assert str(ledger.evidence_path) in evidence
    assert all('"event_type": "' + kind + '"' in evidence for kind in ("small_change_admit", "terminal", "review"))
    body = Path(brief["path"]).read_text()
    assert "Resume path:" in body and "reconcile" in body
    assert "SECRET_TRANSCRIPT_DO_NOT_INLINE" not in body
    assert hashlib.sha256(body.encode()).hexdigest() == brief["sha256"]
    assert brief["sha256"] in Path(brief["path"]).name
    assert Path(brief["path"]).parent == root.parent / "briefs"
    assert Mailbox(root).brief(brief, verify=True) == body.encode()
    assert cli("verify", "--path", brief["path"], "--sha256", brief["sha256"])["ok"] is True


@lifecycle_only
def test_unknown_effects_and_woken_unread_are_never_dropped(records):
    root, _, _, wake = records
    rows = sections(compose(root)["brief"])
    assert any(row.get("request_id") == "uncertain" and row.get("state") == "unknown_effect"
               for row in rows["Open obligations"])
    assert any(row.get("message_id") == "woken-note" and row.get("state") == "woken"
               for row in rows["Unread work"])
    assert ref(wake) in [row["ref"] for row in rows["Evidence references"]]


@lifecycle_only
def test_determinism_and_no_store_mutations(records):
    root, _, _, _ = records
    before = files(root.parent)
    first = compose(root, as_of=AS_OF)
    raw = Path(first["brief"]["path"]).read_bytes()
    after = files(root.parent)
    assert after.pop(str(Path(first["brief"]["path"]).relative_to(root.parent))) == raw
    assert after == before
    assert compose(root, as_of=AS_OF) == first
    assert Path(first["brief"]["path"]).read_bytes() == raw


@secure_publication
def test_exact_entry_bound_and_overflow_leave_no_partial_output(pilot):  # noqa: F811
    root, _ = pilot
    initial = compose(root)
    needed = 256 - initial["entries"]
    seed_messages(root, (message(identifier="note-%03d" % index) for index in range(needed)))
    at_bound = compose(root)
    assert at_bound["entries"] == 256
    assert len(sections(at_bound["brief"])["Unread work"]) == needed
    invoke(root, "publish", message(identifier="overflow"))
    before = files(root.parent)
    assert compose(root, expect=2)["error"] == "fresh brief exceeds 256 entries"
    assert files(root.parent) == before


@secure_publication
def test_corruption_refuses_verify_and_mailbox_read(pilot):  # noqa: F811
    root, _ = pilot
    brief = compose(root)["brief"]
    Path(brief["path"]).write_bytes(b"corrupted\n")
    assert cli("verify", "--path", brief["path"], "--sha256", brief["sha256"], expect=2)["error"] == "brief sha256 mismatch"
    with pytest.raises(ValueError, match="^brief sha256 mismatch$"):
        Mailbox(root).brief(brief, verify=True)


@secure_publication
def test_handoff_carries_brief_and_successor_pages_inbox_losslessly(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    identifiers = ["note-%03d" % i for i in range(105)]
    seed_messages(root, (message(identifier=identifier) for identifier in identifiers))
    brief = compose(root)["brief"]
    assert [row["message_id"] for row in sections(brief)["Unread work"]] == identifiers
    result = handoff(tmp_path, {"schema": "aegis.hierarchy-handoff/v1", "host": "host-two",
                               "session": "successor", "outgoing_stopped": True,
                               "entries": [{"root": str(root), "endpoint": ENDPOINT, "briefs": [brief]}]}, 0)
    invoke(root, "ack-handoff", result["entries"][0]["acknowledge"])
    seen, cursor = [], None
    for _ in range(8):
        flags = {"after": cursor} if cursor else {}
        page = invoke(root, "inbox", endpoint=ENDPOINT, include_briefs=True, limit=17, **flags)
        assert page["checkpoint_briefs"][0]["sha256"] == brief["sha256"]
        seen += [row["message"]["message_id"] for row in page["messages"]]
        cursor = page["next_after"]
        if cursor is None:
            break
    assert cursor is None and seen == identifiers


@pytest.mark.parametrize("endpoint", [ENDPOINT, "a/lane/review", "a/orchestrator", "a/front-door"])
@secure_publication
def test_contract_matches_role_kind_and_host_family(pilot, endpoint):  # noqa: F811
    root, _ = pilot
    write_plan(SimpleNamespace(base=root.parent), hierarchy="a", team="claude-code", stand_ins={})
    answer = compose(root, endpoint)
    body = Path(answer["brief"]["path"]).read_text()
    rows = sections(answer["brief"])
    expected = {ENDPOINT: ["lane.md"], "a/lane/review": ["lane.md", "reviewer.md"],
                "a/orchestrator": ["orchestrator.md"], "a/front-door": ["front-door.md"]}[endpoint]
    assert [Path(item["ref"]["path"]).name for item in rows["Role contract"]] == expected
    assert all(item["family"] == "claude" for item in rows["Role contract"])
    assert "<!-- host:" not in body
    assert any(row["ref"] == ref(root.parent / "host-plan.json") for row in rows["Evidence references"])


@pytest.mark.parametrize("flags,error", [
    ({"endpoint": "b/front-door"}, "endpoint is outside initiative a"),
    ({"lifecycle": "missing"}, "lifecycle directory unavailable"),
])
def test_invalid_inputs_refuse_without_writing(pilot, flags, error):  # noqa: F811
    root, _ = pilot
    if flags.get("lifecycle") == "missing":
        flags = {"lifecycle": str(root.parent / "missing-lifecycle")}
    before = files(root.parent)
    assert error in compose(root, expect=2, **flags)["error"]
    assert files(root.parent) == before


@secure_publication
def test_verify_detects_changed_reference_even_with_unchanged_brief(pilot):  # noqa: F811
    root, _ = pilot
    brief = compose(root)["brief"]
    manifest = root / "manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b"\n")
    assert "reference sha256 mismatch" in cli("verify", "--path", brief["path"], "--sha256", brief["sha256"], expect=2)["error"]


@secure_publication
def test_uncertain_jobs_keep_ids_hashes_and_v2_dependencies(tmp_path):
    root, _, _ = receipt_fixture(tmp_path)
    packet = tmp_path / "packet.md"
    packet.write_text(json.dumps({"schema": "aegis.hierarchy-job-packet/v2", "recipe": "tests",
                                 "checkout": str(tmp_path), "commit": "a" * 40, "tree": "b" * 40,
                                 "after": {"message_id": "prior", "sha256": "c" * 64},
                                 "recipes_sha256": "d" * 64}))
    original = invoke(root, "publish", message(recipient="a/root", identifier="uncertain-job",
                                               kind="job_request", brief=ref(packet)))
    invoke(root, "publish", message("a/root", "a/orchestrator", identifier="lost-reply", kind="job_receipt",
                                    in_reply_to="uncertain-job", receipt={"state": "unknown", "reason": "lost reply"}))
    before = files(tmp_path)
    brief = compose(root, "a/orchestrator")["brief"]
    rows = sections(brief)
    job = next(row for row in rows["Open obligations"] if row.get("job_id") == "a/uncertain-job")
    assert job["state"] == "unknown" and job["ref"] == ref(original["path"])
    assert any(row.get("after") == {"message_id": "prior", "sha256": "c" * 64} and row["ref"] == ref(packet)
               for row in rows["Dependencies"])
    assert any(row.get("source", {}).get("commit") == "a" * 40 for row in rows["Source identity"])
    after = files(tmp_path)
    after.pop(str(Path(brief["path"]).relative_to(tmp_path)))
    assert after == before


@secure_publication
def test_recorded_reads_are_excluded_but_no_delivery_history_is_conservative(tmp_path):
    root, delivery, _ = receipt_fixture(tmp_path, endpoint="a/root")
    invoke(root, "inbox", endpoint="a/root", delivery_dir=delivery, mark_read=True,
           host="host-one", session="a/root", generation=1)
    brief = compose(root, "a/root")["brief"]
    aggregate = sections(brief)["Unread work"]
    assert len(aggregate) == 1 and aggregate[0]["state"] == "read_by_predecessor" and aggregate[0]["count"] == 1
    assert "receipt-note" not in json.dumps(sections(brief)["Unread work"])
    assert any(row.get("kind") == "delivery_read" for row in sections(brief)["Evidence references"])


@secure_publication
def test_run_root_resolves_initiative_base_and_runtime_pin(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    base = tmp_path / "initiatives" / "a"
    base.mkdir(parents=True)
    root.rename(base / "mailbox")
    setup = {"initiative": "a", "mailbox_root": str(base / "mailbox"), "delivery_dir": str(base / "delivery"),
             "source": str(ROOT), "source_commit": "e" * 40, "source_tree": "f" * 40}
    (base / "provision.json").write_text(json.dumps(setup))
    answer = compose(tmp_path)
    assert Path(answer["brief"]["path"]).parent == base / "briefs"
    sources = sections(answer["brief"])["Source identity"]
    assert any(row.get("source_commit") == "e" * 40 and row["ref"] == ref(base / "provision.json") for row in sources)


@lifecycle_only
def test_malformed_journal_refuses_without_creating_a_briefs_folder(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    ledger = Ledger(tmp_path)
    ledger.publish()
    event = ledger.path / "events" / "000001.json"
    event.write_text("{}")
    before = files(tmp_path)
    assert "missing fields" in compose(root, expect=2)["error"]
    assert files(tmp_path) == before and not (tmp_path / "briefs").exists()


@pytest.mark.parametrize("argv", [[], ["compose"], ["verify", "--path", "relative.md"]])
def test_malformed_cli_answers_as_json(argv):
    assert "required" in cli(*argv, expect=2)["error"]


def test_malformed_structured_packet_refuses_instead_of_dropping_dependencies(tmp_path):
    root, _, _ = receipt_fixture(tmp_path)
    packet = tmp_path / "broken-packet.md"
    packet.write_text('{"schema":"aegis.hierarchy-job-packet/v2","after":')
    invoke(root, "publish", message(recipient="a/root", identifier="broken-job", kind="job_request", brief=ref(packet)))
    before = files(tmp_path)
    error = compose(root, "a/orchestrator", expect=2)["error"]
    assert str(packet) in error and "JSON" in error
    assert files(tmp_path) == before


@secure_publication
def test_failed_atomic_publication_leaves_no_brief_or_temporary_file(pilot):  # noqa: F811
    root, _ = pilot
    # Inject only at the OS boundary, then enter the actual CLI. No composer internals are replaced.
    driver = ("import os,runpy,sys\n"
              "def refuse(*args,**kwargs):\n    raise OSError('fixture replace refused')\n"
              "os.replace=refuse\n"
              "sys.argv=sys.argv[1:]\n"
              "runpy.run_path(sys.argv[0],run_name='__main__')\n")
    before = files(root.parent)
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(TOOL), "compose", "--root", str(root),
                           "--initiative", "a", "--endpoint", ENDPOINT], capture_output=True, text=True, timeout=15)
    assert proc.returncode == 3 and not proc.stderr
    assert json.loads(proc.stdout)["error"] == "brief publication failed: fixture replace refused"
    assert files(root.parent) == before
    assert list((root.parent / "briefs").iterdir()) == []


@lifecycle_only
@pytest.mark.parametrize("transition", ["disposition", "resolve"])
def test_next_request_origin_and_pending_obligation_are_the_creating_event(pilot, tmp_path, transition):  # noqa: F811
    root, _ = pilot
    ledger = Ledger(tmp_path)
    first, following = request("first"), request("successor")
    ledger.publish(first)
    if transition == "resolve":
        ledger.event("disposition", status="HOLD", resolution={"kind": "blocked", "owner": "coordinator-1",
                     "next_decision": "resume", "condition": "ready", "evidence": ledger.evidence}, **ledger.target(first))
        blocker = ledger.status()["requests"]["first"]["resolution"]
        extra = {"blocker_sha256": hashlib.sha256(json.dumps(blocker, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
    else:
        extra = {"status": "FINAL"}
    receipt = ledger.event(transition, resolution={"kind": "next", "request": raw_request(following),
                           "evidence": ledger.evidence}, **ledger.target(first), **extra)
    origin = ref(ledger.path / "events" / ("%06d.json" % receipt["sequence"]))
    before = files(tmp_path)
    answer = compose(root)
    rows = sections(answer["brief"])
    for section in ("Approved scope", "Source identity", "Open obligations"):
        items = [row for row in rows[section] if row.get("request_id") == "successor"]
        assert items and all(item["ref"] == origin for item in items)
    assert not any(row.get("request_id") == "first" for row in rows["Approved scope"])
    after = files(tmp_path)
    after.pop(str(Path(answer["brief"]["path"]).relative_to(tmp_path)))
    assert after == before


def completed_request(ledger, identifier):
    value = ledger.ready(request(identifier))
    intent = identifier + "-intent"
    ledger.intent(value, intent_id=intent)
    result = {"request_sha256": ledger.target(value)["request_sha256"], "intent_id": intent,
              "outcome": "passed", "exit_code": 0, "source": SOURCE, "evidence": ledger.evidence}
    terminal = raw_request(result)
    ledger.event("terminal", actor=ledger.operator, result=terminal, **ledger.target(value))
    ledger.event("review", actor="reviewer-1", result_sha256=terminal["sha256"], source=SOURCE,
                 verdict="accept", evidence=ledger.evidence, **ledger.target(value))
    ledger.event("delivery", evidence=ledger.evidence, **ledger.target(value))
    ledger.event("disposition", status="FINAL", resolution={"kind": "complete", "evidence": ledger.evidence},
                 **ledger.target(value))
    return value


@lifecycle_only
def test_forty_completed_requests_are_covered_by_one_head_without_consuming_the_bound(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    ledger = Ledger(tmp_path)
    seed_completed_requests(ledger, 40)
    before = files(tmp_path)
    answer = compose(root)
    rows = sections(answer["brief"])
    assert answer["entries"] < 20
    assert rows["Approved scope"] == rows["Open obligations"] == []
    heads = [row for row in rows["Evidence references"] if row["kind"] == "lifecycle_head"]
    assert len(heads) == 1
    assert heads[0]["ref"] == ref(ledger.path / "events" / ("%06d.json" % ledger.status()["sequence"]))
    after = files(tmp_path)
    after.pop(str(Path(answer["brief"]["path"]).relative_to(tmp_path)))
    assert after == before


@secure_publication
def test_257_genuinely_unread_messages_refuse_without_writing(pilot):  # noqa: F811
    root, _ = pilot
    seed_messages(root, (message(identifier="open-%03d" % index) for index in range(257)))
    before = files(root.parent)
    assert compose(root, expect=2)["error"] == "fresh brief exceeds 256 entries"
    assert files(root.parent) == before and not (root.parent / "briefs").exists()


@lifecycle_only
def test_expired_scope_is_history_but_its_unsettled_obligation_remains(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    ledger = Ledger(tmp_path)
    ledger.publish(request("expired", continuation={"members": [], "max_starts": 1, "expires_at": "2000-01-01T00:00:00Z"}))
    rows = sections(compose(root)["brief"])
    assert not any(row.get("request_id") == "expired" for row in rows["Approved scope"])
    assert any(row.get("request_id") == "expired" for row in rows["Open obligations"])


@secure_publication
def test_closed_dispatch_lease_and_missing_brief_are_history(pilot, tmp_path):  # noqa: F811
    root, old_brief, ready = active_writer(pilot, tmp_path)
    completion = invoke(root, "publish", message("a/lane/f2", "a/orchestrator", identifier="done", kind="result",
                                    in_reply_to="dispatch-1", result={"source_revision": ready["base_revision"],
                                    "source_tree": "b" * 40, "checks": [{"check": "tests", "outcome": "pass", "reference": "retained"}],
                                    "lane_check": "retained"}))
    Path(old_brief["path"]).unlink()
    answer = compose(root)
    rows = sections(answer["brief"])
    assert ready["lease_ref"] not in json.dumps(rows["Approved scope"])
    assert not rows["Open obligations"]
    history = [row for row in rows["Evidence references"] if row["kind"] == "mailbox_history"]
    assert len(history) == 1 and history[0]["ref"] == ref(completion["path"])
    assert history[0]["historical_briefs"] == "not_reverified"
    assert not any(row["ref"]["path"] == old_brief["path"] for row in rows["Evidence references"])


def job_history(tmp_path):
    root, _, _ = receipt_fixture(tmp_path)
    packet = tmp_path / "packet.md"
    packet.write_text(json.dumps({"schema": "aegis.hierarchy-job-packet/v1", "recipe": "tests",
                                 "checkout": str(tmp_path), "commit": "a" * 40, "tree": "b" * 40}))
    original = invoke(root, "publish", message(recipient="a/root", identifier="job", kind="job_request", brief=ref(packet)))
    unknown = invoke(root, "publish", message("a/root", "a/orchestrator", identifier="unknown", kind="job_receipt",
                                              in_reply_to="job", receipt={"state": "unknown", "reason": "lost reply"}))
    evidence = tmp_path / "job-result.json"
    evidence.write_text("{}\n")
    terminal = invoke(root, "publish", message("a/root", "a/orchestrator", identifier="terminal", kind="job_receipt",
                                               in_reply_to="job", receipt={"state": "completed", "exit_code": 0, "evidence": [ref(evidence)]}))
    return root, packet, original, unknown, terminal


def set_record_time(record, at):
    # Stored histories may order differently from publication; the reader validates this supported input.
    header = {**record["message"], "created_at": at}
    body = header.pop("body")
    Path(record["path"]).write_bytes(b"---\n" + json.dumps(header, sort_keys=True).encode() + b"\n---\n\n" + body.encode())


@secure_publication
def test_later_unknown_survives_an_earlier_terminal_until_a_correlated_later_terminal(tmp_path):
    root, packet, original, unknown, terminal = job_history(tmp_path)
    set_record_time(terminal, "2026-01-01T00:00:00Z")
    set_record_time(unknown, "2026-01-02T00:00:00Z")
    rows = sections(compose(root, "a/orchestrator")["brief"])
    assert any(row.get("job_id") == "a/job" and row.get("state") == "unknown" and row["ref"] == ref(original["path"])
               for row in rows["Open obligations"])
    # The same correlated terminal only settles the job when its durable timestamp is later.
    set_record_time(terminal, "2026-01-03T00:00:00Z")
    rows = sections(compose(root, "a/orchestrator")["brief"])
    assert not any(row.get("job_id") == "a/job" for row in rows["Open obligations"])


@secure_publication
@pytest.mark.parametrize("damage", ["missing", "changed"])
def test_historical_packets_do_not_block_but_uncertain_packets_do(tmp_path, damage):
    root, packet, original, unknown, terminal = job_history(tmp_path)
    set_record_time(unknown, "2026-01-01T00:00:00Z")
    set_record_time(terminal, "2026-01-02T00:00:00Z")
    if damage == "missing":
        packet.unlink()
    else:
        packet.write_text("changed\n")
    rows = sections(compose(root, "a/orchestrator")["brief"])
    history = [row for row in rows["Evidence references"] if row["kind"] == "mailbox_history"]
    assert len(history) == 1 and history[0]["ref"] == ref(original["path"])
    assert history[0]["historical_briefs"] == "not_reverified"
    assert not any(row["ref"]["path"] == str(packet) for row in rows["Evidence references"])
    set_record_time(unknown, "2026-01-03T00:00:00Z")
    before = files(tmp_path)
    error = compose(root, "a/orchestrator", expect=2)["error"]
    assert ("file unavailable" if damage == "missing" else "brief sha256 mismatch") in error
    assert files(tmp_path) == before


@secure_publication
def test_old_read_and_wake_history_is_bounded_and_successor_reads_are_generation_scoped(tmp_path):
    root, delivery, checkpoint = receipt_fixture(tmp_path, endpoint="a/root")
    invoke(root, "inbox", endpoint="a/root", delivery_dir=delivery, mark_read=True,
           host="host-one", session="a/root", generation=1)
    folder = delivery / "reads" / "a/root"
    receipt = json.loads(next(folder.iterdir()).read_text())
    for index in range(300):
        (folder / ("history-%03d.json" % index)).write_text(json.dumps(receipt))
    wakes = delivery / "wakes" / "a/root"
    wakes.mkdir(parents=True)
    for index in range(300):
        (wakes / ("history-%03d.json" % index)).write_text(json.dumps(
            {**receipt, "wake_id": "wake-%03d" % index, "state": "started"}))
    answer = compose(root, "a/root")
    assert answer["entries"] < 20
    before_bind = sections(answer["brief"])["Unread work"]
    assert len(before_bind) == 1 and before_bind[0]["state"] == "read_by_predecessor"
    invoke(root, "bind", {"endpoint": "a/root", "host": "host-two", "session": "successor", "expected_generation": 1,
                          "checkpoint": checkpoint})
    rows = sections(compose(root, "a/root")["brief"])
    assert len(rows["Unread work"]) == 1
    assert rows["Unread work"][0]["state"] == "read_by_predecessor" and rows["Unread work"][0]["count"] == 1


@secure_publication
def test_json_answer_reports_absent_lifecycle_coverage(pilot):  # noqa: F811
    root, _ = pilot
    assert compose(root)["coverage"]["lifecycle"] == "absent"


def faulted_cli(root, driver, timeout=30):
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(TOOL), str(root)],
                          capture_output=True, text=True, timeout=timeout,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert not proc.stderr, proc.stderr
    return proc.returncode, json.loads(proc.stdout)


@secure_publication
@pytest.mark.parametrize("boundary", ["create", "rename"])
def test_publication_directory_swap_never_writes_into_a_store(pilot, boundary):  # noqa: F811
    root, _ = pilot
    briefs, held, store = root.parent / "briefs", root.parent / "held-briefs", root.parent / "store"
    briefs.mkdir()
    store.mkdir()
    sentinel = store / "sentinel"
    sentinel.write_text("store must stay unchanged")
    driver = ("import os,runpy,sys\nfrom pathlib import Path\n"
              "tool,root=sys.argv[1:]\nbase=Path(root).parent\n"
              "real_open,real_replace=os.open,os.replace\nswapped=False\n"
              "def swap():\n"
              "    global swapped\n"
              "    if not swapped:\n"
              "        swapped=True\n"
              "        os.rename(base/'briefs',base/'held-briefs')\n"
              "        os.symlink(base/'store',base/'briefs',target_is_directory=True)\n"
              "def opening(path,flags,*args,**kwargs):\n"
              + ("    if str(path).split('/')[-1].startswith('.fresh-') and flags & os.O_CREAT: swap()\n" if boundary == "create" else "")
              + "    return real_open(path,flags,*args,**kwargs)\n"
              "def replacing(src,dst,*args,**kwargs):\n"
              + ("    swap()\n" if boundary == "rename" else "")
              + "    return real_replace(src,dst,*args,**kwargs)\n"
              "os.open,os.replace=opening,replacing\n"
              "sys.argv=[tool,'compose','--root',root,'--initiative','a','--endpoint','a/lane/f2']\n"
              "runpy.run_path(tool,run_name='__main__')\n")
    before = files(store)
    code, answer = faulted_cli(root, driver)
    assert files(store) == before, "publication followed the swapped symlink into a store"
    assert code == 2 and "publication directory changed" in answer["error"]
    assert list(held.iterdir()) == []


def test_unsupported_dir_fd_refuses_cleanly_before_creating_any_output(pilot):  # noqa: F811
    root, _ = pilot
    driver = ("import os,runpy,sys\n"
              "tool,root=sys.argv[1:]\nos.supports_dir_fd=set()\n"
              "sys.argv=[tool,'compose','--root',root,'--initiative','a','--endpoint','a/lane/f2']\n"
              "runpy.run_path(tool,run_name='__main__')\n")
    before = files(root.parent)
    code, answer = faulted_cli(root, driver)
    assert code == 2 and answer["error"] == "secure brief publication requires directory descriptor support"
    assert files(root.parent) == before and not (root.parent / "briefs").exists()


def test_byte_limit_refuses_without_writing(pilot):  # noqa: F811
    root, _ = pilot
    source = root.parent / "source"
    templates = source / "tools/hierarchy_templates"
    (templates / "roles").mkdir(parents=True)
    shutil.copyfile(ROOT / "tools/hierarchy_templates/lane-brief.md", templates / "lane-brief.md")
    (templates / "roles/lane.md").write_text("# Role\n" + "x" * 262144)
    (root.parent / "provision.json").write_text(json.dumps({"initiative": "a", "source": str(source),
        "mailbox_root": str(root), "delivery_dir": str(root.parent / "delivery")}))
    before = files(root.parent)
    assert compose(root, expect=2)["error"] == "fresh brief exceeds mailbox brief byte limit (262144)"
    assert files(root.parent) == before and not (root.parent / "briefs").exists()


def test_verify_portable_brief_without_a_journal_or_publication(tmp_path):
    manifest = tmp_path / "record.json"
    manifest.write_text("{}\n")
    brief = tmp_path / "brief.md"
    body = ["# Fresh thread brief", "<!-- aegis.hierarchy-fresh-brief/v1 -->", "Resume path: Verify first."]
    for name in SECTIONS:
        body += ["## " + name, "- " + json.dumps({"kind": "record", "ref": ref(manifest)})]
    brief.write_text("\n".join(body) + "\n")
    reference = ref(brief)
    assert cli("verify", "--path", brief, "--sha256", reference["sha256"])["ok"] is True


def provision_record(root, **changes):
    value = {"initiative": "a", "source": str(ROOT), "mailbox_root": str(root),
             "delivery_dir": str(root.parent / "delivery"), **changes}
    (root.parent / "provision.json").write_text(json.dumps(value))
    return value


@secure_publication
def test_output_cannot_be_the_mailbox_store(pilot):  # noqa: F811
    root, _ = pilot
    destination = root.parent / "briefs"
    root.rename(destination)
    before = files(destination.parent)
    assert "output directory overlaps coordination store" in compose(destination, expect=2)["error"]
    assert files(destination.parent) == before


@pytest.mark.parametrize("store_kind", ["delivery", "store", "board", pytest.param("lifecycle", marks=lifecycle_only)])
@pytest.mark.parametrize("relation", ["equal", "inside", "around"])
def test_output_refuses_overlap_with_every_declared_coordination_store(pilot, tmp_path, store_kind, relation):  # noqa: F811
    root, _ = pilot
    output = tmp_path / "briefs"
    store = {"equal": output, "inside": tmp_path, "around": output / "nested-store"}[relation]
    flags = {}
    if store_kind == "lifecycle":
        staging = tmp_path / "staging"
        staging.mkdir()
        ledger = Ledger(staging)
        shutil.copytree(ledger.path, store, dirs_exist_ok=True)
        flags["lifecycle"] = str(store)
    else:
        store.mkdir(parents=True, exist_ok=True)
        provision_record(root, **{("delivery_dir" if store_kind == "delivery" else store_kind): str(store)})
        # A command-line override must not stop protecting the provisioned delivery store.
        flags["delivery_dir"] = str(tmp_path / "safe-delivery")
    before = files(tmp_path)
    assert "output directory overlaps coordination store" in compose(root, expect=2, **flags)["error"]
    assert files(tmp_path) == before


@secure_publication
@pytest.mark.parametrize("record_path", ["initiatives/other/provision.json", "evidence/provision-init.json"])
def test_store_named_by_another_run_record_is_also_protected(pilot, tmp_path, record_path):  # noqa: F811
    root, _ = pilot
    path = tmp_path / record_path
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"store": str(tmp_path / "briefs")}))
    before = files(tmp_path)
    assert "output directory overlaps coordination store" in compose(root, expect=2)["error"]
    assert files(tmp_path) == before and not (tmp_path / "briefs").exists()


FROZEN_COMPOSE = ("import datetime,runpy,sys\n"
                  "class Frozen(datetime.datetime):\n"
                  "    @classmethod\n"
                  "    def now(cls,tz=None): return cls(2026,11,7,12,tzinfo=tz)\n"
                  "datetime.datetime=Frozen\n"
                  "tool,root=sys.argv[1:]\n"
                  "sys.argv=[tool,'compose','--root',root,'--initiative','a','--endpoint','a/lane/f2']\n"
                  "runpy.run_path(tool,run_name='__main__')\n")


@secure_publication
@pytest.mark.parametrize("special", ["fifo", "directory"])
def test_special_destination_refuses_without_hanging_or_writing(pilot, special):  # noqa: F811
    root, _ = pilot
    code, first = faulted_cli(root, FROZEN_COMPOSE)
    assert code == 0
    path = Path(first["brief"]["path"])
    path.unlink()
    if special == "fifo":
        os.mkfifo(path)
    else:
        path.mkdir()
    before = files(root.parent)
    code, answer = faulted_cli(root, FROZEN_COMPOSE, timeout=2)
    assert code == 2 and answer["error"] == "brief must be a regular file"
    assert files(root.parent) == before
    assert stat.S_ISFIFO(path.stat().st_mode) if special == "fifo" else path.is_dir()


@secure_publication
def test_returned_path_must_identify_the_written_inode_after_an_ancestor_moves(pilot):  # noqa: F811
    root, _ = pilot
    base = root.parent
    moved = base.with_name(base.name + "-moved")
    driver = ("import os,runpy,sys\nfrom pathlib import Path\n"
              "tool,root=sys.argv[1:]\nbase=Path(root).parent\nreal_open=os.open\nmoved=False\n"
              "def opening(path,flags,*args,**kwargs):\n"
              "    global moved\n"
              "    if str(path).startswith('.fresh-') and flags & os.O_CREAT and not moved:\n"
              "        moved=True\n"
              "        base.rename(base.with_name(base.name+'-moved'))\n"
              "        base.mkdir()\n"
              "    return real_open(path,flags,*args,**kwargs)\n"
              "os.open=opening\n"
              "sys.argv=[tool,'compose','--root',root,'--initiative','a','--endpoint','a/lane/f2']\n"
              "runpy.run_path(tool,run_name='__main__')\n")
    code, answer = faulted_cli(root, driver)
    assert code == 3 and "published brief pathname no longer identifies written file" in answer["error"]
    assert list(base.iterdir()) == [] and list((moved / "briefs").iterdir()) == []


@secure_publication
def test_initiative_named_serve_composes_without_operational_import_side_effects(tmp_path):
    root = tmp_path / "mailbox"
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": {"serve/front-door": {}, "serve/orchestrator": {}},
                          "counterparts": [], "writer_limit": 1})
    provision_record(root, initiative="serve")
    answer = cli("compose", "--root", root, "--initiative", "serve", "--endpoint", "serve/orchestrator")
    assert answer["ok"] is True and sections(answer["brief"])["Role contract"][0]["role"] == "orchestrator"


@secure_publication
@pytest.mark.parametrize("family", ["claude", "codex"])
@pytest.mark.parametrize("role", ["front-door", "orchestrator", "router", "decider", "implementer", "integrator", "reviewer"])
def test_template_rendering_exactly_matches_launcher_in_a_separate_process(tmp_path, role, family):
    endpoint = "a/lane/" + role if role in {"implementer", "integrator", "reviewer"} else "a/" + role
    root = tmp_path / "mailbox"
    invoke(root, "init", {"schema": "aegis.hierarchy-pilot/v1", "endpoints": {"a/front-door": {}, "a/orchestrator": {},
        endpoint: {"kind": role} if "/lane/" in endpoint else {}}, "counterparts": [], "writer_limit": 1})
    write_plan(SimpleNamespace(base=tmp_path), hierarchy="a", team="claude-code" if family == "claude" else "codex-cli", stand_ins={})
    answer = compose(root, endpoint)
    text = Path(answer["brief"]["path"]).read_text()
    inline = "\n".join(line[2:] for line in text.splitlines() if line.startswith("> "))
    driver = ("import json,sys\nfrom types import SimpleNamespace\n"
              "from pathlib import Path\nsource,root,endpoint,family=sys.argv[1:]\n"
              "sys.argv=[str(Path(source)/'tools/hierarchy_launcher.py')]\n"
              "sys.path.insert(0,str(Path(source)/'tools'))\n"
              "from hierarchy_launcher import start_prompt\nfrom hierarchy_mailbox import Mailbox\n"
              "prompt,contracts=start_prompt(SimpleNamespace(mailbox=Mailbox(root),setup={'source':source}),endpoint,family)\n"
              "print(json.dumps({'text':prompt.partition('\\n\\n')[2].rpartition('\\n\\n')[0],'contracts':contracts}))\n")
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(ROOT), str(root), endpoint, family],
                          capture_output=True, text=True, timeout=15)
    assert proc.returncode == 0 and not proc.stderr, proc.stdout + proc.stderr
    expected = json.loads(proc.stdout)
    assert inline == expected["text"]
    assert [row["ref"] for row in sections(answer["brief"])["Role contract"]] == expected["contracts"]


@lifecycle_only
@pytest.mark.parametrize("path_limit", [None, 1024], ids=["native", "macos-path-limit"])
def test_valid_large_settled_lifecycle_record_uses_the_lifecycle_reader_limit(pilot, tmp_path, monkeypatch, path_limit):  # noqa: F811
    if path_limit is not None:
        real_is_symlink = Path.is_symlink

        def limited_is_symlink(path):
            if len(os.fsencode(path)) >= path_limit:
                raise OSError(errno.ENAMETOOLONG, "simulated macOS pathname limit", str(path))
            return real_is_symlink(path)

        monkeypatch.setattr(Path, "is_symlink", limited_is_symlink)
    root, _ = pilot
    ledger = Ledger(tmp_path)
    # Nested JSON escaping grows the wire record, not the POSIX filename bytes.
    component = '"\\' * 64
    paths = [str(tmp_path / "declared" / str(index) / component / component) for index in range(256)]
    assert len(paths) <= 256
    assert max(len(os.fsencode(path)) for path in paths) < 1024
    assert max(len(os.fsencode(part)) for path in paths for part in Path(path).parts) < 255
    for path in paths:
        safe_path(path)
    value = request("large-history", paths=paths)
    receipt = ledger.publish(value)
    record = ledger.path / "events" / ("%06d.json" % receipt["sequence"])
    assert 262144 < len(record.read_bytes()) < 1048576
    ledger.event("disposition", status="FINAL", resolution={"kind": "next", "request": raw_request(request("pending")),
                 "evidence": ledger.evidence}, **ledger.target(value))
    before = files(tmp_path)
    answer = compose(root)
    assert answer["entries"] < 20
    assert all(row.get("request_id") != value["id"] for rows in sections(answer["brief"]).values() for row in rows)
    after = files(tmp_path)
    after.pop(str(Path(answer["brief"]["path"]).relative_to(tmp_path)))
    assert after == before


@lifecycle_only
def test_expiry_decisions_are_reproducible_from_explicit_as_of(pilot, tmp_path):  # noqa: F811
    root, _ = pilot
    ledger = Ledger(tmp_path)
    ledger.publish(request("timed", continuation={"members": [], "max_starts": 1, "expires_at": "2026-11-07T12:00:00Z"}))
    before = compose(root, as_of="2026-11-07T11:59:59Z")
    after = compose(root, as_of="2026-11-07T12:00:01Z")
    assert any(row.get("request_id") == "timed" for row in sections(before["brief"])["Approved scope"])
    assert not any(row.get("request_id") == "timed" for row in sections(after["brief"])["Approved scope"])
    assert compose(root, as_of="2026-11-07T11:59:59Z") == before
    body = Path(before["brief"]["path"]).read_text()
    assert "2026-11-07T11:59:59" in body and "validate expiry live" in body


@pytest.mark.parametrize("value", ["yesterday", "2026-11-07T12:00:00-05:00"])
def test_as_of_requires_rfc3339_utc_without_writes(pilot, value):  # noqa: F811
    root, _ = pilot
    before = files(root.parent)
    assert "invalid --as-of" in compose(root, as_of=value, expect=2)["error"]
    assert files(root.parent) == before


@secure_publication
@pytest.mark.parametrize("order", ["compose-then-bind", "bind-then-compose"])
def test_successor_lifetime_reads_use_one_predecessor_aggregate(tmp_path, order):
    root, delivery, checkpoint = receipt_fixture(tmp_path, endpoint="a/root")
    seed_messages(root, (message(recipient="a/root", identifier="lifetime-%03d" % index) for index in range(248)))
    invoke(root, "publish", message(recipient="a/root", identifier="esc-7", kind="escalation"))
    cursor = None
    for _ in range(4):
        flags = {"after": cursor} if cursor else {}
        page = invoke(root, "inbox", endpoint="a/root", delivery_dir=delivery, mark_read=True,
                      host="host-one", session="a/root", generation=1, limit=100, **flags)
        cursor = page["next_after"]
        if cursor is None:
            break
    assert cursor is None
    binding = {"endpoint": "a/root", "host": "host-two", "session": "successor", "expected_generation": 1,
               "checkpoint": checkpoint}
    if order == "bind-then-compose":
        invoke(root, "bind", binding)
    answer = compose(root, "a/root")
    rows = sections(answer["brief"])["Unread work"]
    assert answer["entries"] < 20 and len(rows) == 1
    aggregate = rows[0]
    assert aggregate["state"] == "read_by_predecessor" and aggregate["count"] == 250
    assert aggregate["generation"] == 2 and aggregate["message_types"]["escalation"] == 1
    assert aggregate["ref"] == ref(aggregate["ref"]["path"])
    assert "esc-7" in json.loads(Path(aggregate["ref"]["path"]).read_text())["message_ids"]
    if order == "compose-then-bind":
        binding["checkpoint"]["briefs"].append(answer["brief"])
        invoke(root, "bind", binding)
    own = compose(root, "a/root", target_generation=1, expect=2)
    assert "target generation precedes current binding" in own["error"]


@secure_publication
def test_explicit_current_target_generation_applies_its_own_reads(tmp_path):
    root, delivery, _ = receipt_fixture(tmp_path, endpoint="a/root")
    invoke(root, "inbox", endpoint="a/root", delivery_dir=delivery, mark_read=True,
           host="host-one", session="a/root", generation=1)
    answer = compose(root, "a/root", target_generation=1)
    assert sections(answer["brief"])["Unread work"] == []
    assert "Target generation: 1" in Path(answer["brief"]["path"]).read_text()


@secure_publication
@pytest.mark.skipif(not hasattr(os, "O_PATH"), reason="search-only traversal uses Linux O_PATH")
def test_search_only_parent_directories_allow_publication(pilot):  # noqa: F811
    root, _ = pilot
    ancestor = root.parent / "search-only"
    base = ancestor / "run"
    base.mkdir(parents=True)
    root.rename(base / "mailbox")
    root = base / "mailbox"
    mode = stat.S_IMODE(ancestor.stat().st_mode)
    ancestor.chmod(0o111)
    try:
        answer = compose(root)
    finally:
        ancestor.chmod(mode)
    assert Mailbox(root).brief(answer["brief"])


@secure_publication
@pytest.mark.parametrize("accessor", ["native", "python39"])
def test_directory_eacces_is_a_permission_refusal(pilot, accessor):  # noqa: F811
    root, _ = pilot
    # Python 3.9's pathlib accessor must capture the builtin before os.open is patched.
    driver = ("import errno,os,runpy,sys\nfrom pathlib import Path\n"
              "tool,root=sys.argv[1:]\nreal_open=os.open\n"
              "def opening(path,flags,*args,**kwargs):\n"
              "    if str(path)=='briefs': raise PermissionError(errno.EACCES,'fixture directory denied')\n"
              "    return real_open(path,flags,*args,**kwargs)\n"
              "os.open=opening\n"
              "sys.argv=[tool,'compose','--root',root,'--initiative','a','--endpoint','a/lane/f2']\n"
              "runpy.run_path(tool,run_name='__main__')\n")
    if accessor == "python39":
        # Emulate 3.9's class-level os.open capture at pathlib import on newer Python.
        driver = ("import builtins,io\n"
                  "real_import=builtins.__import__\naccessor_installed=False\n"
                  "def importing(name,*args,**kwargs):\n"
                  "    global accessor_installed\n"
                  "    module=real_import(name,*args,**kwargs)\n"
                  "    if name=='pathlib' and not accessor_installed:\n"
                  "        accessor_installed=True\n"
                  "        import os\n"
                  "        class NormalAccessor:\n"
                  "            open=os.open\n"
                  "        normal=NormalAccessor()\n"
                  "        def path_open(self,mode='r',buffering=-1,encoding=None,errors=None,newline=None):\n"
                  "            return io.open(self,mode,buffering,encoding,errors,newline,\n"
                  "                           opener=lambda path,flags: normal.open(path,flags,0o666))\n"
                  "        module.Path.open=path_open\n"
                  "    return module\n"
                  "builtins.__import__=importing\n") + driver
    before = files(root.parent)
    code, answer = faulted_cli(root, driver)
    assert code == 2 and "publication directory permission denied" in answer["error"]
    assert "changed" not in answer["error"]
    assert files(root.parent) == before


def structured_job(tmp_path, changes=None, missing=None):
    root, _, _ = receipt_fixture(tmp_path)
    value = {"schema": "aegis.hierarchy-job-packet/v2", "recipe": "tests", "checkout": str(tmp_path),
             "commit": "a" * 40, "tree": "b" * 40, "recipes_sha256": "c" * 64,
             "after": {"message_id": "prior", "sha256": "d" * 64}, **(changes or {})}
    if value["schema"] == "aegis.hierarchy-job-packet/v1":
        value.pop("after", None)
        value.pop("recipes_sha256", None)
    if missing is not None:
        value.pop(missing)
    path = tmp_path / "structured-packet.md"
    path.write_text(json.dumps(value))
    invoke(root, "publish", message(recipient="a/root", identifier="structured-job", kind="job_request", brief=ref(path)))
    return root, path, value


@pytest.mark.parametrize("changes,missing,field", [
    ({}, "after", "after"),
    ({"commit": {"transcript": "DO_NOT_INLINE_PACKET_TRANSCRIPT"}}, None, "commit"),
    ({"schema": "aegis.hierarchy-job-packet/v99"}, None, "schema"),
    ({}, "recipes_sha256", "recipes_sha256"),
    ({}, "tree", "tree"),
    ({"checkout": {}}, None, "checkout"),
    ({"tree": []}, None, "tree"),
    ({"paths": [{"transcript": "DO_NOT_INLINE_PACKET_TRANSCRIPT"}]}, None, "paths"),
    ({"paths": "tests"}, None, "paths"),
    ({"paths": ["../escape.py"]}, None, "paths"),
    ({"dirty_content_sha256": {}}, None, "dirty_content_sha256"),
    ({"expected_tree": {}}, None, "expected_tree"),
    ({"merge": {}}, None, "merge"),
    ({"message": {}}, None, "message"),
    ({"recipe": {}}, None, "recipe"),
    ({"after": {"message_id": {}, "sha256": "d" * 64}}, None, "after"),
    ({"recipes_sha256": []}, None, "recipes_sha256"),
])
def test_malformed_structured_packets_refuse_before_extracting_fields(tmp_path, changes, missing, field):
    root, path, _ = structured_job(tmp_path, changes, missing)
    before = files(tmp_path)
    error = compose(root, "a/orchestrator", expect=2)["error"]
    assert str(path) in error and field in error
    assert "DO_NOT_INLINE_PACKET_TRANSCRIPT" not in error
    assert files(tmp_path) == before and not (tmp_path / "briefs").exists()


@pytest.mark.parametrize("changes,missing,field", [
    ({}, "after", "after"),
    ({"commit": {"transcript": "DO_NOT_INLINE_PACKET_TRANSCRIPT"}}, None, "commit"),
])
def test_packet_rejection_agrees_with_the_runners_admission_checks(tmp_path, changes, missing, field):
    root, path, _ = structured_job(tmp_path, changes, missing)
    # No standalone schema validator exists. The actual admission API must fail
    # on these fields before it could reach any checkout or execution boundary.
    driver = ("import json,sys\nfrom pathlib import Path\n"
              "source,root,packet,checkout=sys.argv[1:]\n"
              "sys.path.insert(0,str(Path(source)/'tools'))\n"
              "from hierarchy_jobs import admit\nfrom hierarchy_mailbox import Mailbox\n"
              "mailbox=Mailbox(root)\nmessage=mailbox.messages()['structured-job']['message']\n"
              "try:\n"
              "    admit(None,{'checkouts':[checkout]},message,mailbox,{'recipes':{'tests':{'kind':'command','steps':[]}}})\n"
              "except ValueError as error:\n    print(json.dumps({'error':str(error)}))\n"
              "else:\n    raise AssertionError('malformed packet reached admission')\n")
    result = subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(ROOT), str(root), str(path), str(tmp_path)],
                            capture_output=True, text=True, timeout=15,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0 and not result.stderr, result.stdout + result.stderr
    assert field in json.loads(result.stdout)["error"]
    assert field in compose(root, "a/orchestrator", expect=2)["error"]


@pytest.mark.parametrize("after", [None, []])
def test_non_object_dependency_names_the_after_field(tmp_path, after):
    root, path, _ = structured_job(tmp_path, {"after": after})
    before = files(tmp_path)
    error = compose(root, "a/orchestrator", expect=2)["error"]
    assert str(path) in error and ": invalid after:" in error
    assert files(tmp_path) == before


@secure_publication
@pytest.mark.parametrize("version", [1, 2])
def test_valid_packet_source_fields_remain_scalar_and_paths_are_strings(tmp_path, version):
    value = {"schema": "aegis.hierarchy-job-packet/v%d" % version,
             "paths": ["tests/example.py::test_one"], "dirty_content_sha256": hashlib.sha256(b"").hexdigest()}
    root, path, packet = structured_job(tmp_path, value)
    rows = sections(compose(root, "a/orchestrator")["brief"])
    source = next(row["source"] for row in rows["Source identity"] if row.get("job_id") == "structured-job")
    assert source["commit"] == packet["commit"] and source["tree"] == packet["tree"]
    assert source["paths"] == packet["paths"]
    assert all(isinstance(item, str) for item in source["paths"])


FSYNC_DRIVER = ("import errno,fcntl,json,os,runpy,stat,sys\nfrom pathlib import Path\n"
                "tool,root,fail,peer=sys.argv[1:]\nbase=Path(root).parent\ntrace=base/'fsync-trace.json'\n"
                "events=[]\nrenamed=False\nalready_published=any((base/'briefs').glob('fresh-*.md'))\n"
                "real_fsync,real_replace,real_mkdir=os.fsync,os.replace,os.mkdir\n"
                "def making(path,*args,**kwargs):\n"
                "    result=real_mkdir(path,*args,**kwargs)\n"
                "    if peer=='yes' and str(path)=='briefs':\n"
                "        events.append('peer_created')\n"
                "        raise FileExistsError(errno.EEXIST,'peer created the directory without syncing its parent')\n"
                "    return result\n"
                "def replacing(*args,**kwargs):\n"
                "    global renamed\n    result=real_replace(*args,**kwargs)\n    renamed=True\n    return result\n"
                "def syncing(fd):\n"
                "    metadata=os.fstat(fd)\n"
                "    if stat.S_ISDIR(metadata.st_mode):\n"
                "        assert renamed or already_published,'directory synced before rename'\n"
                "        flags=fcntl.fcntl(fd,fcntl.F_GETFL)\n"
                "        assert flags & os.O_ACCMODE == os.O_RDONLY\n"
                "        assert not flags & getattr(os,'O_PATH',0)\n"
                "        parent=base.stat()\n"
                "        kind='parent' if (metadata.st_dev,metadata.st_ino)==(parent.st_dev,parent.st_ino) else 'directory'\n"
                "    else:\n        assert stat.S_ISREG(metadata.st_mode)\n        kind='file'\n"
                "    events.append(kind)\n"
                "    if kind==fail: raise OSError('fixture '+kind+' fsync refused')\n"
                "    return real_fsync(fd)\n"
                "os.fsync,os.replace,os.mkdir=syncing,replacing,making\n"
                "sys.argv=[tool,'compose','--root',root,'--initiative','a','--endpoint','a/lane/f2','--as-of','2026-11-07T12:00:00Z']\n"
                "try:\n    runpy.run_path(tool,run_name='__main__')\n"
                "finally:\n    trace.write_text(json.dumps(events))\n")


def traced_publication(root, fail="", peer_creation=False):
    proc = subprocess.run([sys.executable, "-I", "-B", "-c", FSYNC_DRIVER, str(TOOL), str(root), fail,
                           "yes" if peer_creation else "no"],
                          capture_output=True, text=True, timeout=15,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert not proc.stderr, proc.stderr
    return proc.returncode, json.loads(proc.stdout), json.loads((root.parent / "fsync-trace.json").read_text())


@secure_publication
@pytest.mark.parametrize("existing", ["none", "directory", "brief"])
def test_publication_syncs_directory_and_parent_on_every_success(pilot, existing):  # noqa: F811
    root, _ = pilot
    if existing == "directory":
        (root.parent / "briefs").mkdir()
    elif existing == "brief":
        compose(root, as_of=AS_OF)
    code, answer, events = traced_publication(root)
    assert code == 0, answer
    expected = {"none": ["file", "directory", "parent"], "directory": ["file", "directory", "parent"],
                "brief": ["directory", "parent"]}
    assert events == expected[existing]
    assert Mailbox(root).brief(answer["brief"])


@secure_publication
@pytest.mark.parametrize("failed", ["directory", "parent"])
def test_directory_sync_failure_never_reports_publication_success(pilot, failed):  # noqa: F811
    root, _ = pilot
    code, answer, events = traced_publication(root, failed)
    assert code == 3 and "ok" not in answer
    assert answer["error"] == "brief publication failed: fixture " + failed + " fsync refused"
    assert events[-1] == failed


@secure_publication
def test_parent_sync_failure_is_not_forgotten_on_retry(pilot):  # noqa: F811
    root, _ = pilot
    code, _, events = traced_publication(root, "parent")
    assert code == 3 and events == ["file", "directory", "parent"]
    published = list((root.parent / "briefs").glob("fresh-*.md"))
    assert len(published) == 1
    reference = ref(published[0])
    contents = published[0].read_bytes()
    code, _, events = traced_publication(root, "parent")
    assert code == 3 and events == ["directory", "parent"]
    code, answer, events = traced_publication(root)
    assert code == 0 and events == ["directory", "parent"]
    assert answer["brief"] == reference and Mailbox(root).brief(reference) == contents


@secure_publication
def test_peer_creation_without_parent_sync_is_completed_by_this_composer(pilot):  # noqa: F811
    root, _ = pilot
    code, answer, events = traced_publication(root, peer_creation=True)
    assert code == 0, answer
    assert events == ["peer_created", "file", "directory", "parent"]
    assert Mailbox(root).brief(answer["brief"])


@secure_publication
@pytest.mark.skipif(not hasattr(os, "O_PATH"), reason="search-only traversal uses Linux O_PATH")
def test_unreadable_output_parent_cannot_report_durable_success(pilot):  # noqa: F811
    root, _ = pilot
    compose(root, as_of=AS_OF)
    base = root.parent
    mode = stat.S_IMODE(base.stat().st_mode)
    base.chmod(0o111)
    try:
        error = compose(root, as_of=AS_OF, expect=3)["error"]
    finally:
        base.chmod(mode)
    assert "brief publication failed" in error and "Permission denied" in error


@secure_publication
@pytest.mark.parametrize("paths", [None, "", 0, False, {}, []])
def test_no_paths_packets_match_the_runners_falsy_path_handling(tmp_path, paths):
    root, path, _ = structured_job(tmp_path, {"paths": paths})
    driver = ("import json,sys\nfrom pathlib import Path\nsource,packet,checkout=sys.argv[1:]\n"
              "sys.path.insert(0,str(Path(source)/'tools'))\nfrom hierarchy_jobs import checked_paths\n"
              "print(json.dumps(checked_paths(json.loads(Path(packet).read_text()),"
              "{'kind':'command','steps':[['$python','-c','pass']]},checkout)))\n")
    result = subprocess.run([sys.executable, "-I", "-B", "-c", driver, str(ROOT), str(path), str(tmp_path)],
                            capture_output=True, text=True, timeout=15,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 0 and not result.stderr, result.stdout + result.stderr
    expected = json.loads(result.stdout)
    assert expected == []
    before = files(tmp_path)
    answer = compose(root, "a/orchestrator")
    source = next(row["source"] for row in sections(answer["brief"])["Source identity"] if row.get("job_id") == "structured-job")
    assert source["paths"] == expected
    after = files(tmp_path)
    after.pop(str(Path(answer["brief"]["path"]).relative_to(tmp_path)))
    assert after == before


@secure_publication
def test_valid_merge_packet_composes_without_admitting_or_executing_it(tmp_path):
    root, path, packet = structured_job(tmp_path, {"schema": "aegis.hierarchy-job-packet/v1", "recipe": "merge",
        "merge": "c" * 40, "expected_tree": "d" * 40, "message": "Merge reviewed candidate"})
    before = files(tmp_path)
    answer = compose(root, "a/orchestrator")
    row = next(row for row in sections(answer["brief"])["Source identity"] if row.get("job_id") == "structured-job")
    assert row["ref"] == ref(path)
    assert row["source"]["merge"] == packet["merge"] and row["source"]["expected_tree"] == packet["expected_tree"]
    assert "paths" not in row["source"]
    after = files(tmp_path)
    after.pop(str(Path(answer["brief"]["path"]).relative_to(tmp_path)))
    assert after == before


@secure_publication
@pytest.mark.parametrize("notes", [12, 24])
def test_consumed_reference_rechecks_do_not_enumerate_shared_cache(pilot, monkeypatch, capsys, notes):  # noqa: F811
    from tools import hierarchy_fresh_brief as fresh

    root, reference = pilot
    for number in range(notes):
        note = root.parent / ("cache-note-%d.md" % number)
        note.write_text("typed note %d\n" % number, encoding="utf-8")
        invoke(root, "publish", message(identifier="cache-note-%d" % number, kind="brief",
            brief={"path": str(note), "sha256": hashlib.sha256(note.read_bytes()).hexdigest()}))
    # Repeated declarations exercise already-cached paths as well as cache misses.
    for number in range(2):
        invoke(root, "publish", message(identifier="shared-cache-note-%d" % number, kind="brief", brief=reference))
    expected = compose(root, as_of=AS_OF)
    visits = []
    caches = []

    class CountedCache(dict):
        def __iter__(self):
            for key in super().__iter__():
                visits.append(key)
                yield key

    original = fresh._Operation.__init__

    def initialized(self, **kwargs):
        if kwargs.get("reference_cache") is None:
            kwargs["reference_cache"] = CountedCache()
            caches.append(kwargs["reference_cache"])
        original(self, **kwargs)

    monkeypatch.setattr(fresh._Operation, "__init__", initialized)
    code = fresh.main(["compose", "--root", str(root), "--initiative", "a", "--endpoint", ENDPOINT,
                       "--as-of", AS_OF])
    output = capsys.readouterr()
    assert code == 0 and output.err == "", output
    assert json.loads(output.out) == expected
    assert max(map(len, caches)) >= notes
    assert len(visits) == 0, "cached-path membership must not enumerate identity entries"


R9_MESSAGE_ONLY_WALK_PROBE = r'''
import errno, hashlib, sys
from pathlib import Path
from types import SimpleNamespace
tools, fallback, root, backend, kind = sys.argv[1:]
sys.path[:0] = [tools, fallback]
import hierarchy_fresh_brief as fresh
ordinary = Path(root) / 'ordinary'
note = ordinary / 'note.md'
sha = hashlib.sha256(note.read_bytes()).hexdigest()
failures = {'generic': OSError, 'missing': FileNotFoundError,
            'not-directory': NotADirectoryError, 'denied': PermissionError}
name = kind.removesuffix('-errno')
failure = failures[name]
number = {'generic': errno.EIO, 'missing': errno.ENOENT,
          'not-directory': errno.ENOTDIR, 'denied': errno.EACCES}[name]
arguments = (number, 'modelled directory unavailable') if kind.endswith('-errno') else ('modelled directory unavailable',)
real_os = fresh.os
def opened(path, flags, *args, **kwargs):
    if str(path) == 'ordinary' and flags & real_os.O_DIRECTORY:
        raise failure(*arguments)
    return real_os.open(path, flags, *args, **kwargs)
def stated(path, *args, **kwargs):
    if Path(path) == ordinary:
        raise failure(*arguments)
    return real_os.lstat(path, *args, **kwargs)
fresh.os = SimpleNamespace(**{**vars(real_os), 'open': opened, 'lstat': stated})
if backend == 'portable':
    fresh._reference_descriptors = lambda: False
sys.exit(fresh.main(['verify', '--path', str(note), '--sha256', sha]))
'''

# Actual ec27eebf capture: all sixteen parameter rows have these same bytes.
R9_MESSAGE_ONLY_WALK_GOLDEN = (2, b'{"error": "modelled directory unavailable"}\n', b'')
R9_FILENAMELESS_WALK_GOLDENS = {
    "generic": R9_MESSAGE_ONLY_WALK_GOLDEN,
    "missing": R9_MESSAGE_ONLY_WALK_GOLDEN,
    "not-directory": R9_MESSAGE_ONLY_WALK_GOLDEN,
    "denied": R9_MESSAGE_ONLY_WALK_GOLDEN,
    "generic-errno": (2, b'{"error": "[Errno 5] modelled directory unavailable"}\n', b''),
    "missing-errno": (2, b'{"error": "[Errno 2] modelled directory unavailable"}\n', b''),
    "not-directory-errno": (2, b'{"error": "[Errno 20] modelled directory unavailable"}\n', b''),
    "denied-errno": (2, b'{"error": "[Errno 13] modelled directory unavailable"}\n', b''),
}


def r9_message_only_walk_probe(tmp_path, backend, kind, planned, *, tools=None):
    import hierarchy_hosts
    ordinary = tmp_path / "ordinary"
    ordinary.mkdir(parents=True)
    (ordinary / "note.md").write_bytes(b"public fixture\n")
    if planned:
        (tmp_path / "host-plan.json").write_text(json.dumps(
            hierarchy_hosts.plan_record("a", "codex-cli", "codex-cli", {}, "0" * 64)))
    result = subprocess.run([sys.executable, "-I", "-B", "-c", R9_MESSAGE_ONLY_WALK_PROBE,
        str(tools or ROOT / "tools"), str(ROOT / "tools"), str(tmp_path), backend, kind],
        capture_output=True, timeout=30)
    return result.returncode, result.stdout, result.stderr


@lifecycle_only
@pytest.mark.parametrize("backend", ["native", "portable"])
@pytest.mark.parametrize("kind", tuple(R9_FILENAMELESS_WALK_GOLDENS))
@pytest.mark.parametrize("planned", [False, True])
def test_round9_public_message_only_walk_error_bytes(tmp_path, backend, kind, planned):
    import hierarchy_fresh_brief as fresh
    if backend == "native" and not fresh._reference_descriptors():
        pytest.skip("directory descriptors unavailable")
    assert r9_message_only_walk_probe(tmp_path, backend, kind, planned) == R9_FILENAMELESS_WALK_GOLDENS[kind]


R10_LINK_IO_SETUP = r'''
if fault == 'link-to-io':
    import errno
    from types import SimpleNamespace
    real_os, descriptors = fresh.os, {}
    ordinary, public = root / 'ordinary', root / 'public'
    def unavailable(path):
        value = Path(path)
        return ordinary in value.parents or value == public / 'note.md'
    class FaultPath(type(Path())):
        def stat(self, *args, **kwargs):
            if unavailable(self):
                raise OSError(errno.EIO, real_os.strerror(errno.EIO), str(self))
            return super().stat(*args, **kwargs)
        def lstat(self, *args, **kwargs):
            if unavailable(self):
                raise OSError(errno.EIO, real_os.strerror(errno.EIO), str(self))
            return super().lstat(*args, **kwargs)
    # The isolated child owns these module references; global OS functions stay intact.
    protocol.Path = FaultPath
    def actual(path, kwargs):
        if isinstance(path, int):
            return None
        value = Path(path)
        parent = descriptors.get(kwargs.get('dir_fd'))
        return parent / value if not value.is_absolute() and parent is not None else value
    def observed(function):
        def call(path, *args, **kwargs):
            value = actual(path, kwargs)
            if value is not None and unavailable(value):
                raise OSError(errno.EIO, real_os.strerror(errno.EIO), str(value))
            return function(path, *args, **kwargs)
        return call
    def opened(path, *args, **kwargs):
        value = actual(path, kwargs)
        descriptor = real_os.open(path, *args, **kwargs)
        descriptors[descriptor] = value
        return descriptor
    def closed(descriptor):
        descriptors.pop(descriptor, None)
        return real_os.close(descriptor)
    fresh.os = SimpleNamespace(**{**vars(real_os), 'stat': observed(real_os.stat),
        'lstat': observed(real_os.lstat), 'open': opened, 'close': closed})
'''
R10_PUBLIC_PROBE = R9_PUBLIC_PROBE.replace(
    "tools, fallback, root, seam, backend = sys.argv[1:]",
    "tools, fallback, root, seam, backend, fault = sys.argv[1:]").replace(
    "root = Path(root)\n", "root = Path(root)\n" + R10_LINK_IO_SETUP)


R13_LEAF_GOLDENS = {('disposition', False, 'native'): (0,
                                    b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"first'
                                    b'": "lifecycle row UNKNOWN at event fault-event: symlink paths are not supported:'
                                    b' {CASE}/ordinary/note.md"}}}\n',
                                    b''),
 ('disposition', False, 'portable'): (0,
                                      b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"f'
                                      b'irst": "lifecycle row UNKNOWN at event fault-event: symlink paths are not su'
                                      b'pported: {CASE}/ordinary/note.md"}}}\n',
                                      b''),
 ('disposition', True, 'native'): (0,
                                   b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"first'
                                   b'": "lifecycle row UNKNOWN at event fault-event: symlink paths are not supported:'
                                   b' {CASE}/ordinary/note.md"}}}\n',
                                   b''),
 ('disposition', True, 'portable'): (0,
                                     b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"first'
                                     b'": "lifecycle row UNKNOWN at event fault-event: symlink paths are not supported:'
                                     b' {CASE}/ordinary/note.md"}}}\n',
                                     b''),
 ('paths', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary/note.md"}\n', b''),
 ('paths', False, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary/note.md"}\n', b''),
 ('paths', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary/note.md"}\n', b''),
 ('paths', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary/note.md"}\n', b''),
 ('resolve', False, 'native'): (0,
                                b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"first": "'
                                b'lifecycle row UNKNOWN at event fault-event: symlink paths are not supported: {CASE}/'
                                b'ordinary/note.md"}}}\n',
                                b''),
 ('resolve', False, 'portable'): (0,
                                  b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"first'
                                  b'": "lifecycle row UNKNOWN at event fault-event: symlink paths are not supported:'
                                  b' {CASE}/ordinary/note.md"}}}\n',
                                  b''),
 ('resolve', True, 'native'): (0,
                               b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"first": "'
                               b'lifecycle row UNKNOWN at event fault-event: symlink paths are not supported: {CASE}/'
                               b'ordinary/note.md"}}}\n',
                               b''),
 ('resolve', True, 'portable'): (0,
                                 b'{"result": {"refusals": {}, "requests": ["first", "healthy"], "unknown": {"first": "'
                                 b'lifecycle row UNKNOWN at event fault-event: symlink paths are not supported: {CASE}/'
                                 b'ordinary/note.md"}}}\n',
                                 b''),
 ('scope', False, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary/note.md"}\n', b''),
 ('scope', False, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary/note.md"}\n', b''),
 ('scope', True, 'native'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary/note.md"}\n', b''),
 ('scope', True, 'portable'): (2, b'{"error": "symlink paths are not supported: {CASE}/ordinary/note.md"}\n', b''),
 ('shared-disposition', False, 'native'): (0,
                                           b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"],'
                                           b' "unknown": {}}}\n',
                                           b''),
 ('shared-disposition', False, 'portable'): (0,
                                             b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"],'
                                             b' "unknown": {}}}\n',
                                             b''),
 ('shared-disposition', True, 'native'): (0,
                                          b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"],'
                                          b' "unknown": {}}}\n',
                                          b''),
 ('shared-disposition', True, 'portable'): (0,
                                            b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"],'
                                            b' "unknown": {}}}\n',
                                            b''),
 ('shared-resolve', False, 'native'): (0,
                                       b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "un'
                                       b'known": {}}}\n',
                                       b''),
 ('shared-resolve', False, 'portable'): (0,
                                         b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "un'
                                         b'known": {}}}\n',
                                         b''),
 ('shared-resolve', True, 'native'): (0,
                                      b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "un'
                                      b'known": {}}}\n',
                                      b''),
 ('shared-resolve', True, 'portable'): (0,
                                        b'{"result": {"refusals": {}, "requests": ["first", "healthy", "hostile"], "un'
                                        b'known": {}}}\n',
                                        b'')}
R13_LEAF_PROBE = R10_PUBLIC_PROBE.replace("target = root / 'ordinary' / 'note.md'", """
(root / 'ordinary').unlink()
(root / 'ordinary').mkdir()
(root / 'ordinary' / 'note.md').symlink_to(root / 'public' / 'note.md')
target = root / 'ordinary' / 'note.md'
""")


@lifecycle_only
@pytest.mark.parametrize("seam,planned,backend", tuple(itertools.product(
    ("paths","scope","disposition","resolve"),
    (False,True),("native","portable"))))
def test_round13_leaf_link_lookup_keeps_the_baseline_consumer(tmp_path,seam,planned,backend):
    if os.geteuid()==0: pytest.skip("mode-000 witness requires an unprivileged runner")
    if backend=="native" and not portable_fresh._reference_descriptors(): pytest.skip("directory descriptors unavailable")
    assert r9_public_probe(tmp_path,seam,"link-to-denied",planned,backend,_probe=R13_LEAF_PROBE)==R13_LEAF_GOLDENS[(seam,planned,backend)]


@lifecycle_only
@pytest.mark.parametrize("seam,planned,backend", tuple(itertools.product(
    ("shared-disposition","shared-resolve"),(False,True),("native","portable"))))
def test_round13_unproved_leaf_destination_cannot_be_inert_scope(tmp_path,seam,planned,backend):
    if os.geteuid()==0: pytest.skip("mode-000 witness requires an unprivileged runner")
    if backend=="native" and not portable_fresh._reference_descriptors(): pytest.skip("directory descriptors unavailable")
    # The last destination itself is now a target lookup after proved parents.
    # Keep this a proof-failure control by requiring traversal below the denied
    # directory before the final leaf can be reached.
    probe=R13_LEAF_PROBE.replace(".symlink_to(root / 'public' / 'note.md')",
                               ".symlink_to(root / 'public' / 'unproved' / 'note.md')")
    code,out,error=r9_public_probe(tmp_path,seam,"link-to-denied",planned,backend,_probe=probe)
    assert code==0 and error==b""
    state=json.loads(out)["result"]
    assert "healthy" in state["requests"]
    assert state["refusals"]["hostile"]
    assert "healthy" not in state["refusals"]


@lifecycle_only
@pytest.mark.parametrize("destination_kind", ["public", "private"])
def test_round10_unavailable_link_primitives_quarantine_without_descriptor_calls(tmp_path, monkeypatch, destination_kind):
    linked, public, home = (tmp_path / name for name in ("linked", "public", "owner"))
    private = home / ".codex"
    for directory in (linked, public, private):
        directory.mkdir(parents=True)
    ledger = Ledger(tmp_path)
    ledger.publish(request("healthy"))
    ledger.publish(request("following", paths=[str(linked / "note.md")]))
    linked.rmdir()
    symlink_or_skip(private if destination_kind == "private" else public, linked, target_is_directory=True)
    real_os, opened_paths = portable_fresh.os, []
    def opened(value, flags, *args, **kwargs):
        value = Path(value)
        assert kwargs.get("dir_fd") is None
        assert not flags & getattr(real_os, "O_DIRECTORY", 0)
        assert value not in {linked, private} and private not in value.parents and linked not in value.parents
        opened_paths.append(value)
        return real_os.open(value, flags, *args, **kwargs)
    def no_parent(*args, **kwargs):
        pytest.fail("unsupported link proof reached a directory descriptor")
    monkeypatch.setattr(alias_router, "_owner_home", lambda: home)
    monkeypatch.setattr(portable_fresh, "_descriptor_capabilities", lambda: False)
    monkeypatch.setattr(portable_fresh, "_reference_descriptors", lambda: False)
    monkeypatch.setattr(portable_fresh, "_symlink_reader", lambda: pytest.fail("unsupported link proof reached the reader"))
    monkeypatch.setattr(portable_fresh, "_reference_parent", no_parent)
    # Bind the existing reader seam to owned IO; neither module.os nor os.open changes.
    original_read = portable_fresh._read_reference
    observed_read = FunctionType(original_read.__code__, {**original_read.__globals__,
        "os": SimpleNamespace(**{**vars(real_os), "open": opened})},
        original_read.__name__, original_read.__defaults__, original_read.__closure__)
    observed_read.__kwdefaults__ = original_read.__kwdefaults__
    monkeypatch.setattr(portable_fresh, "_read_reference", observed_read)
    operation = portable_fresh._Operation()
    journal = operation.lifecycle(ledger.path)
    _policy, state = journal.load()
    assert set(state["requests"]) == {"healthy", "following"}
    assert journal.refusals_for("following")
    assert journal.refusals_for("healthy") == []
    operation.verify()
    assert not operation.failed_validation
    assert opened_paths
    assert portable_fresh.os is real_os


@lifecycle_only
@pytest.mark.parametrize("anchors", [(2, 1), (3, 1), (1, 2), (2, 3), (3, 2), (2, 2), (3, 3)])
@pytest.mark.parametrize("field,shared", [("paths", False), ("scope", False),
    ("disposition", False), ("disposition", True), ("resolve", False), ("resolve", True)])
def test_round10_anchor_chain_is_quarantined_before_scope_publication(tmp_path, monkeypatch, anchors, field, shared):
    from concurrent.futures import ThreadPoolExecutor
    import hierarchy_fresh_brief as fresh
    import hierarchy_lifecycle as life
    import hierarchy_workspace as workspace
    from tests.integration.test_hierarchy_router import Loop
    if not fresh._reference_descriptors() or fresh._symlink_reader() is None:
        pytest.skip("bounded descriptor-relative link reader unavailable")
    world = Loop(tmp_path)
    world.team("engine")
    world.team("docs")
    world.approved(request("healthy", team="docs"))
    first_link, second_link, home = (tmp_path / name for name in ("l1", "l2", "alice"))
    private = home / ".codex"
    private.mkdir(parents=True)
    (private / "auth.json").write_bytes(b"controlled private fixture\n")
    first_link.mkdir()
    path = str(first_link / ".codex/auth.json")
    bad = request("following", paths=[path])
    if field == "paths":
        world.approved(bad)
    elif field == "scope":
        change = SmallChange(world.ledger, bad)
        change.plan["plan"]["path_scopes"] = [bad["paths"]]
        change.register()
    else:
        first = request("first")
        world.ledger.publish(first)
        extra = {}
        if field == "resolve":
            world.ledger.event("disposition", status="HOLD", resolution={"kind": "blocked",
                "owner": "engine/coordinator", "next_decision": "review", "condition": "reviewed",
                "evidence": world.ledger.evidence}, **world.ledger.target(first))
            extra["blocker_sha256"] = fresh.digest(world.ledger.status()["requests"]["first"]["resolution"])
        evidence = [{"path": path, "sha256": "0" * 64}] if shared else world.ledger.evidence
        world.ledger.event(field, **({"status": "FINAL"} if field == "disposition" else extra),
            resolution={"kind": "next", "request": raw_request(bad), "evidence": evidence},
            **world.ledger.target(first))
        world.ledger.approve(bad)
    first_link.rmdir()
    spell = lambda value, count: "/" * count + str(value).lstrip("/")
    symlink_or_skip(spell(second_link, anchors[0]), first_link, target_is_directory=True)
    symlink_or_skip(spell(home, anchors[1]), second_link, target_is_directory=True)
    real_os, descriptors, accesses = fresh.os, {}, []
    def actual(value, kwargs):
        value = Path(value)
        return descriptors[kwargs["dir_fd"]] / value if not value.is_absolute() else value
    def stated(value, *args, **kwargs):
        value_path = actual(value, kwargs)
        assert private not in value_path.parents, ("private descendant metadata", value_path)
        if value_path == private:
            accesses.append({"path": str(value_path), "kind": "stat", "operation": id(fresh._PATH_GUARD.get())})
        return real_os.stat(value, *args, **kwargs)
    def opened(value, *args, **kwargs):
        value_path = actual(value, kwargs)
        assert value_path != private and private not in value_path.parents, ("private open", value_path)
        descriptor = real_os.open(value, *args, **kwargs)
        descriptors[descriptor] = value_path
        return descriptor
    def closed(descriptor):
        descriptors.pop(descriptor, None)
        return real_os.close(descriptor)
    monkeypatch.setattr("hierarchy_router._owner_home", lambda: home)
    monkeypatch.setattr("hierarchy_router.os", SimpleNamespace(**{**vars(real_os), "stat": stated}))
    monkeypatch.setattr("hierarchy_fresh_brief.os", SimpleNamespace(**{**vars(real_os),
        "stat": stated, "open": opened, "close": closed}))
    owners = []
    def probe():
        operation = fresh._Operation()
        owners.append(operation)
        journal = operation.lifecycle(world.ledger.path)
        _policy, state = journal.load()
        assert {"following", "healthy"} <= set(state["requests"])
        assert journal.refusals_for("following", consume=True)
        assert journal.refusals_for("healthy") == []
        assert not journal.unknown_rows
        brief = fresh.Brief(_operation=operation)
        fresh.lifecycle_records(brief, world.ledger.path, fresh.parse_time("2030-01-01T00:00:00Z"))
        assert not any(row.get("request_id") == "following" for row in brief.sections["Approved scope"])
        assert path not in json.dumps(brief.sections["Approved scope"])
        operation.verify()
        assert not operation.failed_validation
    probe()
    with ThreadPoolExecutor(max_workers=2) as pool:
        for future in (pool.submit(probe), pool.submit(probe)):
            future.result(timeout=30)
    rows = alias_router.status(life.Lifecycle(world.ledger.path), workspace.Store(world.workspace.store), 0)["requests"]
    assert next(row for row in rows if row["request_id"] == "healthy")["state"] == "ready"
    from tests.integration.test_hierarchy_small_change_dispatch import assert_private_root_probes
    assert_private_root_probes([private], accesses)
    assert not descriptors


@lifecycle_only
@pytest.mark.parametrize("fault", ["eacces","einval","regular","recheck","disposition","resolve"])
def test_round13_proof_failures_and_repointed_inert_scope_are_row_local(tmp_path,monkeypatch,fault):
    from concurrent.futures import ThreadPoolExecutor
    from queue import Queue
    from threading import Event
    from tests.integration.test_hierarchy_router import Loop
    if not portable_fresh._reference_descriptors() or portable_fresh._symlink_reader() is None:
        pytest.skip("bounded descriptor-relative link reader unavailable")
    if fault in {"disposition","resolve"} and os.geteuid()==0:
        pytest.skip("mode-000 witness requires an unprivileged runner")
    world=Loop(tmp_path)
    world.team("engine"); world.team("docs")
    world.approved(request("healthy",team="docs"))
    home=tmp_path/"owner"; private=home/".codex"
    private.mkdir(parents=True)
    (private/"auth.json").write_bytes(b"controlled private fixture")
    linked,denied=tmp_path/"linked",tmp_path/"denied"
    linked.mkdir(); denied.mkdir()
    path=str(linked if fault in {"disposition","resolve"} else linked/"auth.json")
    bad=request("following",paths=[path])
    if fault in {"disposition","resolve"}:
        first=request("first"); world.ledger.publish(first)
        extra={}
        if fault=="resolve":
            world.ledger.event("disposition",status="HOLD",resolution={"kind":"blocked","owner":"engine/coordinator",
                "next_decision":"review","condition":"reviewed","evidence":world.ledger.evidence},**world.ledger.target(first))
            extra["blocker_sha256"]=portable_fresh.digest(world.ledger.status()["requests"]["first"]["resolution"])
        world.ledger.event(fault,**({"status":"FINAL"} if fault=="disposition" else extra),
            resolution={"kind":"next","request":raw_request(bad),"evidence":[{"path":path,"sha256":"0"*64}]},
            **world.ledger.target(first))
        world.ledger.approve(bad)
    else: world.approved(bad)
    linked.rmdir()
    symlink_or_skip(denied/"auth.json" if fault in {"disposition","resolve"} else private,linked,
        target_is_directory=fault not in {"disposition","resolve"})
    entered,changed=Event(),Event()
    mutations,acknowledgments=Queue(),Queue()
    original_snapshot=portable_fresh._link_snapshot
    original_parent=portable_fresh._reference_parent
    original_proof_parent=portable_fresh._proof_parent
    original_check=portable_fresh._reference_check
    native_read=portable_fresh._symlink_reader()
    descriptors=[]
    def parent(value,*args,**kwargs):
        value=Path(value)
        assert value!=private and private not in value.parents
        descriptor,marks=original_parent(value,*args,**kwargs)
        descriptors.append(descriptor)
        return descriptor,marks
    def snapshot(*args,**kwargs):
        result=original_snapshot(*args,**kwargs)
        if result is not None and Path(args[1])==linked:
            mutations.put(True)
            assert acknowledgments.get(timeout=10),"repoint did not complete"
        return result
    def proof_parent(value,*args,**kwargs):
        value=Path(value)
        assert value!=private and private not in value.parents
        descriptor,marks=original_proof_parent(value,*args,**kwargs)
        descriptors.append(descriptor)
        return descriptor,marks
    def checked(value,*args,**kwargs):
        if Path(value)==linked:
            linked.unlink()
            linked.symlink_to(denied/"auth.json")
        return original_check(value,*args,**kwargs)
    def read(directory,name,size):
        if fault in {"eacces","einval"}:
            code=errno.EACCES if fault=="eacces" else errno.EINVAL
            raise OSError(code,os.strerror(code),name)
        if fault=="regular":
            entered.set()
            assert changed.wait(10),"regular-file replacement did not complete"
        return native_read(directory,name,size)
    def recheck(*args,**kwargs):
        raise OSError(errno.EACCES,os.strerror(errno.EACCES),str(linked))
    monkeypatch.setattr(alias_router,"_owner_home",lambda:home)
    monkeypatch.setattr(portable_fresh,"_reference_parent",parent)
    monkeypatch.setattr(portable_fresh,"_proof_parent",proof_parent)
    if fault in {"disposition","resolve"}:
        monkeypatch.setattr(portable_fresh,"_link_snapshot",snapshot)
        monkeypatch.setattr(portable_fresh,"_reference_check",checked)
    elif fault=="recheck": monkeypatch.setattr(portable_fresh,"_stable_link",recheck)
    else: monkeypatch.setattr(portable_fresh,"_symlink_reader",lambda:read)
    def replace():
        if fault in {"disposition","resolve"}:
            while mutations.get(timeout=15) is not None:
                linked.unlink()
                linked.symlink_to(private/"auth.json")
                acknowledgments.put(True)
            return
        assert entered.wait(10),"proof did not reach the mutation boundary"
        linked.unlink()
        if fault=="regular": linked.write_bytes(b"public replacement")
        else: linked.symlink_to(private/"auth.json")
        changed.set()
    denied.chmod(0)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            mutation=pool.submit(replace) if fault in {"regular","disposition","resolve"} else None
            operation=portable_fresh._Operation()
            journal=operation.lifecycle(world.ledger.path)
            try:
                _policy,state=journal.load()
                assert {"healthy","following"}<=set(state["requests"])
                assert journal.refusals_for("following")
                assert journal.refusals_for("healthy")==[]
                brief=portable_fresh.Brief(_operation=operation)
                portable_fresh.lifecycle_records(brief,world.ledger.path,portable_fresh.parse_time("2030-01-01T00:00:00Z"))
                assert path not in json.dumps(brief.sections["Approved scope"])
                assert journal.refusals_for("following",consume=True)
                assert journal.refusals_for("following",consume=True)
                operation.verify()
                assert not operation.failed_validation and operation.path_guard._global_failure is None
                healthy=tmp_path/"healthy-after-refusal.md"
                healthy.write_bytes(b"independent healthy capture")
                retry=portable_fresh._Operation()
                assert retry.read(healthy)[1]==b"independent healthy capture"
                retry.verify()
                for descriptor in set(descriptors):
                    with pytest.raises(OSError) as closed: os.fstat(descriptor)
                    assert closed.value.errno==errno.EBADF
            finally:
                if mutation is not None:
                    changed.set()
                    if fault in {"disposition","resolve"}: mutations.put(None)
                    mutation.result(timeout=15)
    finally: denied.chmod(0o700)


@lifecycle_only
@pytest.mark.parametrize("seam",["disposition","resolve"])
@pytest.mark.parametrize("shape",["leaf_hop","directory_hop","direct_leaf"])
def test_round13_denied_hop_target_is_unproved_and_never_approved(tmp_path,monkeypatch,seam,shape):
    from tests.integration.test_hierarchy_router import Loop
    if not portable_fresh._reference_descriptors() or portable_fresh._symlink_reader() is None:
        pytest.skip("bounded descriptor-relative link reader unavailable")
    if os.geteuid()==0: pytest.skip("mode-000 witness requires an unprivileged runner")
    world=Loop(tmp_path); world.team("engine"); world.team("docs")
    world.approved(request("healthy",team="docs"))
    home=tmp_path/"owner"; private=home/".codex"
    public,denied=tmp_path/"public",tmp_path/"denied"
    for directory in (private,public,denied): directory.mkdir(parents=True)
    (private/"note.md").write_bytes(b"controlled private fixture")
    symlink_or_skip(private,denied/"priv_link",target_is_directory=True)
    linked=tmp_path/"l1"
    linked.mkdir()
    path=str(linked/"note.md")
    # Publish while the path is public, then replace only its stored observation.
    first=request("first"); world.ledger.publish(first)
    following=request("following",paths=[path])
    extra={}
    if seam=="resolve":
        world.ledger.event("disposition",status="HOLD",resolution={"kind":"blocked","owner":"engine/coordinator",
            "next_decision":"review","condition":"reviewed","evidence":world.ledger.evidence},**world.ledger.target(first))
        extra["blocker_sha256"]=portable_fresh.digest(world.ledger.status()["requests"]["first"]["resolution"])
    world.ledger.event(seam,**({"status":"FINAL"} if seam=="disposition" else extra),
        resolution={"kind":"next","request":raw_request(following),"evidence":[{"path":path,"sha256":"0"*64}]},
        **world.ledger.target(first))
    world.ledger.approve(following)
    linked.rmdir()
    if shape=="leaf_hop":
        symlink_or_skip(public,linked,target_is_directory=True)
        symlink_or_skip(denied/"priv_link"/"note.md",public/"note.md")
    elif shape=="directory_hop": symlink_or_skip(denied/"priv_link",linked,target_is_directory=True)
    else:
        linked.mkdir()
        symlink_or_skip(denied/"priv_link"/"note.md",linked/"note.md")
    monkeypatch.setattr(alias_router,"_owner_home",lambda:home)
    denied.chmod(0)
    try:
        operation=portable_fresh._Operation(); journal=operation.lifecycle(world.ledger.path)
        _policy,state=journal.load()
        assert "healthy" in state["requests"]
        assert journal.refusals_for("following")
        assert journal.refusals_for("healthy")==[]
        for _ in range(2):
            assert journal.refusals_for("following",consume=True)
            brief=portable_fresh.Brief(_operation=operation)
            portable_fresh.lifecycle_records(brief,world.ledger.path,portable_fresh.parse_time("2030-01-01T00:00:00Z"))
            assert path not in json.dumps(brief.sections["Approved scope"])
        operation.verify()
        assert not operation.failed_validation and operation.path_guard._global_failure is None
    finally: denied.chmod(0o700)
    assert journal.refusals_for("following",consume=True)
    retry=portable_fresh._Operation().lifecycle(world.ledger.path)
    retry.load()
    assert retry.refusals_for("following",consume=True)
    assert retry.refusals_for("healthy")==[]


@lifecycle_only
@pytest.mark.parametrize("phase",["preflight","classify"])
@pytest.mark.parametrize("prior",["symlink","policy"])
def test_round13_directory_cleanup_cannot_downgrade_proof_or_policy(tmp_path,monkeypatch,phase,prior):
    from tests.integration.test_hierarchy_router import Loop
    if not portable_fresh._reference_descriptors() or portable_fresh._symlink_reader() is None:
        pytest.skip("bounded descriptor-relative link reader unavailable")
    world=Loop(tmp_path); world.team("engine"); world.team("docs")
    world.approved(request("healthy",team="docs"))
    linked,public,home=tmp_path/"linked",tmp_path/"public",tmp_path/"owner"
    private=home/".codex"
    for directory in (linked,public,private): directory.mkdir(parents=True)
    (private/"note.md").write_bytes(b"controlled private fixture")
    if phase=="classify": (linked/"sub").mkdir()
    path=str(linked/"sub"/"note.md" if phase=="classify" else linked/"note.md")
    first=request("first"); world.ledger.publish(first)
    following=request("following",paths=[path])
    world.ledger.event("disposition",status="FINAL",resolution={"kind":"next","request":raw_request(following),
        "evidence":[{"path":path,"sha256":"0"*64}]},**world.ledger.target(first))
    world.ledger.approve(following)
    if phase=="classify": (linked/"sub").rmdir()
    linked.rmdir(); symlink_or_skip(public,linked,target_is_directory=True)
    if phase=="classify": symlink_or_skip(private,public/"sub",target_is_directory=True)
    else: symlink_or_skip(private/"note.md",public/"note.md")
    real_os=portable_fresh.os
    info=public.stat(); public_identity=info.st_dev,info.st_ino
    armed,closed,policy_seen=[False],[],[False]
    trigger=linked/"note.md" if phase=="preflight" else public/"sub"
    def close(descriptor):
        info=real_os.fstat(descriptor)
        selected=(armed[0] and (info.st_dev,info.st_ino)==public_identity
                  and (prior!="policy" or policy_seen[0]))
        real_os.close(descriptor)
        if selected:
            closed.append(descriptor)
            raise OSError(errno.EIO,"controlled proof-directory cleanup failure")
    def metadata(*args,**kwargs):
        if armed[0] and prior=="policy" and args[0]==("sub" if phase=="classify" else "note.md"):
            policy_seen[0]=True
            raise alias_router.CapturedPolicyError("controlled proof policy failure")
        return real_os.stat(*args,**kwargs)
    namespace={**vars(portable_fresh),"os":SimpleNamespace(**{**vars(real_os),"close":close,"stat":metadata})}
    # Bind production functions to one owned OS boundary, including any cleanup helper.
    for name,function in vars(portable_fresh).items():
        if isinstance(function,FunctionType) and function.__globals__ is vars(portable_fresh):
            clone=FunctionType(function.__code__,namespace,name,function.__defaults__,function.__closure__)
            clone.__kwdefaults__=function.__kwdefaults__
            namespace[name]=clone
    original=namespace["_proof_check" if phase=="classify" else "_reference_check"]
    def checked(value,*args,**kwargs):
        previous=armed[0]
        armed[0]=Path(value)==trigger and (phase=="classify" or not kwargs.get("_classifying"))
        try: return original(value,*args,**kwargs)
        finally: armed[0]=previous
    monkeypatch.setattr(alias_router,"_owner_home",lambda:home)
    if phase=="classify":
        namespace["_proof_check"]=checked
        monkeypatch.setattr(portable_fresh,"_proof_check",checked)
    else:
        namespace["_reference_check"]=checked
        monkeypatch.setattr(portable_fresh,"_reference_check",checked)
    operation=portable_fresh._Operation(); journal=operation.lifecycle(world.ledger.path)
    if prior=="policy":
        with pytest.raises(alias_router.CapturedPolicyError,match="controlled proof policy failure"): journal.load()
        assert operation.path_guard._global_failure is not None
    else:
        journal.load()
        assert journal.refusals_for("following",consume=True)
        assert journal.refusals_for("healthy")==[]
        brief=portable_fresh.Brief(_operation=operation)
        portable_fresh.lifecycle_records(brief,world.ledger.path,portable_fresh.parse_time("2030-01-01T00:00:00Z"))
        assert path not in json.dumps(brief.sections["Approved scope"])
        operation.verify()
        assert operation.path_guard._global_failure is None
    assert closed
    for descriptor in set(closed):
        with pytest.raises(OSError) as error: real_os.fstat(descriptor)
        assert error.value.errno==errno.EBADF


@lifecycle_only
def test_round13_cached_target_errno_quarantines_a_failed_proof_close(tmp_path,monkeypatch):
    from tests.integration.test_hierarchy_router import Loop
    if not portable_fresh._reference_descriptors() or portable_fresh._symlink_reader() is None:
        pytest.skip("bounded descriptor-relative link reader unavailable")
    if os.geteuid()==0: pytest.skip("mode-000 witness requires an unprivileged runner")
    world=Loop(tmp_path); world.team("engine"); world.team("docs")
    world.approved(request("healthy",team="docs"))
    linked,denied=tmp_path/"linked",tmp_path/"denied"
    linked.mkdir(); denied.mkdir()
    path=str(linked/"auth.json")
    first=request("first"); world.ledger.publish(first)
    following=request("following",paths=[path])
    world.ledger.event("disposition",status="FINAL",resolution={"kind":"next","request":raw_request(following),
        "evidence":[{"path":path,"sha256":"0"*64}]},**world.ledger.target(first))
    world.ledger.approve(following)
    linked.rmdir(); symlink_or_skip(denied,linked,target_is_directory=True)
    stable,disposition=portable_fresh._stable_link,portable_fresh._disposition
    real_os=portable_fresh.os
    consuming,closed=[False],[]
    def close(descriptor):
        real_os.close(descriptor); closed.append(descriptor)
        raise OSError(errno.EIO,"controlled proof-close failure")
    failing=FunctionType(stable.__code__,{**stable.__globals__,
        "os":SimpleNamespace(**{**vars(real_os),"close":close})},stable.__name__,stable.__defaults__,stable.__closure__)
    failing.__kwdefaults__=stable.__kwdefaults__
    def checked(error,*args,**kwargs):
        if kwargs.get("seam")=="scope": consuming[0]=True
        return disposition(error,*args,**kwargs)
    def rechecked(*args,**kwargs):
        return failing(*args,**kwargs) if consuming[0] else stable(*args,**kwargs)
    monkeypatch.setattr(portable_fresh,"_disposition",checked)
    monkeypatch.setattr(portable_fresh,"_stable_link",rechecked)
    denied.chmod(0)
    try:
        operation=portable_fresh._Operation(); journal=operation.lifecycle(world.ledger.path)
        _policy,state=journal.load()
        assert {"following","healthy"}<=set(state["requests"])
        assert journal.refusals_for("following") and journal.refusals_for("healthy")==[]
        brief=portable_fresh.Brief(_operation=operation)
        portable_fresh.lifecycle_records(brief,world.ledger.path,portable_fresh.parse_time("2030-01-01T00:00:00Z"))
        assert path not in json.dumps(brief.sections["Approved scope"])
        operation.verify()
        assert closed and operation.path_guard._global_failure is None and not operation.failed_validation
        for descriptor in set(closed):
            with pytest.raises(OSError) as error: os.fstat(descriptor)
            assert error.value.errno==errno.EBADF
    finally: denied.chmod(0o700)
